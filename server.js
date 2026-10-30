"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { once } = require("node:events");
const { DiscoveryService } = require("./src/discovery");
const {
  createPairingEnvelope,
  createPairingSession,
  fingerprint,
  openPairingEnvelope,
  openWithKey,
  publicIdentity,
  sealWithKey,
  timingSafeStringEqual,
  validatePublicIdentity,
  signObject, verifyObject, pairingProofPayload,
} = require("./src/security");
const { Store } = require("./src/store");
const { resolvePeer, isPrivateIpv4 } = require("./src/peer-address");
const { listVolumes } = require("./src/storage");
const { TransferManager } = require("./src/transfer-manager");
const { receivedFile, showFolder } = require("./src/received-files");
const { previewInfo } = require("./src/image-preview");
const { jsonResponse, readJsonBody, safeFileName, readJson, atomicWriteJson } = require("./src/utils");

const ROOT = __dirname;
function configuredAuthOrigin() {
  const candidate = process.env.DROPSYNC_AUTH_URL || (() => {
    try { return fs.readFileSync(path.join(ROOT, "auth-config.js"), "utf8").match(/\burl:\s*["']([^"']+)["']/)?.[1] || ""; }
    catch { return ""; }
  })();
  try { const value = new URL(candidate); return value.protocol === "https:" ? value.origin : null; }
  catch { return null; }
}
const AUTH_ORIGIN = configuredAuthOrigin();
function defaultDataDirectory() {
  if (process.platform === "win32") {
    return path.join(process.env.LOCALAPPDATA || path.join(os.homedir(), "AppData", "Local"), "DropSync");
  }
  if (process.platform === "darwin") return path.join(os.homedir(), "Library", "Application Support", "DropSync");
  return path.join(process.env.XDG_STATE_HOME || path.join(os.homedir(), ".local", "state"), "dropsync");
}
const DATA_DIR = path.resolve(process.env.DROPSYNC_DATA_DIR || defaultDataDirectory());
require("./src/data-lock").acquire(DATA_DIR);
const localVault = require("./src/local-vault");
if (!process.parentPort && process.env.DROPSYNC_VAULT_PASSPHRASE) {
  localVault.register(DATA_DIR, localVault.passphraseKey(DATA_DIR, process.env.DROPSYNC_VAULT_PASSPHRASE), "Passphrase vault");
  localVault.migrate(DATA_DIR); delete process.env.DROPSYNC_VAULT_PASSPHRASE;
}
else if (!process.parentPort && process.platform === "win32") {
  localVault.register(DATA_DIR, require("./src/windows-vault").unlockWindowsVault(DATA_DIR), "Windows DPAPI"); localVault.migrate(DATA_DIR);
}
else if (!process.parentPort) throw new Error("Use the desktop OS vault, or set DROPSYNC_VAULT_PASSPHRASE (at least 12 characters) before starting the CLI service. Unprotected device keys are not created.");
const PORT = Number(process.env.DROPSYNC_PORT || 47821);
const HOST = process.env.DROPSYNC_HOST || "0.0.0.0";
const DEVICE_TYPE = process.parentPort ? "desktop" : "browser";
const MAX_STAGE_BYTES = 10 * 1024 * 1024 * 1024;
const CSRF_TOKEN = crypto.randomBytes(32).toString("base64url");
const store = new Store(DATA_DIR);
const stagedFiles = new Map();
const stagingManifest = path.join(DATA_DIR, "staged-files.json");
for (const record of readJson(stagingManifest, [])) {
  if (!record || !/^[a-f0-9-]{36}$/i.test(record.id) || !/^[a-f0-9]{64}$/.test(record.sha256) || typeof record.name !== "string") continue;
  const target = path.join(DATA_DIR, "staging", record.id + ".bin");
  try { if (fs.statSync(target).size === record.size) stagedFiles.set(record.id, { ...record, path: target }); } catch { /* Missing immutable copies are omitted. */ }
}
function saveStaging() { atomicWriteJson(stagingManifest, [...stagedFiles.values()].map(({ path: _path, ...item }) => item)); }
const eventClients = new Set();
const pairingAttempts = new Map();
const authFlows = new Map();
const lastTransferStatuses = new Map();
let pendingIncomingIds = new Set();
let pairingSession = null;
let serverPort = PORT;

function broadcast(type, data) {
  const body = `event: ${type}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const response of eventClients) response.write(body);
  if (type === "incoming" && data.length) process.parentPort?.postMessage({ type: "incoming-pending", count: data.length });
  if (type === "incoming") {
    for (const item of data) if (!pendingIncomingIds.has(item.id)) broadcast("notification", store.notify({ title: "Incoming file", message: `${item.fileName} from ${item.deviceName}`, transferId: item.id, kind: "incoming" }));
    pendingIncomingIds = new Set(data.map((item) => item.id));
  }
  if (type === "transfer") {
    const previous = lastTransferStatuses.get(data.id); lastTransferStatuses.set(data.id, data.status);
    if (lastTransferStatuses.size > 1000) lastTransferStatuses.delete(lastTransferStatuses.keys().next().value);
    if (previous !== data.status && ["completed", "failed", "retrying"].includes(data.status)) broadcast("notification", store.notify({ title: { completed: "Transfer completed", failed: "Transfer interrupted", retrying: "Connection interrupted · retrying" }[data.status], message: `${data.fileName}${data.error ? ": " + String(data.error).slice(0, 250) : ""}`, transferId: data.id, kind: data.status, canRetry: data.status === "failed" && data.direction === "send" }));
  }
  if (type === "notification" && store.settings.notificationsEnabled) process.parentPort?.postMessage({ type: "notification", title: data.title, body: data.message });
  if (["transfer", "settings"].includes(type)) process.parentPort?.postMessage({ type: "runtime-state", active: [...transfers.active.values()].filter((item) => ["connecting", "sending", "receiving", "scanning", "publishing", "retrying", "awaiting-acceptance"].includes(item.status)).length, keepRunning: store.settings.keepRunningInBackground, clipboardEnabled: store.settings.clipboardEnabled, keepAwake: store.settings.keepAwakeWhileSharing && store.settings.receivingEnabled });
}

const desktopActions = new Map();
process.parentPort?.on("message", ({ data }) => {
  if (!["file-action-result", "update-result"].includes(data?.type)) return;
  const pending = desktopActions.get(data.requestId);
  if (!pending) return;
  clearTimeout(pending.timer); desktopActions.delete(data.requestId);
  if (data.error) pending.reject(Object.assign(new Error(data.error), { statusCode: 400 }));
  else pending.resolve(data.result);
});
function desktopUpdate(action, body = {}) {
  if (!process.parentPort) return Promise.resolve({ configured: false, status: "browser", currentVersion: require("./package.json").version });
  return new Promise((resolve, reject) => {
    const requestId = crypto.randomUUID();
    const timer = setTimeout(() => { desktopActions.delete(requestId); reject(new Error("Update operation timed out")); }, 11 * 60_000);
    desktopActions.set(requestId, { resolve, reject, timer });
    process.parentPort.postMessage({ type: "update-action", requestId, action, body });
  });
}
function desktopFileAction(action, target) {
  return new Promise((resolve, reject) => {
    const requestId = crypto.randomUUID();
    const timer = setTimeout(() => { desktopActions.delete(requestId); reject(Object.assign(new Error("Desktop did not respond"), { statusCode: 503 })); }, 10_000);
    desktopActions.set(requestId, { resolve, reject, timer });
    process.parentPort.postMessage({ type: "file-action", requestId, action, target });
  });
}

const discovery = new DiscoveryService({
  identity: store.identity,
  getName: () => store.settings.deviceName,
  getPort: () => serverPort,
  getDeviceType: () => DEVICE_TYPE,
  isTrusted: (id) => Boolean(store.getTrustedDevice(id)),
  getTrustedIdentity: (id) => store.getTrustedDevice(id),
  onChange: (devices) => {
    for (const device of devices) store.rememberDeviceType(device.deviceId, device.deviceType);
    broadcast("devices", knownDevices());
  },
});

const transfers = new TransferManager({
  store,
  discovery,
  onEvent: (type, data) => broadcast(type, data),
});

function publicDevice(device) {
  return {
    deviceId: device.deviceId,
    name: device.name,
    deviceType: device.deviceType,
    address: device.address,
    port: device.port,
    trusted: Boolean(store.getTrustedDevice(device.deviceId)),
    online: device.online !== false,
    lastSeen: device.lastSeen,
    fingerprint: fingerprint(device.signingPublicKey),
    capabilities: device.capabilities || { pairing: true, transferSend: true, transferReceive: true },
  };
}

function knownDevices() {
  const live = discovery.list().map(publicDevice);
  const ids = new Set(live.map((d) => d.deviceId));
  return [...live, ...store.devices.filter((d) => !ids.has(d.deviceId)).map((d) => publicDevice({ ...d, online: false }))];
}

async function probePeer(target) {
  const packet = await getJson({ host: target.host, port: target.port, path: "/peer/info" });
  if (packet?.data?.deviceId === store.identity.deviceId) throw new Error("This is your own device");
  const pinned = store.getTrustedDevice(packet?.data?.deviceId);
  if (pinned && (pinned.signingPublicKey !== packet.data.signingPublicKey || pinned.exchangePublicKey !== packet.data.exchangePublicKey)) throw new Error("Peer identity changed; pair again after verifying its fingerprint");
  const device = discovery.handleMessage(Buffer.from(JSON.stringify(packet)), { address: target.host });
  if (!device) throw new Error("Invalid signed DropSync identity");
  return device;
}

let probingPeers = false;
async function refreshManualPeers() {
  if (probingPeers) return;
  probingPeers = true;
  try {
    discovery.cleanup();
    await Promise.allSettled((store.settings.manualPeers || []).map(async (address) => {
      const target = await resolvePeer(address);
      if (target) await probePeer(target);
    }));
  } finally { probingPeers = false; }
}
const peerRefreshTimer = setInterval(refreshManualPeers, 8000);
peerRefreshTimer.unref();

function selfInfo() {
  return {
    deviceId: store.identity.deviceId,
    name: store.settings.deviceName,
    deviceType: DEVICE_TYPE,
    fingerprint: fingerprint(store.identity.signingPublicKey),
    port: serverPort,
    addresses: Object.values(os.networkInterfaces()).flat().filter((item) => item && item.family === "IPv4" && !item.internal).map((item) => item.address),
  };
}

function systemInfo() {
  let storage = null;
  try {
    const stats = fs.statfsSync(store.settings.downloadDirectory);
    const total = Number(stats.blocks) * Number(stats.bsize);
    const free = Number(stats.bavail) * Number(stats.bsize);
    storage = { total, free, used: Math.max(0, total - free), directory: store.settings.downloadDirectory };
  } catch { /* storage statistics are optional */ }
  return {
    platform: process.platform,
    node: process.version,
    hostname: os.hostname(),
    storage,
    volumes: listVolumes(store.settings.downloadDirectory),
  };
}

function isLoopback(address) {
  return address === "127.0.0.1" || address === "::1" || address === "::ffff:127.0.0.1";
}

function setSecurityHeaders(res) {
  res.setHeader("Content-Security-Policy", [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "font-src 'self'",
    "img-src 'self' data:",
    `connect-src 'self' http://127.0.0.1:* http://localhost:* https://*.supabase.co${AUTH_ORIGIN ? ` ${AUTH_ORIGIN}` : ""}`,
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; "));
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()");
}

function requireLocal(req) {
  const host = String(req.headers.host || "").toLowerCase();
  if (!isLoopback(req.socket.remoteAddress) || !/^(127\.0\.0\.1|localhost|\[::1\])(?::\d+)?$/.test(host)) {
    const error = new Error("The DropSync interface is only available on this computer");
    error.statusCode = 403;
    throw error;
  }
}

function requireCsrf(req) {
  if (!timingSafeStringEqual(req.headers["x-dropsync-csrf"] || "", CSRF_TOKEN)) {
    const error = new Error("Invalid request token");
    error.statusCode = 403;
    throw error;
  }
  const origin = req.headers.origin;
  if (origin && origin !== `http://${req.headers.host}`) {
    const error = new Error("Cross-origin request rejected");
    error.statusCode = 403;
    throw error;
  }
}

function rateLimitPairing(address) {
  const now = Date.now();
  for (const [key, times] of pairingAttempts) if (times.every((time) => now - time >= 60_000)) pairingAttempts.delete(key);
  if (!pairingAttempts.has(address) && pairingAttempts.size >= 512) return false;
  const history = (pairingAttempts.get(address) || []).filter((time) => now - time < 60_000);
  if (history.length >= 10) return false;
  history.push(now);
  pairingAttempts.set(address, history);
  return true;
}

function postJson({ host, port, path: requestPath, body, timeout = 10_000 }) {
  return new Promise((resolve, reject) => {
    const encoded = Buffer.from(JSON.stringify(body));
    const request = http.request({
      host,
      port,
      path: requestPath,
      method: "POST",
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Content-Length": encoded.length,
      },
      timeout,
    }, (response) => {
      const chunks = [];
      let size = 0;
      response.on("data", (chunk) => {
        size += chunk.length;
        if (size <= 64 * 1024) chunks.push(chunk);
        else response.destroy(new Error("Peer response is too large"));
      });
      response.on("error", reject);
      response.on("end", () => {
        let payload = {};
        try { payload = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { /* handled below */ }
        if (response.statusCode >= 200 && response.statusCode < 300) resolve(payload);
        else reject(new Error(payload.error || `Peer request failed (${response.statusCode})`));
      });
    });
    request.on("timeout", () => request.destroy(new Error("Peer request timed out")));
    request.on("error", reject);
    request.end(encoded);
  });
}

function getJson({ host, port, path: requestPath, timeout = 4_000 }) {
  return new Promise((resolve, reject) => {
    const request = http.request({ host, port, path: requestPath, method: "GET", timeout }, (response) => {
      const chunks = [];
      let size = 0;
      response.on("data", (chunk) => {
        size += chunk.length;
        if (size <= 64 * 1024) chunks.push(chunk);
        else request.destroy(new Error("Peer response is too large"));
      });
      response.on("end", () => {
        let payload;
        try { payload = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { return reject(new Error("Peer returned invalid data")); }
        if (response.statusCode >= 200 && response.statusCode < 300) resolve(payload);
        else reject(new Error(payload.error || `Peer request failed (${response.statusCode})`));
      });
    });
    request.on("timeout", () => request.destroy(new Error("Peer request timed out")));
    request.on("error", reject);
    request.end();
  });
}

async function pairWithDevice(deviceId, code) {
  if (!store.peerAllowed(deviceId)) throw new Error("This device is blocked by organization policy");
  const device = discovery.get(deviceId);
  if (!device) throw new Error("Device is no longer online");
  if (!/^\d{6}$/.test(String(code))) throw new Error("Enter the six-digit pairing code");
  const payload = {
    code: String(code),
    identity: publicIdentity(store.identity),
    name: store.settings.deviceName,
    deviceType: DEVICE_TYPE,
    timestamp: Date.now(),
    port: serverPort,
  };
  payload.proof = signObject(pairingProofPayload(payload), store.identity.signingPrivateKey);
  const { envelope, key, requestId } = createPairingEnvelope(device.exchangePublicKey, payload);
  const response = await postJson({ host: device.address, port: device.port, path: "/peer/pair", body: envelope });
  const remote = openWithKey(key, requestId, response);
  if (!validatePublicIdentity(remote.identity) || remote.identity.deviceId !== device.deviceId) throw new Error("Peer identity changed during pairing");
  if (remote.identity.signingPublicKey !== device.signingPublicKey || remote.identity.exchangePublicKey !== device.exchangePublicKey) {
    throw new Error("Peer key mismatch detected");
  }
  const trusted = store.trustDevice({ ...remote.identity, name: remote.name, deviceType: device.deviceType });
  store.rememberPeer(`${device.address}:${device.port}`);
  discovery.markTrust(deviceId);
  broadcast("devices", discovery.list().map(publicDevice));
  return trusted;
}

async function handlePeerPair(req, res) {
  if (!rateLimitPairing(req.socket.remoteAddress || "unknown")) return jsonResponse(res, 429, { error: "Too many pairing attempts" });
  const envelope = await readJsonBody(req, 48 * 1024);
  let opened;
  try { opened = openPairingEnvelope(store.identity.exchangePrivateKey, envelope); } catch { return jsonResponse(res, 400, { error: "Invalid encrypted pairing request" }); }
  const payload = opened.payload;
  if (!pairingSession || pairingSession.expiresAt < Date.now()) return jsonResponse(res, 409, { error: "No active pairing session" });
  pairingSession.attempts = (pairingSession.attempts || 0) + 1;
  if (pairingSession.attempts > 5 || !timingSafeStringEqual(payload.code || "", pairingSession.code)) {
    if (pairingSession.attempts > 5) pairingSession = null;
    return jsonResponse(res, 401, { error: "Pairing code is invalid" });
  }
  if (!validatePublicIdentity(payload.identity) || typeof payload.name !== "string" || !payload.name.trim() || payload.name.length > 48 || !Number.isFinite(payload.timestamp) || Math.abs(Date.now() - payload.timestamp) > 2 * 60 * 1000
    || !verifyObject(pairingProofPayload(payload), payload.proof, payload.identity.signingPublicKey)) {
    return jsonResponse(res, 400, { error: "Invalid peer identity" });
  }
  if (!store.peerAllowed(payload.identity.deviceId)) return jsonResponse(res, 403, { error: "Device is not allowed by organization policy" });
  if (payload.port !== undefined && (!Number.isInteger(payload.port) || payload.port < 1 || payload.port > 65535)) return jsonResponse(res, 400, { error: "Invalid peer port" });
  const pinned = store.getTrustedDevice(payload.identity.deviceId);
  if (pinned && (pinned.signingPublicKey !== payload.identity.signingPublicKey || pinned.exchangePublicKey !== payload.identity.exchangePublicKey)) return jsonResponse(res, 409, { error: "Pinned identity changed. Remove trust and verify the fingerprint before pairing again." });
  store.trustDevice({ ...payload.identity, name: payload.name, deviceType: discovery.get(payload.identity.deviceId)?.deviceType || payload.deviceType });
  const address = String(req.socket.remoteAddress || "").replace(/^::ffff:/, "");
  const port = payload.port || discovery.get(payload.identity.deviceId)?.port || 47821;
  if (isPrivateIpv4(address)) { store.rememberPeer(`${address}:${port}`); probePeer({ host: address, port }).catch(() => {}); }
  pairingSession = null;
  discovery.markTrust(payload.identity.deviceId);
  broadcast("paired", { deviceId: payload.identity.deviceId, name: payload.name });
  const response = sealWithKey(opened.key, envelope.requestId, {
    identity: publicIdentity(store.identity),
    name: store.settings.deviceName,
    deviceType: DEVICE_TYPE,
  });
  jsonResponse(res, 200, response);
}

async function stageFile(req, res) {
  if (stagedFiles.size >= 100) return jsonResponse(res, 429, { error: "Remove some selected files before adding more" });
  const encodedName = req.headers["x-dropsync-file-name"];
  let name = "file";
  try { name = Buffer.from(String(encodedName || ""), "base64url").toString("utf8"); } catch { /* fallback */ }
  name = safeFileName(name);
  const declaredSize = Number(req.headers["content-length"]);
  const limit = Math.min(store.settings.maxIncomingFileBytes, MAX_STAGE_BYTES);
  if (Number.isFinite(declaredSize) && declaredSize > limit) return jsonResponse(res, 413, { error: "File exceeds the configured size limit" });

  const id = crypto.randomUUID();
  const tempPath = path.join(DATA_DIR, "staging", `${id}.part`);
  const finalPath = path.join(DATA_DIR, "staging", `${id}.bin`);
  const output = fs.createWriteStream(tempPath, { flags: "wx", mode: 0o600 });
  output.on("error", (error) => req.destroy(error));
  const hash = crypto.createHash("sha256");
  let size = 0;
  try {
    for await (const chunk of req) {
      size += chunk.length;
      if (size > limit) throw Object.assign(new Error("File exceeds the configured size limit"), { statusCode: 413 });
      hash.update(chunk);
      if (!output.write(chunk)) await once(output, "drain");
    }
    output.end();
    await once(output, "finish");
    fs.renameSync(tempPath, finalPath);
    const record = { id, name, size, sha256: hash.digest("hex"), path: finalPath, createdAt: Date.now() };
    stagedFiles.set(id, record);
    saveStaging();
    jsonResponse(res, 201, { id, name, size, sha256: record.sha256 });
  } catch (error) {
    output.destroy();
    try { fs.unlinkSync(tempPath); } catch { /* nothing to remove */ }
    throw error;
  }
}

function cleanStaging() {
  const cutoff = Date.now() - 24 * 60 * 60 * 1000;
  for (const [id, file] of stagedFiles) {
    if (file.createdAt < cutoff && ![...transfers.active.values()].some((transfer) => transfer.stagedFileId === id)) {
      stagedFiles.delete(id);
      try { fs.unlinkSync(file.path); } catch { /* already gone */ }
    }
  }
  saveStaging();
}

function bootstrapPayload() {
  return {
    version: "0.7.0",
    csrfToken: CSRF_TOKEN,
    self: selfInfo(),
    settings: store.settings,
    managedSettings: Object.keys(store.policy.settings),
    vault: store.vaultStatus(),
    notifications: store.notifications,
    discovery: discovery.status(),
    devices: knownDevices(),
    trustedDevices: store.devices.map((item) => ({ deviceId: item.deviceId, name: item.name, deviceType: item.deviceType, fingerprint: item.fingerprint, pairedAt: item.pairedAt })),
    transfers: transfers.list(),
    stagedFiles: [...stagedFiles.values()].map(({ path: _path, ...item }) => item),
    incomingRequests: transfers.approvals.list(),
    desktop: Boolean(process.parentPort),
    security: {
      protocol: "DropSync transfer/2 (discovery and pairing/1)",
      identity: "Ed25519",
      keyAgreement: "X25519 + HKDF-SHA-256",
      encryption: "AES-256-GCM per 256 KiB chunk",
    },
    capabilities: { discovery: true, pairing: true, transferSend: true, transferReceive: true },
    system: systemInfo(),
  };
}

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
};

function serveStatic(url, res) {
  const pathname = url.pathname === "/" ? "/welcome.html" : url.pathname;
  // Never expose source, installers, configuration, or private data through the UI server.
  const publicFiles = new Set(["/index.html", "/styles.css", "/app.js", "/runtime.js", "/updates-ui.js", "/project-info.js", "/feature-settings.js", "/workspace-features.js", "/product.js", "/auth.js", "/auth-config.js", "/welcome.html", "/welcome.css", "/welcome.js"]);
  if (!publicFiles.has(pathname)) return jsonResponse(res, 404, { error: "Not found" });
  let decoded;
  try { decoded = decodeURIComponent(pathname); } catch { return jsonResponse(res, 400, { error: "Invalid path" }); }
  const filePath = path.resolve(ROOT, `.${decoded}`);
  if (!filePath.startsWith(`${ROOT}${path.sep}`) || filePath.startsWith(`${DATA_DIR}${path.sep}`)) return jsonResponse(res, 404, { error: "Not found" });
  let stat;
  try { stat = fs.statSync(filePath); } catch { return jsonResponse(res, 404, { error: "Not found" }); }
  if (!stat.isFile()) return jsonResponse(res, 404, { error: "Not found" });
  res.writeHead(200, {
    "Content-Type": MIME[path.extname(filePath).toLowerCase()] || "application/octet-stream",
    "Content-Length": stat.size,
    "Cache-Control": path.extname(filePath) === ".html" ? "no-store" : "no-cache",
  });
  fs.createReadStream(filePath).pipe(res);
}

async function route(req, res) {
  setSecurityHeaders(res);
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);

  if (url.pathname.startsWith("/peer/")) {
    const peerAddress = String(req.socket.remoteAddress || "").replace(/^::ffff:/, "");
    if (peerAddress !== "::1" && !isPrivateIpv4(peerAddress)) return jsonResponse(res, 403, { error: "Only private LAN or Tailscale peers are allowed" });
    if (req.method === "GET" && url.pathname === "/peer/info") return jsonResponse(res, 200, discovery.createAnnouncement());
    if (req.method === "POST" && url.pathname === "/peer/pair") return handlePeerPair(req, res);
    if (req.method === "POST" && url.pathname === "/peer/transfers") return transfers.receive(req, res);
    if (req.method === "POST" && url.pathname === "/peer/transfers/prepare") return transfers.prepareIncoming(req, res);
    return jsonResponse(res, 404, { error: "Unknown peer endpoint" });
  }

  requireLocal(req);
  if (req.method === "GET" && url.pathname === "/auth/callback") {
    const state = url.searchParams.get("state");
    const expires = authFlows.get(state);
    authFlows.delete(state);
    if (!expires || expires < Date.now()) return jsonResponse(res, 400, { error: "Sign-in expired. Return to DropSync and try again." });
    broadcast("auth-callback", { code: url.searchParams.get("code"), error: url.searchParams.get("error_description") });
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    return res.end("<!doctype html><html><meta name='viewport' content='width=device-width'><title>DropSync</title><body><h1>Return to DropSync</h1><p>You can close this tab. Your sign-in is being completed in the app.</p></body></html>");
  }
  if (url.pathname === "/healthz") return jsonResponse(res, 200, { ok: true, deviceId: store.identity.deviceId });

  if (url.pathname.startsWith("/api/")) {
    if (!["GET", "HEAD"].includes(req.method)) requireCsrf(req);
    if (req.method === "POST" && url.pathname === "/api/auth/flow") {
      for (const [key, expires] of authFlows) if (expires < Date.now()) authFlows.delete(key);
      if (authFlows.size > 20) return jsonResponse(res, 429, { error: "Too many pending sign-ins" });
      const state = crypto.randomBytes(32).toString("base64url");
      authFlows.set(state, Date.now() + 10 * 60 * 1000);
      return jsonResponse(res, 200, { redirect: `http://127.0.0.1:${serverPort}/auth/callback?state=${state}` });
    }
    if (req.method === "GET" && url.pathname === "/api/bootstrap") return jsonResponse(res, 200, bootstrapPayload());
    if (req.method === "GET" && url.pathname === "/api/project/license") return jsonResponse(res, 200, { text: fs.readFileSync(path.join(ROOT, "LICENSE"), "utf8") });
    if (req.method === "GET" && url.pathname === "/api/incoming") return jsonResponse(res, 200, { requests: transfers.approvals.list() });
    const approvalMatch = url.pathname.match(/^\/api\/incoming\/([0-9a-f-]{36})$/i);
    if (req.method === "POST" && approvalMatch) {
      const body = await readJsonBody(req);
      if (typeof body.accept !== "boolean") return jsonResponse(res, 400, { error: "Choose Accept or Decline" });
      try { transfers.decideIncoming(approvalMatch[1], body.accept); }
      catch (error) { return jsonResponse(res, 409, { error: error.message }); }
      return jsonResponse(res, 200, { requests: transfers.approvals.list(), transfers: transfers.list() });
    }
    if (req.method === "POST" && url.pathname === "/api/downloads/show") {
      if (process.parentPort) await desktopFileAction("folder", store.settings.downloadDirectory);
      else await showFolder(store.settings.downloadDirectory);
      return jsonResponse(res, 200, { ok: true });
    }
    const fileMatch = url.pathname.match(/^\/api\/received\/([0-9a-f-]{36})\/(open|show|download|location)$/i);
    if (fileMatch) {
      const file = await receivedFile(store, fileMatch[1]);
      const action = fileMatch[2];
      if (req.method === "GET" && action === "location") return jsonResponse(res, 200, file);
      if (req.method === "GET" && action === "download") {
        res.writeHead(200, { "Content-Type": "application/octet-stream", "Content-Length": fs.statSync(file.path).size,
          "Content-Disposition": `attachment; filename*=UTF-8''${encodeURIComponent(file.name).replace(/'/g, "%27")}` });
        fs.createReadStream(file.path).pipe(res); return;
      }
      if (req.method === "POST" && ["open", "show"].includes(action)) {
        if (process.parentPort) await desktopFileAction(action, file.path);
        else if (action === "show") await showFolder(file.path, true);
        else return jsonResponse(res, 400, { error: "Use Download copy in the browser, or Open file in the desktop app" });
        return jsonResponse(res, 200, { ok: true });
      }
    }
    const previewMatch = url.pathname.match(/^\/api\/received\/([a-f0-9-]{36})\/preview$/i);
    if (req.method === "GET" && previewMatch) {
      const file = await receivedFile(store, previewMatch[1]);
      try {
        const info = await previewInfo(file.path);
        res.writeHead(200, { "Content-Type": info.type, "Content-Length": info.size, "X-Image-Width": info.width, "X-Image-Height": info.height, "Cache-Control": "private, max-age=600", "Content-Disposition": "inline" }); fs.createReadStream(file.path).pipe(res); return;
      } catch { return jsonResponse(res, 415, { error: "No image preview is available" }); }
    }
    if (req.method === "GET" && url.pathname === "/api/devices") return jsonResponse(res, 200, { devices: knownDevices() });
    if (req.method === "POST" && url.pathname === "/api/devices/manual") {
      const address = String((await readJsonBody(req)).address || "").trim();
      const target = await resolvePeer(address);
      if (!target) return jsonResponse(res, 400, { error: "Enter a private IPv4 / Tailscale IP or a full MagicDNS name (*.ts.net), optionally followed by a port" });
      let device;
      try {
        device = await probePeer(target);
      } catch (error) {
        return jsonResponse(res, 502, { error: `Could not reach DropSync at ${target.host}:${target.port}: ${error.message}` });
      }
      store.rememberPeer(address);
      return jsonResponse(res, 200, { device: publicDevice(device) });
    }
    if (req.method === "GET" && url.pathname === "/api/transfers") return jsonResponse(res, 200, { transfers: transfers.list() });
    if (req.method === "DELETE" && url.pathname === "/api/transfers") {
      const status = url.searchParams.get("status");
      if (!['completed', 'failed', 'cancelled'].includes(status)) return jsonResponse(res, 400, { error: "A clearable transfer status is required" });
      const removed = store.clearTransfers(status);
      broadcast("history-cleared", { status, removed });
      return jsonResponse(res, 200, { removed });
    }
    if (req.method === "GET" && url.pathname === "/api/events") {
      res.writeHead(200, {
        "Content-Type": "text/event-stream; charset=utf-8",
        "Cache-Control": "no-cache, no-transform",
        "Connection": "keep-alive",
      });
      res.write(`event: ready\ndata: ${JSON.stringify({ time: Date.now() })}\n\n`);
      eventClients.add(res);
      req.on("close", () => eventClients.delete(res));
      return;
    }
    if (req.method === "POST" && url.pathname === "/api/pairing/session") {
      pairingSession = { ...createPairingSession(), attempts: 0 };
      return jsonResponse(res, 200, { code: pairingSession.code, expiresAt: pairingSession.expiresAt, self: selfInfo() });
    }
    if (req.method === "PUT" && url.pathname === "/api/settings") {
      const oldScan = JSON.stringify([store.settings.virusTotalEnabled, store.settings.virusTotalUploadUnknown, store.settings.virusTotalBlockUnknown]);
      const wasDiscoveryEnabled = store.settings.discoveryEnabled;
      const settings = store.updateSettings(await readJsonBody(req));
      if (oldScan !== JSON.stringify([settings.virusTotalEnabled, settings.virusTotalUploadUnknown, settings.virusTotalBlockUnknown])) transfers.scanner.invalidate();
      if (wasDiscoveryEnabled && !settings.discoveryEnabled) discovery.stop();
      else if (!wasDiscoveryEnabled && settings.discoveryEnabled) discovery.start();
      else discovery.announce();
      broadcast("settings", settings);
      return jsonResponse(res, 200, { settings });
    }
    if (req.method === "POST" && url.pathname === "/api/pair") {
      const body = await readJsonBody(req);
      const trusted = await pairWithDevice(body.deviceId, body.code);
      return jsonResponse(res, 200, { trusted: { deviceId: trusted.deviceId, name: trusted.name, fingerprint: trusted.fingerprint } });
    }
    const trustedMatch = url.pathname.match(/^\/api\/trusted\/([a-f0-9]{32})$/i);
    if (req.method === "DELETE" && trustedMatch) {
      const removed = store.removeTrustedDevice(trustedMatch[1].toLowerCase());
      transfers.revokeDevice(trustedMatch[1].toLowerCase());
      discovery.markTrust(trustedMatch[1].toLowerCase());
      broadcast("devices", knownDevices());
      return jsonResponse(res, 200, { removed });
    }
    if (req.method === "GET" && url.pathname === "/api/updates/status") return jsonResponse(res, 200, await desktopUpdate("status"));
    const updateAction = url.pathname.match(/^\/api\/updates\/(check|download|install|preferences)$/);
    if (req.method === "POST" && updateAction) return jsonResponse(res, 200, await desktopUpdate(updateAction[1], await readJsonBody(req)));
    if (req.method === "GET" && url.pathname === "/api/notifications") return jsonResponse(res, 200, { notifications: store.notifications });
    if (req.method === "POST" && url.pathname === "/api/notifications/read") { store.readNotifications(); return jsonResponse(res, 200, { notifications: store.notifications }); }
    if (req.method === "POST" && url.pathname === "/api/notifications/clear") { store.notifications = []; atomicWriteJson(path.join(DATA_DIR, "notifications.json"), []); return jsonResponse(res, 200, { notifications: [] }); }
    if (req.method === "GET" && url.pathname === "/api/security/virustotal") return jsonResponse(res, 200, { configured: Boolean(store.getSecret("virusTotalApiKey")), persisted: store.vaultStatus().protected });
    if (req.method === "POST" && url.pathname === "/api/security/virustotal/key") { const result = store.setSecret("virusTotalApiKey", String((await readJsonBody(req)).key || "").trim()); transfers.scanner.invalidate(); return jsonResponse(res, 200, result); }
    if (req.method === "POST" && url.pathname === "/api/stage/text") {
      const body = await readJsonBody(req, 1100 * 1024), text = body.text;
      if (typeof text !== "string" || !text.trim() || Buffer.byteLength(text, "utf8") > 1024 * 1024) return jsonResponse(res, 400, { error: "Enter text up to 1 MiB" });
      if (stagedFiles.size >= 100) return jsonResponse(res, 429, { error: "Remove some selected files first" });
      const id = crypto.randomUUID(), target = path.join(DATA_DIR, "staging", `${id}.bin`), contents = Buffer.from(text);
      fs.writeFileSync(target, contents, { flag: "wx", mode: 0o600 });
      const record = { id, name: body.kind === "clipboard" ? "Clipboard text.txt" : "Shared text.txt", size: contents.length, sha256: crypto.createHash("sha256").update(contents).digest("hex"), path: target, createdAt: Date.now() };
      stagedFiles.set(id, record); saveStaging(); return jsonResponse(res, 201, { stagedFiles: [...stagedFiles.values()].map(({ path: _path, ...item }) => item) });
    }
    const retryMatch = url.pathname.match(/^\/api\/transfers\/([a-f0-9-]{36})\/retry$/i);
    if (req.method === "POST" && retryMatch) {
      const previous = transfers.list().find((item) => item.id === retryMatch[1]);
      if (!previous || previous.direction !== "send" || !["failed", "cancelled"].includes(previous.status)) return jsonResponse(res, 400, { error: "Only a stopped outgoing transfer may be retried" });
      const staged = stagedFiles.get(previous.stagedFileId); if (!staged) return jsonResponse(res, 404, { error: "Select the source file again before retrying" });
      return jsonResponse(res, 202, { transfer: await transfers.send({ deviceId: previous.deviceId, stagedFile: staged, operationId: previous.operationId || previous.id, retryOf: previous.id }) });
    }
    if (req.method === "POST" && url.pathname === "/api/stage") return stageFile(req, res);
    const stageMatch = url.pathname.match(/^\/api\/stage\/([0-9a-f-]{36})$/i);
    if (req.method === "DELETE" && stageMatch) {
      const staged = stagedFiles.get(stageMatch[1]);
      if (staged) {
        stagedFiles.delete(stageMatch[1]);
        saveStaging();
        try { fs.unlinkSync(staged.path); } catch { /* already removed */ }
      }
      return jsonResponse(res, 200, { ok: true });
    }
    if (req.method === "POST" && url.pathname === "/api/transfers/send") {
      const body = await readJsonBody(req);
      if (typeof body.deviceId !== "string" || !Array.isArray(body.fileIds) || !body.fileIds.length || body.fileIds.length > 100) {
        return jsonResponse(res, 400, { error: "Choose a device and at least one file" });
      }
      const created = [];
      for (const id of body.fileIds) {
        const staged = stagedFiles.get(id);
        if (!staged) return jsonResponse(res, 404, { error: "A selected file is no longer staged" });
        created.push(await transfers.send({ deviceId: body.deviceId, stagedFile: staged }));
      }
      return jsonResponse(res, 202, { transfers: created });
    }
    const actionMatch = url.pathname.match(/^\/api\/transfers\/([0-9a-f-]{36})\/action$/i);
    if (req.method === "POST" && actionMatch) {
      const body = await readJsonBody(req);
      return jsonResponse(res, 200, { transfer: transfers.control(actionMatch[1], body.action) });
    }
    return jsonResponse(res, 404, { error: "Unknown API endpoint" });
  }

  if (!["GET", "HEAD"].includes(req.method)) return jsonResponse(res, 405, { error: "Method not allowed" });
  serveStatic(url, res);
}

// Authenticated streams may be deliberately slow. Header/body and idle limits are
// enforced separately; a fixed whole-request deadline would abort large transfers.
const server = http.createServer({ maxHeaderSize: 16 * 1024, headersTimeout: 15_000, requestTimeout: 0, keepAliveTimeout: 5000 }, (req, res) => {
  route(req, res).catch((error) => {
    console.error(error);
    if (!res.headersSent) jsonResponse(res, error.statusCode || 500, { error: error.statusCode ? error.message : "Internal server error" });
    else res.destroy();
  });
});
server.maxConnections = 96;
server.maxRequestsPerSocket = 100;
server.setTimeout(120_000, (socket) => socket.destroy());

server.on("error", (error) => {
  if (error.code === "EADDRINUSE") {
    console.error(`DropSync could not start: port ${PORT} is already in use.`);
    console.error("Stop the other DropSync process or set DROPSYNC_PORT to another port.");
    process.exitCode = 1;
    return;
  }
  throw error;
});
server.on("clientError", (_error, socket) => socket.end("HTTP/1.1 400 Bad Request\r\n\r\n"));
server.listen(PORT, HOST, () => {
  serverPort = server.address().port;
  if (store.settings.discoveryEnabled) discovery.start();
  refreshManualPeers();
  process.parentPort?.postMessage({ type: "ready", port: serverPort });
  process.parentPort?.postMessage({ type: "runtime-state", active: 0, keepRunning: store.settings.keepRunningInBackground, clipboardEnabled: store.settings.clipboardEnabled, keepAwake: store.settings.keepAwakeWhileSharing && store.settings.receivingEnabled });
  console.log(`DropSync is running at http://127.0.0.1:${serverPort}`);
  console.log(`Device: ${store.settings.deviceName} (${fingerprint(store.identity.signingPublicKey)})`);
});

const stagingTimer = setInterval(cleanStaging, 60 * 60 * 1000);
stagingTimer.unref?.();

function shutdown() {
  discovery.stop();
  for (const response of eventClients) response.end();
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 3000).unref();
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

module.exports = { server, store, discovery, transfers };
