"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { once } = require("node:events");
const {
  CHUNK_SIZE,
  createEphemeralExchange,
  decryptChunk,
  deriveTransferKey,
  encryptChunk,
  signObject,
  verifyObject,
  sealFileInfo,
  openFileInfo,
  transferReceipt,
  timingSafeStringEqual,
} = require("./security");
const { uniquePath } = require("./utils");
const { IncomingApprovals } = require("./incoming-approvals");
const { enforceIncomingPolicy, markReceivedFile } = require("./content-policy");
const { ThreatScanner } = require("./threat-scanner");
const { BandwidthLimiter } = require("./bandwidth");

function publicTransfer(transfer) {
  const { request, waiters, sourcePath, targetPath, scanAbort, partialPath, receivingDirectory, ...safe } = transfer;
  return safe;
}

function expectedWireSize(size, chunkSize = CHUNK_SIZE) {
  return size + Math.ceil(size / chunkSize) * 24;
}

class TransferManager {
  constructor({ store, discovery, onEvent, logger = console }) {
    this.store = store;
    this.discovery = discovery;
    this.onEvent = onEvent;
    this.logger = logger;
    this.active = new Map();
    this.seenTransferIds = new Map();
    this.receivingIds = new Set();
    this.scanner = new ThreatScanner(store);
    this.uploadLimit = new BandwidthLimiter(() => store.settings.uploadLimitKBps * 1024);
    this.downloadLimit = new BandwidthLimiter(() => store.settings.downloadLimitKBps * 1024);
    this.remoteLimits = new Map();
    this.authorizedOperations = new Map();
    this.deniedOperations = new Map();
    this.approvals = new IncomingApprovals({ store, onChange: (pending) => this.onEvent?.("incoming", pending) });
  }

  list() {
    const liveIds = new Set(this.active.keys());
    const live = [...this.active.values()].map(publicTransfer);
    const historic = this.store.transfers.filter((item) => !liveIds.has(item.id)).map(publicTransfer);
    return [...live, ...historic].slice(0, 500);
  }

  emit(transfer) {
    const safe = publicTransfer(transfer);
    this.onEvent?.("transfer", safe);
    this.store.addTransfer({ ...safe, ...(transfer.partialPath ? { partialPath: transfer.partialPath, receivingDirectory: transfer.receivingDirectory } : {}) });
  }

  update(transfer, patch, persist = false) {
    Object.assign(transfer, patch, { updatedAt: new Date().toISOString() });
    this.onEvent?.("transfer", publicTransfer(transfer));
    if (persist) this.store.addTransfer({ ...publicTransfer(transfer), ...(transfer.partialPath ? { partialPath: transfer.partialPath, receivingDirectory: transfer.receivingDirectory } : {}) });
  }

  async send({ deviceId, stagedFile, operationId, retryOf }) {
    const discovered = this.discovery.get(deviceId);
    const trusted = this.store.getTrustedDevice(deviceId);
    if (!discovered || !discovered.online) throw new Error("Device is not online");
    if (!trusted) throw new Error("Device must be paired before sending");
    if (this.store.settings.sendingEnabled === false) throw new Error("Sending is disabled by device policy");
    this.assertTrusted(deviceId, discovered);
    if (!stagedFile || !fs.existsSync(stagedFile.path)) throw new Error("Staged file is missing");

    const id = crypto.randomUUID();
    const transfer = {
      id,
      operationId: operationId || id,
      retryOf: retryOf || null,
      direction: "send",
      deviceId,
      deviceName: discovered.name,
      fileName: stagedFile.name,
      size: stagedFile.size,
      sha256: stagedFile.sha256,
      stagedFileId: stagedFile.id,
      bytesTransferred: 0,
      progress: 0,
      status: "connecting",
      encrypted: true,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      paused: false,
      cancelled: false,
      waiters: [],
      sourcePath: stagedFile.path,
      request: null,
      scanAbort: new AbortController(),
    };
    this.active.set(id, transfer);
    this.emit(transfer);
    this.runJob(transfer, discovered, trusted).catch((error) => {
      if (transfer.cancelled) return;
      transfer.request?.destroy();
      this.update(transfer, { status: "failed", error: error.message }, true);
      this.active.delete(transfer.id);
      this.logger.warn(`Transfer ${transfer.id} failed: ${error.message}`);
    });
    return publicTransfer(transfer);
  }

  async waitIfPaused(transfer) {
    while (transfer.paused && !transfer.cancelled) {
      await new Promise((resolve) => transfer.waiters.push(resolve));
    }
    if (transfer.cancelled) throw new Error("Transfer cancelled");
  }

  assertTrusted(id, pinned) {
    const current = this.store.getTrustedDevice(id);
    if (!current || !this.store.peerAllowed(id) || current.signingPublicKey !== pinned.signingPublicKey || current.exchangePublicKey !== pinned.exchangePublicKey) throw new Error("Device trust was removed or its identity changed");
  }

  revokeDevice(id) {
    for (const [key] of this.authorizedOperations) if (key.startsWith(id + ":")) this.authorizedOperations.delete(key);
    for (const item of this.approvals.requests.values()) if (item.meta.senderId === id) this.approvals.settle(item, "rejected");
    for (const transfer of [...this.active.values()]) if (transfer.deviceId === id) this.control(transfer.id, "cancel");
  }

  async runJob(transfer, discovered, trusted) {
    for (let attempt = 0; ; attempt++) {
      transfer.wireId = attempt ? crypto.randomUUID() : transfer.id;
      try { return await this.runSend(transfer, this.discovery.get(transfer.deviceId) || discovered, trusted); }
      catch (error) {
        transfer.request?.destroy();
        if (transfer.cancelled || transfer.status === "scanning" || attempt >= this.store.settings.retryAttempts || !/ECONNRESET|ECONNREFUSED|EHOSTUNREACH|ENETUNREACH|ETIMEDOUT|EPIPE|timed out|socket hang up|aborted/i.test(`${error.code || ""} ${error.message}`)) throw error;
        const retryAt = Date.now() + Math.min(30000, 5000 * 2 ** attempt);
        this.update(transfer, { status: "retrying", retryCount: attempt + 1, retryAt, error: "Connection interrupted. Retrying the verified file.", bytesTransferred: 0, progress: 0 }, true);
        while (Date.now() < retryAt) { await this.waitIfPaused(transfer); this.assertTrusted(transfer.deviceId, trusted); await new Promise((resolve) => setTimeout(resolve, 250)); }
      }
    }
  }

  operation(meta) { return `${meta.senderId}:${meta.operationId || meta.transferId}`; }
  authorized(meta) {
    const lease = this.authorizedOperations.get(this.operation(meta));
    return Boolean(lease && lease.expires > Date.now() && lease.sha256 === meta.sha256 && lease.size === meta.size && lease.fileName === meta.fileName);
  }
  rememberAuthorization(meta) {
    for (const [key, item] of this.authorizedOperations) if (item.expires <= Date.now()) this.authorizedOperations.delete(key);
    if (this.authorized(meta)) return;
    if (this.authorizedOperations.size >= 500) this.authorizedOperations.delete(this.authorizedOperations.keys().next().value);
    this.authorizedOperations.set(this.operation(meta), { expires: Date.now() + 15 * 60000, sha256: meta.sha256, size: meta.size, fileName: meta.fileName });
  }
  decideIncoming(id, accept) {
    const meta = this.approvals.requests.get(id)?.meta;
    this.approvals.decide(id, accept);
    if (meta && !accept) this.denyOperation(meta.senderId, meta.operationId || meta.transferId);
  }
  denyOperation(id, operationId) {
    const key = `${id}:${operationId}`; this.authorizedOperations.delete(key);
    if (this.deniedOperations.size >= 500) this.deniedOperations.delete(this.deniedOperations.keys().next().value);
    this.deniedOperations.set(key, Date.now() + 900000);
  }
  completedOperation(meta) {
    const previous = this.store.transfers.find((item) => item.direction === "receive" && item.status === "completed" && item.deviceId === meta.senderId && (item.operationId || item.id) === (meta.operationId || meta.transferId));
    if (!previous) return false;
    if (previous.sha256 !== meta.sha256 || previous.size !== meta.size || (previous.requestedName && previous.requestedName !== meta.fileName)) throw new Error("Operation metadata changed");
    return true;
  }

  async runSend(transfer, discovered, trusted) {
    this.update(transfer, { status: "scanning" });
    const securityScan = await this.scanner.inspect(transfer.sha256, transfer.sourcePath, { signal: transfer.scanAbort.signal });
    this.update(transfer, { status: "connecting", securityScan });
    const ephemeral = createEphemeralExchange();
    const salt = crypto.randomBytes(32);
    const noncePrefix = crypto.randomBytes(8);
    const wireId = transfer.wireId;
    const key = deriveTransferKey(ephemeral.privateKey, trusted.exchangePublicKey, salt, wireId);
    const meta = {
      version: 2,
      transferId: wireId,
      operationId: transfer.operationId,
      senderId: this.store.identity.deviceId,
      recipientId: trusted.deviceId,
      size: transfer.size,
      fileInfo: sealFileInfo(key, wireId, { fileName: transfer.fileName, sha256: transfer.sha256 }),
      timestamp: Date.now(),
      chunkSize: CHUNK_SIZE,
      ephemeralPublicKey: ephemeral.publicKey,
      salt: salt.toString("base64url"),
      noncePrefix: noncePrefix.toString("base64url"),
    };
    const signature = signObject(meta, this.store.identity.signingPrivateKey);
    await this.waitIfPaused(transfer);
    const prepared = await this.prepareOutgoing(transfer, discovered, meta, signature);
    if (prepared.status === "completed") {
      if (!prepared.ok || prepared.transferId !== wireId || !timingSafeStringEqual(prepared.receipt || "", transferReceipt(key, { ...meta, sha256: transfer.sha256 }))) throw new Error("Peer completion receipt could not be authenticated");
      this.assertTrusted(transfer.deviceId, trusted); this.update(transfer, { status: "completed", error: null, progress: 100, bytesTransferred: transfer.size }, true); this.active.delete(transfer.id); return;
    }
    let remote = this.remoteLimits.get(transfer.deviceId);
    if (!remote) { remote = { rate: 0 }; remote.limiter = new BandwidthLimiter(() => remote.rate); this.remoteLimits.set(transfer.deviceId, remote); }
    remote.rate = Number.isSafeInteger(prepared.downloadLimitKBps) && prepared.downloadLimitKBps >= 0 && prepared.downloadLimitKBps <= 1048576 ? prepared.downloadLimitKBps * 1024 : 0;
    const responsePromise = new Promise((resolve, reject) => {
      const request = http.request({
        host: discovered.address,
        port: discovered.port,
        path: "/peer/transfers",
        method: "POST",
        headers: {
          "Content-Type": "application/vnd.dropsync.encrypted-stream",
          "Content-Length": expectedWireSize(transfer.size),
          "X-DropSync-Meta": Buffer.from(JSON.stringify(meta)).toString("base64url"),
          "X-DropSync-Signature": signature,
        },
        timeout: 180_000,
      }, (response) => {
        const chunks = [];
        let responseSize = 0;
        response.on("data", (chunk) => {
          responseSize += chunk.length;
          if (responseSize <= 64 * 1024) chunks.push(chunk);
          else response.destroy(new Error("Peer response too large"));
        });
        response.on("error", reject);
        response.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          if (response.statusCode >= 200 && response.statusCode < 300) resolve(text);
          else reject(new Error(`Peer rejected transfer (${response.statusCode}): ${text.slice(0, 200)}`));
        });
      });
      transfer.request = request;
      request.on("timeout", () => request.destroy(new Error("Peer connection timed out")));
      request.on("error", reject);
    });
    responsePromise.catch(() => {});

    this.update(transfer, { status: "sending" });
    let counter = 0;
    for await (const chunk of fs.createReadStream(transfer.sourcePath, { highWaterMark: CHUNK_SIZE })) {
      await this.waitIfPaused(transfer);
      this.assertTrusted(transfer.deviceId, trusted);
      const frame = encryptChunk(key, noncePrefix, wireId, counter, chunk);
      for (let offset = 0; offset < frame.length; offset += 4096) {
        const part = frame.subarray(offset, offset + 4096);
        await this.uploadLimit.consume(part.length, () => { this.assertTrusted(transfer.deviceId, trusted); if (transfer.cancelled) throw new Error("Transfer cancelled"); });
        await remote.limiter.consume(part.length, () => { if (transfer.cancelled) throw new Error("Transfer cancelled"); });
        if (!transfer.request.write(part)) await once(transfer.request, "drain");
      }
      counter += 1;
      transfer.bytesTransferred += chunk.length;
      const progress = transfer.size ? Math.min(100, Math.round(transfer.bytesTransferred / transfer.size * 1000) / 10) : 100;
      this.update(transfer, { progress });
    }
    transfer.request.end();
    const receipt = JSON.parse(await responsePromise);
    this.assertTrusted(transfer.deviceId, trusted);
    if (!receipt.ok || receipt.transferId !== wireId || !timingSafeStringEqual(receipt.receipt || "", transferReceipt(key, { ...meta, sha256: transfer.sha256 }))) throw new Error("Peer completion receipt could not be authenticated");
    this.update(transfer, { status: "completed", error: null, progress: 100, bytesTransferred: transfer.size }, true);
    this.active.delete(transfer.id);
  }

  control(id, action, replacement = false) {
    if (!this.active.has(id) && action === "cancel" && ["pending", "accepted"].includes(this.approvals.requests.get(id)?.status)) {
      this.decideIncoming(id, false);
      return this.store.transfers.find((item) => item.id === id);
    }
    const transfer = this.active.get(id);
    if (!transfer) throw new Error("Active transfer not found");
    if (action === "pause" && transfer.direction === "send") {
      transfer.paused = true;
      this.update(transfer, { status: "paused" });
    } else if (action === "resume" && transfer.direction === "send") {
      transfer.paused = false;
      this.update(transfer, { status: "sending" });
      transfer.waiters.splice(0).forEach((resolve) => resolve());
    } else if (action === "cancel") {
      if (transfer.direction === "receive" && !replacement) this.denyOperation(transfer.deviceId, transfer.operationId || transfer.id);
      transfer.cancelled = true;
      transfer.scanAbort?.abort();
      transfer.paused = false;
      transfer.waiters.splice(0).forEach((resolve) => resolve());
      transfer.request?.destroy(new Error("Transfer cancelled"));
      this.update(transfer, { status: "cancelled", error: null }, true);
      this.active.delete(id);
    } else {
      throw new Error("Unsupported transfer action");
    }
    return publicTransfer(transfer);
  }

  async prepareOutgoing(transfer, peer, meta, signature) {
    const deadline = Date.now() + 180_000;
    while (true) {
      await this.waitIfPaused(transfer);
      this.assertTrusted(transfer.deviceId, peer);
      const result = await new Promise((resolve, reject) => {
        const request = http.request({ host: peer.address, port: peer.port, path: "/peer/transfers/prepare", method: "POST",
          headers: { "Content-Length": 0, "X-DropSync-Meta": Buffer.from(JSON.stringify(meta)).toString("base64url"), "X-DropSync-Signature": signature }, timeout: 180000 }, (response) => {
          let body = "";
          response.on("data", (chunk) => { body += chunk; if (body.length > 65_536) response.destroy(new Error("Peer response too large")); });
          response.on("error", reject);
          response.on("end", () => {
            try {
              const value = JSON.parse(body);
              if (response.statusCode >= 400) reject(new Error(value.error || "Incoming transfer declined"));
              else resolve(value);
            } catch (error) { reject(error); }
          });
        });
        transfer.request = request;
        request.on("error", reject);
        request.on("timeout", () => request.destroy(new Error("Peer connection timed out")));
        request.end();
      });
      if (["accepted", "completed"].includes(result.status)) return result;
      if (result.status !== "pending" || Date.now() > deadline) throw new Error("Incoming request expired or was declined");
      this.update(transfer, { status: "awaiting-acceptance" });
      await new Promise((resolve) => setTimeout(resolve, 800));
    }
  }

  parseMeta(req, preflight = false) {
    const encoded = req.headers["x-dropsync-meta"];
    const signature = req.headers["x-dropsync-signature"];
    if (typeof encoded !== "string" || encoded.length > 12_000 || typeof signature !== "string") throw new Error("Missing transfer authentication");
    let meta;
    try { meta = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")); } catch { throw new Error("Invalid transfer metadata"); }
    if (meta.version !== 2 || typeof meta.transferId !== "string" || !/^[0-9a-f-]{36}$/i.test(meta.transferId)) throw new Error("DropSync transfer v2 is required. Update both devices.");
    if (meta.operationId !== undefined && (typeof meta.operationId !== "string" || !/^[a-f0-9-]{36}$/i.test(meta.operationId))) throw new Error("Invalid operation identity");
    if (meta.recipientId !== this.store.identity.deviceId) throw new Error("Transfer is for another device");
    if (!Number.isSafeInteger(meta.size) || meta.size < 0 || meta.size > this.store.settings.maxIncomingFileBytes) throw new Error("File size is not allowed");
    if (meta.chunkSize !== CHUNK_SIZE) throw new Error("Invalid transfer integrity data");
    if (!Number.isFinite(meta.timestamp) || Math.abs(Date.now() - meta.timestamp) > 5 * 60 * 1000) throw new Error("Transfer request expired");
    if (this.seenTransferIds.has(meta.transferId)) throw new Error("Duplicate transfer request");
    const trusted = this.store.getTrustedDevice(meta.senderId);
    if (!trusted || !this.store.peerAllowed(meta.senderId)) throw new Error("Sender is not paired or allowed by policy");
    if (this.store.settings.receivingEnabled === false) throw new Error("Receiving is disabled on this device");
    if (!verifyObject(meta, signature, trusted.signingPublicKey)) throw new Error("Invalid transfer signature");
    if (Buffer.from(meta.salt || "", "base64url").length !== 32 || Buffer.from(meta.noncePrefix || "", "base64url").length !== 8
      || crypto.createPublicKey(meta.ephemeralPublicKey).asymmetricKeyType !== "x25519") throw new Error("Invalid encryption parameters");
    const key = deriveTransferKey(this.store.identity.exchangePrivateKey, meta.ephemeralPublicKey, Buffer.from(meta.salt, "base64url"), meta.transferId);
    const info = openFileInfo(key, meta.transferId, meta.fileInfo);
    if (typeof info.fileName !== "string" || !info.fileName.trim() || info.fileName.length > 500 || !/^[a-f0-9]{64}$/.test(info.sha256)) throw new Error("Invalid private file metadata");
    meta = { ...meta, fileName: enforceIncomingPolicy(info.fileName, this.store.settings), sha256: info.sha256 };
    const contentLength = Number(req.headers["content-length"]);
    if (!preflight && (!Number.isSafeInteger(contentLength) || contentLength !== expectedWireSize(meta.size, meta.chunkSize))) throw new Error("Invalid encrypted stream size");
    return { meta, trusted };
  }

  async prepareIncoming(req, res) {
    try {
      const { meta, trusted } = this.parseMeta(req, true);
      if ((this.deniedOperations.get(this.operation(meta)) || 0) > Date.now()) throw new Error("Incoming transfer was declined");
      await this.scanner.inspect(meta.sha256);
      this.assertTrusted(meta.senderId, trusted);
      if (this.completedOperation(meta)) {
        const key = deriveTransferKey(this.store.identity.exchangePrivateKey, meta.ephemeralPublicKey, Buffer.from(meta.salt, "base64url"), meta.transferId);
        res.writeHead(200, { "Content-Type": "application/json" }); res.end(JSON.stringify({ status: "completed", ok: true, transferId: meta.transferId, receipt: transferReceipt(key, meta) })); return;
      }
      const item = this.approvals.ensure(meta, trusted, this.authorized(meta));
      if (item.status === "accepted") {
        this.rememberAuthorization(meta);
        for (const previous of [...this.active.values()]) if (previous.direction === "receive" && previous.deviceId === meta.senderId && previous.operationId === (meta.operationId || meta.transferId) && previous.id !== meta.transferId) this.control(previous.id, "cancel", true);
      }
      const rejected = ["rejected", "expired"].includes(item.status);
      res.writeHead(rejected ? 403 : 200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(rejected ? { error: item.status === "expired" ? "Incoming request expired" : "Incoming transfer declined" }
        : { status: item.status, transferId: meta.transferId, expiresAt: item.expiresAt, downloadLimitKBps: this.store.settings.downloadLimitKBps }));
    } catch (error) { res.writeHead(401, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: error.message })); }
  }

  async receive(req, res) {
    let parsed;
    try { parsed = this.parseMeta(req); } catch (error) {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: error.message }));
      return;
    }
    const { meta, trusted } = parsed;
    if (this.receivingIds.size >= this.store.settings.maxConcurrentIncoming) { res.writeHead(429); res.end(JSON.stringify({ error: "Too many active incoming transfers" })); return; }
    if (this.receivingIds.has(meta.transferId)) { res.writeHead(409); res.end(); return; }
    this.receivingIds.add(meta.transferId);
    try {
      req.pause();
      const item = this.approvals.ensure(meta, trusted, this.authorized(meta));
      const decision = await this.approvals.wait(item, req);
      this.assertTrusted(meta.senderId, trusted);
      enforceIncomingPolicy(meta.fileName, this.store.settings);
      if (decision !== "accepted" || req.aborted) {
        res.writeHead(403, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: "Incoming transfer declined or expired" }));
        this.receivingIds.delete(meta.transferId); return;
      }
    } catch (error) {
      this.receivingIds.delete(meta.transferId);
      res.writeHead(400, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: error.message })); return;
    }
    this.approvals.finish(meta.transferId);
    this.rememberAuthorization(meta);
    this.seenTransferIds.set(meta.transferId, Date.now());
    for (const [id, timestamp] of this.seenTransferIds) {
      if (Date.now() - timestamp > 10 * 60 * 1000) this.seenTransferIds.delete(id);
    }

    let targetPath = uniquePath(this.store.settings.downloadDirectory, meta.fileName);
    let partPath = path.join(this.store.settings.downloadDirectory, `.dropsync-${this.store.identity.deviceId}-${meta.transferId}.part`);
    const transfer = {
      id: meta.transferId,
      direction: "receive",
      deviceId: meta.senderId,
      deviceName: trusted.name,
      fileName: path.basename(targetPath),
      size: meta.size,
      sha256: meta.sha256,
      operationId: meta.operationId || meta.transferId,
      requestedName: meta.fileName,
      bytesTransferred: 0,
      progress: 0,
      status: "receiving",
      encrypted: true,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      paused: false,
      cancelled: false,
      waiters: [],
      request: req,
      targetPath,
      partialPath: partPath,
      receivingDirectory: this.store.settings.downloadDirectory,
      scanAbort: new AbortController(),
    };
    this.active.set(transfer.id, transfer);
    this.emit(transfer);

    const salt = Buffer.from(meta.salt, "base64url");
    const noncePrefix = Buffer.from(meta.noncePrefix, "base64url");
    let key;
    try {
      if (salt.length !== 32 || noncePrefix.length !== 8) throw new Error("Invalid encryption parameters");
      key = deriveTransferKey(this.store.identity.exchangePrivateKey, meta.ephemeralPublicKey, salt, meta.transferId);
    } catch (error) {
      this.update(transfer, { status: "failed", error: "Key agreement failed" }, true);
      this.active.delete(transfer.id);
      this.receivingIds.delete(transfer.id);
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: error.message }));
      return;
    }

    let descriptor;
    try {
      const space = fs.statfsSync(this.store.settings.downloadDirectory);
      if (Number(space.bavail) * Number(space.bsize) < meta.size + 64 * 1024 * 1024) throw new Error("Not enough free space");
      while (true) {
        try { descriptor = fs.openSync(partPath, "wx", 0o600); break; }
        catch (error) {
          throw error;
        }
      }
    } catch (error) {
      this.update(transfer, { status: "failed", error: "Could not create a file in the download folder" }, true);
      this.active.delete(transfer.id); this.receivingIds.delete(transfer.id);
      res.writeHead(500, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: "Could not create a file in the download folder" })); return;
    }
    const output = fs.createWriteStream(partPath, { fd: descriptor, autoClose: true });
    output.on("error", (error) => req.destroy(error));
    const hash = crypto.createHash("sha256");
    let pending = Buffer.alloc(0);
    let expectedCounter = 0;
    try {
      for await (const networkChunk of req) {
        this.assertTrusted(meta.senderId, trusted);
        req.setTimeout?.(0);
        await this.downloadLimit.consume(networkChunk.length, () => { this.assertTrusted(meta.senderId, trusted); if (transfer.cancelled) throw new Error("Transfer cancelled"); });
        req.setTimeout?.(120_000);
        if (transfer.cancelled) throw new Error("Transfer cancelled");
        pending = pending.length ? Buffer.concat([pending, networkChunk]) : networkChunk;
        while (pending.length >= 8) {
          const encryptedLength = pending.readUInt32BE(4);
          if (encryptedLength > CHUNK_SIZE) throw new Error("Encrypted frame is too large");
          const frameLength = 8 + encryptedLength + 16;
          if (pending.length < frameLength) break;
          const frame = pending.subarray(0, frameLength);
          pending = pending.subarray(frameLength);
          const { counter, plaintext } = decryptChunk(key, noncePrefix, meta.transferId, frame);
          if (counter !== expectedCounter) throw new Error("Encrypted frame sequence is invalid");
          expectedCounter += 1;
          transfer.bytesTransferred += plaintext.length;
          if (transfer.bytesTransferred > meta.size) throw new Error("Received more data than declared");
          hash.update(plaintext);
          if (!output.write(plaintext)) await once(output, "drain");
          const progress = meta.size ? Math.min(100, Math.round(transfer.bytesTransferred / meta.size * 1000) / 10) : 100;
          this.update(transfer, { progress });
        }
      }
      if (pending.length || transfer.bytesTransferred !== meta.size) throw new Error("Encrypted stream ended unexpectedly");
      output.end();
      await once(output, "finish");
      if (!output.closed) await once(output, "close");
      if (hash.digest("hex") !== meta.sha256) throw new Error("File integrity verification failed");
      this.update(transfer, { status: "scanning" });
      const securityScan = await this.scanner.inspect(meta.sha256, partPath, { signal: transfer.scanAbort.signal });
      if (transfer.cancelled) throw new Error("Transfer cancelled");
      this.assertTrusted(meta.senderId, trusted);
      enforceIncomingPolicy(meta.fileName, this.store.settings);
      // Atomic no-replace publication. rename() can overwrite an existing file on Unix.
      while (true) {
        try { fs.linkSync(partPath, targetPath); break; }
        catch (error) {
          if (error.code !== "EEXIST") throw error;
          targetPath = uniquePath(this.store.settings.downloadDirectory, meta.fileName);
        }
      }
      fs.unlinkSync(partPath);
      const safety = markReceivedFile(targetPath);
      this.update(transfer, { status: "completed", progress: 100, fileName: path.basename(targetPath), savedPath: targetPath, safety, securityScan }, true);
      this.active.delete(transfer.id);
      res.writeHead(201, { "Content-Type": "application/json; charset=utf-8" });
      res.end(JSON.stringify({ ok: true, transferId: transfer.id, receipt: transferReceipt(key, meta) }));
    } catch (error) {
      output.destroy();
      try { fs.unlinkSync(partPath); } catch { /* nothing to clean */ }
      this.update(transfer, { status: transfer.cancelled ? "cancelled" : "failed", error: error.message }, true);
      this.active.delete(transfer.id);
      if (!res.headersSent) {
        res.writeHead(400, { "Content-Type": "application/json; charset=utf-8" });
        res.end(JSON.stringify({ error: "Transfer was interrupted or blocked. Check the receiving device for details." }));
      } else res.destroy();
    } finally {
      this.receivingIds.delete(transfer.id);
      this.approvals.finish(transfer.id);
    }
  }
}

module.exports = { TransferManager, expectedWireSize, publicTransfer };
