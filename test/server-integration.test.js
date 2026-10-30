"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const net = require("node:net");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const test = require("node:test");

async function freePort() {
  const server = net.createServer();
  server.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

async function waitFor(fn, timeoutMs = 15_000) {
  const started = Date.now();
  let lastError;
  while (Date.now() - started < timeoutMs) {
    try {
      const value = await fn();
      if (value) return value;
    } catch (error) { lastError = error; }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw lastError || new Error("Timed out waiting for server integration state");
}

async function jsonFetch(url, options = {}) {
  const response = await fetch(url, options);
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || `HTTP ${response.status}`);
  return payload;
}

function launchServer(root, port, dataDir, discoveryPort, name) {
  const child = spawn(process.execPath, ["server.js"], {
    cwd: root,
    env: {
      ...process.env,
      DROPSYNC_PORT: String(port),
      DROPSYNC_DATA_DIR: dataDir,
      DROPSYNC_VAULT_PASSPHRASE: "isolated-fixture-passphrase-only",
      DROPSYNC_DISCOVERY_PORT: String(discoveryPort),
      DROPSYNC_MULTICAST: "239.255.43.77",
    },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  child.output = "";
  child.stdout.on("data", (chunk) => { child.output += chunk; });
  child.stderr.on("data", (chunk) => { child.output += chunk; });
  child.once("exit", (code) => {
    if (code && code !== 0) child.exitError = new Error(`${name} exited with ${code}: ${child.output}`);
  });
  return child;
}

test("two services discover, pair, and transfer a file through the public API", { timeout: 25_000 }, async (t) => {
  const root = path.resolve(__dirname, "..");
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "dropsync-services-"));
  const [portA, portB] = await Promise.all([freePort(), freePort()]);
  const discoveryPort = 46000 + crypto.randomInt(1000);
  const serverA = launchServer(root, portA, path.join(temp, "a"), discoveryPort, "server A");
  const serverB = launchServer(root, portB, path.join(temp, "b"), discoveryPort, "server B");
  const children = [serverA, serverB];
  t.after(async () => {
    for (const child of children) if (!child.killed) child.kill("SIGTERM");
    await Promise.all(children.map((child) => new Promise((resolve) => {
      if (child.exitCode !== null) return resolve();
      child.once("exit", resolve);
      setTimeout(resolve, 2000).unref();
    })));
    fs.rmSync(temp, { recursive: true, force: true });
  });

  const baseA = `http://127.0.0.1:${portA}`;
  const baseB = `http://127.0.0.1:${portB}`;
  await Promise.all([
    waitFor(() => jsonFetch(`${baseA}/healthz`)),
    waitFor(() => jsonFetch(`${baseB}/healthz`)),
  ]);
  if (serverA.exitError) throw serverA.exitError;
  if (serverB.exitError) throw serverB.exitError;

  const [manualSource, manualTarget] = await Promise.all([
    jsonFetch(`${baseA}/api/bootstrap`),
    jsonFetch(`${baseB}/api/bootstrap`),
  ]);
  const manual = await jsonFetch(`${baseA}/api/devices/manual`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-DropSync-CSRF": manualSource.csrfToken },
    body: JSON.stringify({ address: `127.0.0.1:${portB}` }),
  });
  assert.equal(manual.device.deviceId, manualTarget.self.deviceId);
  await jsonFetch(`${baseB}/api/devices/manual`, { method: "POST", headers: { "Content-Type": "application/json", "X-DropSync-CSRF": manualTarget.csrfToken }, body: JSON.stringify({ address: `127.0.0.1:${portA}` }) });

  const discovered = await waitFor(async () => {
    const [a, b] = await Promise.all([jsonFetch(`${baseA}/api/bootstrap`), jsonFetch(`${baseB}/api/bootstrap`)]);
    const seenB = a.devices.find((device) => device.deviceId === b.self.deviceId);
    const seenA = b.devices.find((device) => device.deviceId === a.self.deviceId);
    return seenA && seenB ? { a, b, seenA, seenB } : null;
  });

  assert.equal((await fetch(`${baseB}/api/pairing/session`, { method: "POST" })).status, 403);
  const sessionB = await jsonFetch(`${baseB}/api/pairing/session`, { method: "POST", headers: { "X-DropSync-CSRF": manualTarget.csrfToken } });
  await jsonFetch(`${baseA}/api/pair`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-DropSync-CSRF": discovered.a.csrfToken },
    body: JSON.stringify({ deviceId: discovered.b.self.deviceId, code: sessionB.code }),
  });
  const paired = await jsonFetch(`${baseA}/api/bootstrap`);
  assert.equal(paired.trustedDevices.some((device) => device.deviceId === discovered.b.self.deviceId), true);

  const contents = crypto.randomBytes(400_000);
  const staged = await jsonFetch(`${baseA}/api/stage`, {
    method: "POST",
    headers: {
      "Content-Type": "application/octet-stream",
      "X-DropSync-CSRF": discovered.a.csrfToken,
      "X-DropSync-File-Name": Buffer.from("server-integration.bin").toString("base64url"),
    },
    body: contents,
  });
  const started = await jsonFetch(`${baseA}/api/transfers/send`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-DropSync-CSRF": discovered.a.csrfToken },
    body: JSON.stringify({ deviceId: discovered.b.self.deviceId, fileIds: [staged.id] }),
  });
  const transferId = started.transfers[0].id;
  await waitFor(async () => (await jsonFetch(`${baseB}/api/incoming`)).requests.some((item) => item.id === transferId));
  assert.equal(fs.readdirSync(path.join(temp, "b", "downloads")).length, 0);
  await jsonFetch(`${baseB}/api/incoming/${transferId}`, { method: "POST",
    headers: { "Content-Type": "application/json", "X-DropSync-CSRF": manualTarget.csrfToken }, body: JSON.stringify({ accept: true }) });
  await waitFor(async () => {
    const state = await jsonFetch(`${baseA}/api/transfers`);
    return state.transfers.find((item) => item.id === transferId && item.status === "completed");
  });
  const output = path.join(temp, "b", "downloads", "server-integration.bin");
  assert.deepEqual(fs.readFileSync(output), contents);
  const location = await jsonFetch(`${baseB}/api/received/${transferId}/location`);
  assert.equal(location.path, output);
  assert.deepEqual(Buffer.from(await (await fetch(`${baseB}/api/received/${transferId}/download`)).arrayBuffer()), contents);
  assert.equal((await fetch(`${baseB}/api/received/${transferId}/show`, { method: "POST" })).status, 403);

  // Local static serving must not expose source or machine-local state.
  for (const url of ["/server.js", "/src/store.js", "/package.json", "/.dropsync-data/identity.json"]) {
    assert.equal((await fetch(`${baseA}${url}`)).status, 404);
  }
  const reboundStatus = await new Promise((resolve, reject) => {
    http.get(`${baseA}/api/bootstrap`, { headers: { Host: "attacker.example" } }, (response) => { response.resume(); resolve(response.statusCode); }).on("error", reject);
  });
  assert.equal(reboundStatus, 403);
  assert.equal((await fetch(`${baseA}/api/settings`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: "{}" })).status, 403);

  await new Promise((resolve) => { serverA.once("exit", resolve); serverA.kill(); });
  const restartedA = launchServer(root, portA, path.join(temp, "a"), discoveryPort, "restarted A");
  children.push(restartedA);
  const restarted = await waitFor(() => jsonFetch(`${baseA}/api/bootstrap`));
  assert.equal(restarted.transfers.find((item) => item.id === transferId).status, "completed");
  assert.equal(restarted.trustedDevices.some((item) => item.deviceId === discovered.b.self.deviceId), true);
});
