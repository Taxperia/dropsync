"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { once } = require("node:events");
const { Store } = require("../src/store");
const { publicIdentity } = require("../src/security");
const { TransferManager } = require("../src/transfer-manager");

async function waitFor(predicate, timeoutMs = 5000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const value = predicate();
    if (value) return value;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error("Timed out waiting for transfer");
}

test("a paired peer receives and verifies an encrypted file", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "dropsync-transfer-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const storeA = new Store(path.join(root, "a"));
  const storeB = new Store(path.join(root, "b"));
  storeA.updateSettings({ deviceName: "Sender" });
  storeB.updateSettings({ deviceName: "Receiver", requireIncomingApproval: false });
  storeA.trustDevice({ ...publicIdentity(storeB.identity), name: "Receiver" });
  storeB.trustDevice({ ...publicIdentity(storeA.identity), name: "Sender" });

  const receivedEvents = [];
  const managerB = new TransferManager({ store: storeB, discovery: { get: () => null }, onEvent: (_type, data) => receivedEvents.push(data) });
  const peerServer = http.createServer((req, res) => req.url === "/peer/transfers/prepare" ? managerB.prepareIncoming(req, res) : managerB.receive(req, res));
  peerServer.listen(0, "127.0.0.1");
  await once(peerServer, "listening");
  t.after(() => peerServer.close());
  const port = peerServer.address().port;

  const discovery = {
    get: (id) => id === storeB.identity.deviceId ? {
      deviceId: id,
      name: "Receiver",
      address: "127.0.0.1",
      port,
      online: true,
      signingPublicKey: storeB.identity.signingPublicKey,
      exchangePublicKey: storeB.identity.exchangePublicKey,
    } : null,
  };
  const sentEvents = [];
  const managerA = new TransferManager({ store: storeA, discovery, onEvent: (_type, data) => sentEvents.push(data) });
  const payload = crypto.randomBytes(700_000);
  const sourcePath = path.join(root, "payload.bin");
  fs.writeFileSync(sourcePath, payload);
  const stagedFile = {
    id: crypto.randomUUID(),
    path: sourcePath,
    name: "payload.bin",
    size: payload.length,
    sha256: crypto.createHash("sha256").update(payload).digest("hex"),
  };

  const started = await managerA.send({ deviceId: storeB.identity.deviceId, stagedFile });
  const paused = managerA.control(started.id, "pause");
  assert.equal(paused.status, "paused");
  const pausedAt = paused.bytesTransferred;
  await new Promise((resolve) => setTimeout(resolve, 40));
  assert.equal(managerA.list().find((item) => item.id === started.id).bytesTransferred, pausedAt);
  assert.equal(managerA.control(started.id, "resume").status, "sending");
  const completed = await waitFor(() => sentEvents.find((event) => event.id === started.id && event.status === "completed"));
  assert.equal(completed.progress, 100);
  const received = await waitFor(() => receivedEvents.find((event) => event.id === started.id && event.status === "completed"));
  assert.equal(received.sha256, stagedFile.sha256);
  const outputPath = path.join(storeB.settings.downloadDirectory, "payload.bin");
  assert.deepEqual(fs.readFileSync(outputPath), payload);
});

test("a forged completion receipt does not mark a delivered transfer successful", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "dropsync-receipt-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const a = new Store(path.join(root, "a")), b = new Store(path.join(root, "b"));
  a.trustDevice({ ...publicIdentity(b.identity), name: "Receiver" }); b.trustDevice({ ...publicIdentity(a.identity), name: "Sender" });
  b.updateSettings({ requireIncomingApproval: false });
  const receiver = new TransferManager({ store: b, discovery: {}, logger: { warn() {} } });
  const server = http.createServer((req, res) => {
    if (req.url.endsWith("/prepare")) return receiver.prepareIncoming(req, res);
    const end = res.end;
    res.end = function (data) {
      const reply = JSON.parse(data);
      if (reply.ok) reply.receipt = "forged";
      return end.call(this, JSON.stringify(reply));
    };
    receiver.receive(req, res);
  });
  server.listen(0, "127.0.0.1"); await once(server, "listening");
  t.after(() => { server.closeAllConnections(); server.close(); });
  const sender = new TransferManager({ store: a, logger: { warn() {} }, discovery: { get: () => ({ ...publicIdentity(b.identity), online: true, name: "Receiver", address: "127.0.0.1", port: server.address().port }) } });
  const source = path.join(root, "source.txt"), content = Buffer.from("synthetic private text"); fs.writeFileSync(source, content);
  const started = await sender.send({ deviceId: b.identity.deviceId, stagedFile: { id: crypto.randomUUID(), path: source, name: "secret.txt", size: content.length, sha256: crypto.createHash("sha256").update(content).digest("hex") } });
  const failed = await waitFor(() => sender.list().find((item) => item.id === started.id && item.status === "failed"));
  assert.match(failed.error, /receipt/); assert.deepEqual(fs.readFileSync(path.join(b.settings.downloadDirectory, "secret.txt")), content);
});

test("revoking an active sender prevents publishing its partially received file", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "dropsync-active-revoke-")); t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const a = new Store(path.join(root, "a")), b = new Store(path.join(root, "b"));
  a.trustDevice({ ...publicIdentity(b.identity), name: "Receiver" }); b.trustDevice({ ...publicIdentity(a.identity), name: "Sender" });
  b.updateSettings({ requireIncomingApproval: false });
  let revoked = false;
  const receiver = new TransferManager({ store: b, discovery: {}, logger: { warn() {} }, onEvent: (type, transfer) => {
    if (type === "transfer" && transfer.bytesTransferred > 0 && !revoked) { revoked = true; b.removeTrustedDevice(a.identity.deviceId); receiver.revokeDevice(a.identity.deviceId); }
  } });
  const server = http.createServer((req, res) => req.url.endsWith("/prepare") ? receiver.prepareIncoming(req, res) : receiver.receive(req, res));
  server.listen(0, "127.0.0.1"); await once(server, "listening"); t.after(() => { server.closeAllConnections(); server.close(); });
  const sender = new TransferManager({ store: a, logger: { warn() {} }, discovery: { get: () => ({ ...publicIdentity(b.identity), online: true, name: "Receiver", address: "127.0.0.1", port: server.address().port }) } });
  const content = crypto.randomBytes(4 * 262144), source = path.join(root, "source.bin"); fs.writeFileSync(source, content);
  const started = await sender.send({ deviceId: b.identity.deviceId, stagedFile: { id: crypto.randomUUID(), path: source, name: "revoked.bin", size: content.length, sha256: crypto.createHash("sha256").update(content).digest("hex") } });
  // A reset can trigger the sender's 5-second retry before the revoked peer rejects it.
  await waitFor(() => revoked && sender.list().find((item) => item.id === started.id && item.status === "failed"), 10_000);
  await waitFor(() => receiver.receivingIds.size === 0);
  assert.deepEqual(fs.readdirSync(b.settings.downloadDirectory), []);
});
