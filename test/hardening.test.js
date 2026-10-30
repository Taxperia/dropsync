"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs"), os = require("node:os"), path = require("node:path");
const { createIdentity, publicIdentity, createEphemeralExchange, deriveTransferKey, sealFileInfo, openFileInfo, transferReceipt, signObject } = require("../src/security");
const { enforceIncomingPolicy } = require("../src/content-policy");
const { safeFileName } = require("../src/utils");
const { Store } = require("../src/store");
const { TransferManager } = require("../src/transfer-manager");
const { DiscoveryService } = require("../src/discovery");

test("private metadata binds transfer identity; completion receipts bind content", () => {
  const key = crypto.randomBytes(32), id = crypto.randomUUID(), info = { fileName: "private-document.txt", sha256: "a".repeat(64) };
  const sealed = sealFileInfo(key, id, info);
  assert.equal(JSON.stringify(sealed).includes(info.fileName), false);
  assert.deepEqual(openFileInfo(key, id, sealed), info);
  assert.throws(() => openFileInfo(key, crypto.randomUUID(), sealed));
  assert.throws(() => openFileInfo(crypto.randomBytes(32), id, sealed));
  const meta = { transferId: id, senderId: "a", recipientId: "b", size: 1, sha256: info.sha256 };
  assert.notEqual(transferReceipt(key, meta), transferReceipt(key, { ...meta, sha256: "b".repeat(64) }));
});
test("installers and scripts are blocked by default and special filenames are sanitized", () => {
  for (const name of ["setup.EXE", "script.ps1", "payload.apk", "launcher.desktop", "start.sh", "shortcut.lnk"]) assert.throws(() => enforceIncomingPolicy(name, {}), /blocked/);
  assert.equal(enforceIncomingPolicy("photo.jpg", {}), "photo.jpg");
  assert.equal(enforceIncomingPolicy("setup.exe", { allowExecutableFiles: true }), "setup.exe");
  assert.equal(safeFileName("CON.txt"), "_CON.txt"); assert.equal(safeFileName("photo\u202egpj.exe"), "photo_gpj.exe");
});
test("trust revocation settles pending approval and rejects a subsequent authenticated preflight", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "dropsync-revoke-")); t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const store = new Store(dir), peer = createIdentity(); store.trustDevice({ ...publicIdentity(peer), name: "Phone" });
  const manager = new TransferManager({ store, discovery: {} });
  const id = crypto.randomUUID(), ephemeral = createEphemeralExchange(), salt = crypto.randomBytes(32);
  const key = deriveTransferKey(ephemeral.privateKey, store.identity.exchangePublicKey, salt, id);
  const wire = { version: 2, transferId: id, senderId: peer.deviceId, recipientId: store.identity.deviceId, size: 0, chunkSize: 262144,
    timestamp: Date.now(), salt: salt.toString("base64url"), noncePrefix: crypto.randomBytes(8).toString("base64url"), ephemeralPublicKey: ephemeral.publicKey,
    fileInfo: sealFileInfo(key, id, { fileName: "secret.txt", sha256: "a".repeat(64) }) };
  const req = { headers: { "x-dropsync-meta": Buffer.from(JSON.stringify(wire)).toString("base64url"), "x-dropsync-signature": signObject(wire, peer.signingPrivateKey) } };
  const { meta, trusted } = manager.parseMeta(req, true); const pending = manager.approvals.ensure(meta, trusted);
  const signature = req.headers["x-dropsync-signature"];
  req.headers["x-dropsync-signature"] = signObject(wire, createIdentity().signingPrivateKey);
  assert.throws(() => manager.parseMeta(req, true), /signature/);
  req.headers["x-dropsync-signature"] = signature;
  store.removeTrustedDevice(peer.deviceId); manager.revokeDevice(peer.deviceId);
  assert.equal(pending.status, "rejected"); assert.throws(() => manager.parseMeta(req, true), /not paired/);
  assert.equal(fs.readdirSync(store.settings.downloadDirectory).length, 0);
});
test("a valid discovery signature cannot silently replace a pinned exchange key", () => {
  const local = createIdentity(), peer = createIdentity(), other = createIdentity();
  const discovery = new DiscoveryService({ identity: local, getName: () => "Local", getPort: () => 47821, isTrusted: () => true, getTrustedIdentity: () => peer });
  const data = { ...publicIdentity(peer), exchangePublicKey: other.exchangePublicKey, name: "Peer", port: 47821, timestamp: Date.now() };
  discovery.handleMessage(Buffer.from(JSON.stringify({ type: "dropsync-announce", data, signature: signObject(data, peer.signingPrivateKey) })), { address: "192.168.1.20" });
  assert.equal(discovery.list().length, 0);
});
