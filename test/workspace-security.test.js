"use strict";
// Offline regression fixtures. Execute only with scripts/test-isolated.sh.
const test = require("node:test"), assert = require("node:assert/strict");
const fs = require("node:fs"), path = require("node:path"), os = require("node:os"), crypto = require("node:crypto");
const vault = require("../src/local-vault");
const { Store } = require("../src/store");
const { validateIdToken } = require("../auth-server/oidc");
const recordVault = require("../auth-server/record-vault");
const { ThreatScanner, verdict } = require("../src/threat-scanner");
const { TransferManager } = require("../src/transfer-manager");
const { resolvePeer } = require("../src/peer-address");
const { createIdentity, publicIdentity, createEphemeralExchange, deriveTransferKey, sealFileInfo, signObject, transferReceipt } = require("../src/security");

function directory(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "dropsync-isolated-vault-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true })); return dir;
}
function storeFixture(t) {
  const dir = directory(t), key = crypto.randomBytes(32); vault.register(dir, key, "Fixture vault");
  return { store: new Store(dir), dir, key };
}

test("protected records preserve device identity across migration and fail closed with a wrong key", (t) => {
  const dir = directory(t), legacy = new Store(dir), id = legacy.identity.deviceId, key = crypto.randomBytes(32);
  legacy.updateSettings({ profile: { displayName: "Private owner", avatar: "" } });
  vault.register(dir, key, "Fixture vault"); vault.migrate(dir);
  assert.equal(new Store(dir).identity.deviceId, id);
  assert.equal(fs.readFileSync(path.join(dir, "settings.json"), "utf8").includes("Private owner"), false);
  const original = fs.readFileSync(path.join(dir, "identity.json"), "utf8");
  vault.register(dir, crypto.randomBytes(32)); assert.throws(() => new Store(dir));
  assert.equal(fs.readFileSync(path.join(dir, "identity.json"), "utf8"), original);
  vault.register(dir, key); assert.equal(new Store(dir).identity.deviceId, id);
  const copied = JSON.parse(fs.readFileSync(path.join(dir, "settings.json"), "utf8"));
  assert.throws(() => vault.decode(path.join(dir, "identity.json"), copied), /auth|authenticate/i);
});

test("an invalid existing identity is preserved instead of replaced", (t) => {
  const dir = directory(t), file = path.join(dir, "identity.json"), content = '{"invalid":true}'; fs.writeFileSync(file, content);
  assert.throws(() => new Store(dir), /preserved/); assert.equal(fs.readFileSync(file, "utf8"), content);
});

test("API keys and notification records are encrypted and are not returned in settings", (t) => {
  const { store, dir } = storeFixture(t), key = "a".repeat(64);
  assert.deepEqual(store.setSecret("virusTotalApiKey", key), { configured: true, persisted: true });
  store.notify({ title: "Private filename", body: "confidential.txt", kind: "transfer" });
  assert.equal(fs.readFileSync(path.join(dir, "secrets.json"), "utf8").includes(key), false);
  assert.equal(fs.readFileSync(path.join(dir, "notifications.json"), "utf8").includes("confidential.txt"), false);
  const restored = new Store(dir); assert.equal(restored.getSecret("virusTotalApiKey"), key);
  assert.equal(JSON.stringify(restored.settings).includes(key), false);
  assert.equal(restored.notifications[0].read, false); restored.readNotifications();
  assert.equal(new Store(dir).notifications[0].read, true);
});

test("interrupted cleanup removes only the recorded device-owned partial", (t) => {
  const { store, dir } = storeFixture(t), id = crypto.randomUUID(), folder = store.settings.downloadDirectory;
  const owned = path.join(folder, `.dropsync-${store.identity.deviceId}-${id}.part`), unrelated = path.join(folder, "report.part");
  fs.writeFileSync(owned, "partial"); fs.writeFileSync(unrelated, "keep me");
  store.addTransfer({ id, direction: "receive", status: "receiving", partialPath: owned, receivingDirectory: folder });
  const restored = new Store(dir); assert.equal(restored.transfers[0].status, "failed");
  assert.equal(fs.existsSync(owned), false); assert.equal(fs.readFileSync(unrelated, "utf8"), "keep me");
});

test("managed controls reject changes and malformed UI data cannot become active content", (t) => {
  const { store } = storeFixture(t); store.policy = { settings: { requireIncomingApproval: true }, allowedPeerIds: ["a".repeat(32)] };
  assert.throws(() => store.updateSettings({ requireIncomingApproval: false }), /managed/);
  assert.equal(store.peerAllowed("b".repeat(32)), false); assert.equal(store.peerAllowed("a".repeat(32)), true);
  for (const patch of [{ uploadLimitKBps: -1 }, { retryAttempts: 6 }, { receivingEnabled: "false" }, { allowExecutableFiles: "true" }, { profile: { avatar: "data:image/svg+xml;base64,AAAA" } }]) assert.throws(() => store.updateSettings(patch));
});

test("VirusTotal rejects detections, malformed reports and unknown files without uploading by default", async (t) => {
  assert.equal(verdict({ malicious: 0, suspicious: 1, harmless: 4, undetected: 2 }), "malicious");
  for (const bad of [{}, { malicious: -1, suspicious: 0, harmless: 0, undetected: 1 }, { malicious: 0, suspicious: 0, harmless: "1", undetected: 1 }]) assert.throws(() => verdict(bad));
  const { store } = storeFixture(t); store.setSecret("virusTotalApiKey", "a".repeat(64)); store.updateSettings({ virusTotalEnabled: true });
  const scanner = new ThreatScanner(store), requests = [];
  scanner.request = async (resource) => { requests.push(resource); return null; };
  await assert.rejects(() => scanner.inspect("b".repeat(64)), /unknown-file policy/);
  assert.deepEqual(requests, ["files/" + "b".repeat(64)]);
  store.updateSettings({ virusTotalBlockUnknown: false });
  assert.equal(await scanner.inspect("b".repeat(64)), "virustotal-unknown");
});

test("a retried completed operation gets a new authenticated receipt without a second file or approval", async (t) => {
  const { store } = storeFixture(t), peer = createIdentity(), operationId = crypto.randomUUID();
  store.trustDevice({ ...publicIdentity(peer), name: "Paired phone" });
  store.addTransfer({ id: crypto.randomUUID(), operationId, deviceId: peer.deviceId, direction: "receive", status: "completed", sha256: "b".repeat(64), requestedName: "private.txt", fileName: "private.txt", size: 7 });
  const manager = new TransferManager({ store, discovery: {} });
  async function prepare(name = "private.txt") {
    const ephemeral = createEphemeralExchange(), salt = crypto.randomBytes(32), transferId = crypto.randomUUID();
    const key = deriveTransferKey(ephemeral.privateKey, store.identity.exchangePublicKey, salt, transferId);
    const meta = { version: 2, transferId, operationId, senderId: peer.deviceId, recipientId: store.identity.deviceId, size: 7, chunkSize: 262144, timestamp: Date.now(), salt: salt.toString("base64url"), noncePrefix: crypto.randomBytes(8).toString("base64url"), ephemeralPublicKey: ephemeral.publicKey, fileInfo: sealFileInfo(key, transferId, { fileName: name, sha256: "b".repeat(64) }) };
    const result = {}; await manager.prepareIncoming({ headers: { "x-dropsync-meta": Buffer.from(JSON.stringify(meta)).toString("base64url"), "x-dropsync-signature": signObject(meta, peer.signingPrivateKey) } }, { writeHead(code) { result.code = code; }, end(body) { result.body = JSON.parse(body); } });
    return { ...result, key, meta };
  }
  const first = await prepare(), second = await prepare(); assert.equal(first.body.status, "completed"); assert.equal(second.body.status, "completed");
  assert.notEqual(first.meta.transferId, second.meta.transferId);
  assert.equal(second.body.receipt, transferReceipt(second.key, { ...second.meta, sha256: "b".repeat(64) }));
  assert.notEqual(first.body.receipt, second.body.receipt); assert.equal(manager.approvals.list().length, 0);
  assert.equal(fs.readdirSync(store.settings.downloadDirectory).length, 0);
  assert.equal((await prepare("changed.txt")).code, 401);
  manager.denyOperation(peer.deviceId, operationId); assert.equal((await prepare()).code, 401);
});

test("changing VirusTotal configuration aborts in-flight checks and revokes future content uploads", async (t) => {
  const { store } = storeFixture(t), key = "c".repeat(64); store.setSecret("virusTotalApiKey", key); store.updateSettings({ virusTotalEnabled: true });
  const scanner = new ThreatScanner(store);
  scanner.request = (_resource, _key, { signal }) => new Promise((_resolve, reject) => { signal.addEventListener("abort", () => reject(signal.reason), { once: true }); });
  const check = scanner.inspect("d".repeat(64)); scanner.invalidate();
  await assert.rejects(() => check, /configuration changed/); assert.equal(scanner.inFlight.size, 0);
  const gated = new ThreatScanner(store);
  await assert.rejects(() => gated.request("files", key, { file: "must-never-be-opened", size: 1 }), /permission or API key changed/);
});

test("private peer resolution rejects public IPs and MagicDNS rebinding", async () => {
  assert.equal(await resolvePeer("8.8.8.8"), null);
  assert.equal(await resolvePeer("device.example.com"), null);
  assert.equal(await resolvePeer("home.example.ts.net", async () => ({ address: "8.8.8.8" })), null);
  assert.deepEqual(await resolvePeer("home.example.ts.net:47821", async () => ({ address: "100.80.0.2" })), { host: "100.80.0.2", port: 47821 });
});

test("OIDC verifies signature, issuer, audience, nonce, time and verified email using offline keys", () => {
  const pair = crypto.generateKeyPairSync("ed25519"), jwk = { ...pair.publicKey.export({ format: "jwk" }), kid: "fixture", use: "sig", alg: "EdDSA" };
  const options = { issuer: "https://idp.example.test", clientId: "dropsync", nonce: "fixture-nonce", now: 1000 };
  const claims = { iss: options.issuer, aud: "dropsync", sub: "person-1", nonce: options.nonce, iat: 990, exp: 1100, email: "Person@example.test", email_verified: true };
  function jwt(patch = {}, headerPatch = {}) {
    const head = Buffer.from(JSON.stringify({ alg: "EdDSA", kid: "fixture", ...headerPatch })).toString("base64url"), body = Buffer.from(JSON.stringify({ ...claims, ...patch })).toString("base64url");
    const content = `${head}.${body}`; return `${content}.${crypto.sign(null, Buffer.from(content), pair.privateKey).toString("base64url")}`;
  }
  assert.equal(validateIdToken(jwt(), [jwk], options).email, "person@example.test");
  for (const patch of [{ iss: "https://evil.example.test" }, { aud: "other" }, { aud: ["dropsync", "other"] }, { nonce: "replayed" }, { exp: 900 }, { iat: 1100 }, { email_verified: false }]) assert.throws(() => validateIdToken(jwt(patch), [jwk], options));
  assert.throws(() => validateIdToken(jwt({}, { alg: "HS256" }), [jwk], options));
  assert.throws(() => validateIdToken(jwt({}, { jku: "https://evil.example.test/keys" }), [jwk], options));
  assert.throws(() => validateIdToken(jwt(), [jwk, jwk], options));
  const other = { ...crypto.generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" }), kid: "fixture" };
  assert.throws(() => validateIdToken(jwt(), [other], options));
});

test("account records cannot be opened without the original server key", () => {
  const key = crypto.randomBytes(32).toString("base64"), records = { users: [{ email: "private@example.test" }] }, box = recordVault.protect(records, key);
  assert.equal(JSON.stringify(box).includes(records.users[0].email), false); assert.deepEqual(recordVault.unlock(box, key), records);
  assert.throws(() => recordVault.unlock(box, "")); assert.throws(() => recordVault.unlock(box, crypto.randomBytes(32).toString("base64")));
});

test("organization roles require SSO; members cannot self-promote and suspension revokes sessions", async (t) => {
  const { AuthStore, createAuthServer } = require("../auth-server/server");
  const dir = directory(t), key = crypto.randomBytes(32).toString("base64"), records = new AuthStore(dir, key);
  const admin = records.createUser("admin@example.test"), member = records.createUser("member@example.test");
  records.state.organizations.push({ id: "fixture", name: "Fixture", members: [{ userId: admin.id, role: "admin" }, { userId: member.id, role: "member" }] }); records.save();
  const adminSession = records.createSession(admin, "oidc"), memberSession = records.createSession(member, "oidc"), passwordSession = records.createSession(admin, "password");
  const clientKey = "isolated-client-key-at-least-32-characters";
  const server = createAuthServer({ DROPSYNC_AUTH_CLIENT_KEY: clientKey, DROPSYNC_AUTH_PUBLIC_URL: "http://127.0.0.1:8787", DROPSYNC_AUTH_DATA_DIR: dir,
    DROPSYNC_AUTH_STORAGE_KEY: key, DROPSYNC_ORG_ID: "fixture", DROPSYNC_ORG_NAME: "Fixture", DROPSYNC_ORG_REQUIRE_SSO: "true",
    DROPSYNC_OIDC_ISSUER: "https://idp.example.test", DROPSYNC_OIDC_CLIENT_ID: "fixture", DROPSYNC_OIDC_CLIENT_SECRET: "dummy-secret", DROPSYNC_AUTH_ALLOWED_ORIGINS: "https://appassets.androidplatform.net" });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve)); t.after(() => new Promise((resolve) => server.close(resolve)));
  async function request(route, session, body) {
    return fetch(`http://127.0.0.1:${server.address().port}/auth/v1/${route}`, { method: body ? "POST" : "GET", headers: { apikey: clientKey, Origin: "https://appassets.androidplatform.net", Authorization: `Bearer ${session.access_token}`, "Content-Type": "application/json" }, ...(body ? { body: JSON.stringify(body) } : {}) });
  }
  assert.equal((await request("user", passwordSession)).status, 403);
  assert.equal((await request("organization", memberSession)).status, 200);
  assert.equal((await request("organization/members", memberSession, { userId: member.id, role: "admin" })).status, 403);
  assert.equal((await request("organization/members", adminSession, { userId: admin.id, role: "member" })).status, 409);
  assert.equal((await request("organization/members", adminSession, { userId: member.id, role: "suspended" })).status, 200);
  assert.equal((await request("user", memberSession)).status, 401);
  assert.equal((await request("token?grant_type=refresh_token", memberSession, { refresh_token: memberSession.refresh_token })).status, 401);
  const disk = new AuthStore(dir, key); assert.equal(disk.state.audit.at(-1).event, "organization-role-changed");
  assert.equal(disk.state.organizations[0].members.find((item) => item.userId === member.id).role, "suspended");
});
