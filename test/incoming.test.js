"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const crypto = require("node:crypto");
const { Store } = require("../src/store");
const { IncomingApprovals, APPROVAL_TTL_MS } = require("../src/incoming-approvals");
const { receivedFile } = require("../src/received-files");

function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "dropsync-incoming-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return new Store(directory);
}
test("incoming approval defaults on, binds metadata, supports decline and persists the toggle", (t) => {
  const store = fixture(t), approvals = new IncomingApprovals({ store });
  const meta = { transferId: crypto.randomUUID(), senderId: "a", fileName: "photo.jpg", size: 1 };
  const request = approvals.ensure(meta, { name: "Phone" });
  assert.equal(request.status, "pending"); assert.equal(approvals.list().length, 1);
  assert.equal(approvals.ensure(meta, { name: "Phone" }), request);
  assert.throws(() => approvals.ensure({ ...meta, fileName: "other.exe" }, { name: "Phone" }), /metadata changed/);
  approvals.decide(meta.transferId, false);
  assert.equal(approvals.list().length, 0); assert.equal(approvals.ensure(meta, {}).status, "rejected");
  assert.equal(store.transfers[0].status, "rejected");
  store.updateSettings({ requireIncomingApproval: false });
  assert.equal(new Store(store.dataDir).settings.requireIncomingApproval, false);
  assert.equal(approvals.ensure({ ...meta, transferId: crypto.randomUUID() }, {}).status, "accepted");
});
test("unanswered incoming requests expire without being accepted", (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const store = fixture(t), approvals = new IncomingApprovals({ store });
  const meta = { transferId: crypto.randomUUID(), fileName: "photo.jpg", size: 1 };
  approvals.ensure(meta, { name: "Phone" });
  t.mock.timers.tick(APPROVAL_TTL_MS);
  assert.equal(approvals.list().length, 0); assert.equal(approvals.requests.get(meta.transferId).status, "expired");
  assert.equal(store.transfers[0].status, "rejected");
});
test("saved paths survive download-folder changes, and legacy filenames are verified before opening", async (t) => {
  const store = fixture(t), oldDirectory = store.settings.downloadDirectory;
  const target = path.join(oldDirectory, "photo.jpg"), contents = Buffer.from("verified photo"); fs.writeFileSync(target, contents);
  const id = crypto.randomUUID();
  store.addTransfer({ id, fileName: "photo.jpg", size: contents.length, sha256: crypto.createHash("sha256").update(contents).digest("hex"), direction: "receive", status: "completed" });
  assert.equal((await receivedFile(store, id)).path, target);
  store.updateSettings({ downloadDirectory: path.join(store.dataDir, "new-downloads") });
  assert.equal((await receivedFile(new Store(store.dataDir), id)).path, target);
  fs.unlinkSync(target);
  await assert.rejects(() => receivedFile(store, id), /moved or deleted/);
  const legacy = { id: crypto.randomUUID(), fileName: "other.jpg", size: 4, sha256: "0".repeat(64), direction: "receive", status: "completed" };
  store.addTransfer(legacy); fs.writeFileSync(path.join(store.settings.downloadDirectory, legacy.fileName), "oops");
  await assert.rejects(() => receivedFile(store, legacy.id), /different file/);
  await assert.rejects(() => receivedFile(store, crypto.randomUUID()), /not found/);
});
