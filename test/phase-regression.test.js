"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { Store } = require("../src/store");
const { resolvePeer } = require("../src/peer-address");
const { listVolumes } = require("../src/storage");

test("completed history survives restart and interrupted transfers become failed", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "dropsync-history-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const before = new Store(root);
  before.addTransfer({ id: "complete", status: "completed", fileName: "real.txt" });
  before.addTransfer({ id: "interrupted", status: "receiving", fileName: "partial.txt" });
  before.rememberPeer("100.100.1.2:47821");
  const after = new Store(root);
  assert.equal(after.transfers.find((t) => t.id === "complete").status, "completed");
  assert.equal(after.transfers.find((t) => t.id === "interrupted").status, "failed");
  assert.deepEqual(after.settings.manualPeers, ["100.100.1.2:47821"]);
});

test("Tailscale resolution pins CGNAT addresses and rejects public targets", async () => {
  assert.deepEqual(await resolvePeer("100.80.1.2:47821"), { host: "100.80.1.2", port: 47821 });
  assert.deepEqual(await resolvePeer("laptop.example.ts.net", async () => ({ address: "100.90.2.3" })), { host: "100.90.2.3", port: 47821 });
  for (const address of ["8.8.8.8", "100.128.0.1", "example.com", "127.0.0.1:65536", "127.0.0.1:0", "http://127.0.0.1"]) assert.equal(await resolvePeer(address), null);
  assert.equal(await resolvePeer("laptop.example.ts.net", async () => ({ address: "8.8.8.8" })), null);
});

test("all readable volumes expose consistent capacity measurements", () => {
  const volumes = listVolumes(os.tmpdir());
  assert.ok(volumes.length > 0);
  for (const volume of volumes) { assert.ok(volume.total > 0); assert.ok(volume.free >= 0); assert.equal(volume.used, Math.max(0, volume.total - volume.free)); }
});
