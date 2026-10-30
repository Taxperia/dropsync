"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { Store } = require("../src/store");
const { publicIdentity } = require("../src/security");

test("identity, trusted devices and settings persist across restarts", (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "dropsync-store-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const first = new Store(directory);
  const deviceId = first.identity.deviceId;
  first.updateSettings({ deviceName: "Test Device", ui: { "accent-color": "#5B9DD6", compact: true } });

  const peerDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "dropsync-peer-"));
  t.after(() => fs.rmSync(peerDirectory, { recursive: true, force: true }));
  const peer = new Store(peerDirectory);
  first.trustDevice({ ...publicIdentity(peer.identity), name: "Peer" });

  const second = new Store(directory);
  assert.equal(second.identity.deviceId, deviceId);
  assert.equal(second.settings.deviceName, "Test Device");
  assert.equal(second.settings.ui["accent-color"], "#5B9DD6");
  assert.equal(second.getTrustedDevice(peer.identity.deviceId).name, "Peer");
});
