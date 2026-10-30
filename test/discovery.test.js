"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { DiscoveryService, subnetBroadcast } = require("../src/discovery");
const { createIdentity, publicIdentity, signObject } = require("../src/security");

test("discovery accepts signed current announcements and rejects tampering", () => {
  const local = createIdentity();
  const peer = createIdentity();
  let changes = 0;
  const discovery = new DiscoveryService({
    identity: local,
    getName: () => "Local",
    getPort: () => 47821,
    isTrusted: () => false,
    onChange: () => { changes += 1; },
    logger: { warn() {} },
  });
  const data = {
    ...publicIdentity(peer),
    name: "Peer",
    deviceType: "phone",
    port: 47822,
    timestamp: Date.now(),
    nonce: "test-nonce",
  };
  const packet = Buffer.from(JSON.stringify({ type: "dropsync-announce", data, signature: signObject(data, peer.signingPrivateKey) }));
  discovery.handleMessage(packet, { address: "192.168.1.40" });
  assert.equal(discovery.list().length, 1);
  assert.equal(discovery.list()[0].name, "Peer");
  assert.equal(discovery.list()[0].deviceType, "phone");
  assert.equal(changes, 1);

  const tampered = Buffer.from(JSON.stringify({ type: "dropsync-announce", data: { ...data, name: "Impostor" }, signature: signObject(data, peer.signingPrivateKey) }));
  discovery.handleMessage(tampered, { address: "192.168.1.99" });
  assert.equal(discovery.list()[0].name, "Peer");
  assert.equal(changes, 1);
});

test("discovery calculates directed LAN broadcast addresses", () => {
  assert.equal(subnetBroadcast("192.168.1.42", "255.255.255.0"), "192.168.1.255");
  assert.equal(subnetBroadcast("10.20.33.9", "255.255.0.0"), "10.20.255.255");
  assert.equal(subnetBroadcast("100.93.121.51", "255.255.255.255"), null);
});
