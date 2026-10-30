"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { verifyManifest, newer } = require("../src/update-manifest");

test("update manifest authenticates exact bytes and rejects tampering, expired and ambiguous packages", () => {
  const keys = crypto.generateKeyPairSync("ed25519"), now = Date.now();
  const config = { owner: "dropsync-example", repo: "dropsync", publicKey: keys.publicKey.export({ type: "spki", format: "pem" }).toString() };
  const artifact = { platform: "win32", arch: "x64", name: "DropSync-Setup-0.7.0.exe", size: 100, sha256: "a".repeat(64) };
  const manifest = { schema: 1, version: "0.7.0", tag: "v0.7.0", publishedAt: now, expiresAt: now + 86400_000, artifacts: [artifact] };
  const options = { currentVersion: "0.6.0", platform: "win32", arch: "x64", now };
  const signed = (value) => { const bytes = Buffer.from(JSON.stringify(value)); return [bytes, crypto.sign(null, bytes, keys.privateKey).toString("base64")]; };
  const [bytes, signature] = signed(manifest);
  const result = verifyManifest(bytes, signature, config, options);
  assert.equal(result.available, true); assert.equal(result.url, "https://github.com/dropsync-example/dropsync/releases/download/v0.7.0/DropSync-Setup-0.7.0.exe");
  assert.throws(() => verifyManifest(Buffer.concat([bytes, Buffer.from(" ")]), signature, config, options), /signature/);
  assert.throws(() => verifyManifest(...signed({ ...manifest, expiresAt: now - 1 }), config, options), /expired/);
  assert.throws(() => verifyManifest(...signed({ ...manifest, artifacts: [artifact, artifact] }), config, options), /unique/);
  assert.throws(() => verifyManifest(...signed({ ...manifest, artifacts: [{ ...artifact, name: "../payload.exe" }] }), config, options), /package/);
  assert.throws(() => verifyManifest(bytes, signature, { ...config, owner: "evil/owner" }, options), /repository/);
  assert.equal(verifyManifest(bytes, signature, config, { ...options, currentVersion: "0.7.0" }).available, false);
  assert.equal(verifyManifest(bytes, signature, config, { ...options, currentVersion: "1.0.0" }).available, false);
  assert.throws(() => verifyManifest(bytes, signature, { ...config, publicKey: crypto.generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString() }, options), /signature/);
  assert.equal(newer("1.0.0", "0.99.99"), true); assert.throws(() => newer("1.0.0-beta.1", "0.6.0"));
});
