"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const {
  createIdentity,
  createPairingEnvelope,
  decryptChunk,
  deriveTransferKey,
  encryptChunk,
  openPairingEnvelope,
  openWithKey,
  publicIdentity,
  sealWithKey,
  signObject,
  validatePublicIdentity,
  verifyObject,
} = require("../src/security");

test("device identities are self-authenticating and signatures reject tampering", () => {
  const identity = createIdentity();
  const publicPart = publicIdentity(identity);
  assert.equal(validatePublicIdentity(publicPart), true);
  const message = { deviceId: identity.deviceId, timestamp: Date.now() };
  const signature = signObject(message, identity.signingPrivateKey);
  assert.equal(verifyObject(message, signature, identity.signingPublicKey), true);
  assert.equal(verifyObject({ ...message, deviceId: "0".repeat(32) }, signature, identity.signingPublicKey), false);
});

test("pairing requests and responses are encrypted to the target device", () => {
  const target = createIdentity();
  const request = createPairingEnvelope(target.exchangePublicKey, { code: "123456", name: "Sender" });
  const opened = openPairingEnvelope(target.exchangePrivateKey, request.envelope);
  assert.deepEqual(opened.payload, { code: "123456", name: "Sender" });
  const response = sealWithKey(opened.key, request.requestId, { accepted: true });
  assert.deepEqual(openWithKey(request.key, request.requestId, response), { accepted: true });
  const tampered = Buffer.from(response.ciphertext, "base64url");
  tampered[0] ^= 1;
  response.ciphertext = tampered.toString("base64url");
  assert.throws(() => openWithKey(request.key, request.requestId, response));
});

test("each transfer chunk is authenticated independently", () => {
  const sender = crypto.generateKeyPairSync("x25519");
  const receiver = crypto.generateKeyPairSync("x25519");
  const receiverPublic = receiver.publicKey.export({ type: "spki", format: "pem" }).toString();
  const senderPublic = sender.publicKey.export({ type: "spki", format: "pem" }).toString();
  const salt = crypto.randomBytes(32);
  const id = crypto.randomUUID();
  const senderKey = deriveTransferKey(sender.privateKey, receiverPublic, salt, id);
  const receiverKey = deriveTransferKey(receiver.privateKey, senderPublic, salt, id);
  assert.deepEqual(senderKey, receiverKey);
  const prefix = crypto.randomBytes(8);
  const frame = encryptChunk(senderKey, prefix, id, 0, Buffer.from("DropSync encrypted payload"));
  assert.equal(decryptChunk(receiverKey, prefix, id, frame).plaintext.toString(), "DropSync encrypted payload");
  frame[10] ^= 1;
  assert.throws(() => decryptChunk(receiverKey, prefix, id, frame));
});
