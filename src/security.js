"use strict";

const crypto = require("node:crypto");
const { canonicalJson } = require("./utils");

const PROTOCOL_VERSION = 1;
const CHUNK_SIZE = 256 * 1024;

function exportPublicPem(key) {
  return key.export({ type: "spki", format: "pem" }).toString();
}

function exportPrivatePem(key) {
  return key.export({ type: "pkcs8", format: "pem" }).toString();
}

function publicKeyId(publicPem) {
  const der = crypto.createPublicKey(publicPem).export({ type: "spki", format: "der" });
  return crypto.createHash("sha256").update(der).digest("hex").slice(0, 32);
}

function createIdentity() {
  const signing = crypto.generateKeyPairSync("ed25519");
  const exchange = crypto.generateKeyPairSync("x25519");
  const signingPublicKey = exportPublicPem(signing.publicKey);
  return {
    version: PROTOCOL_VERSION,
    deviceId: publicKeyId(signingPublicKey),
    signingPublicKey,
    signingPrivateKey: exportPrivatePem(signing.privateKey),
    exchangePublicKey: exportPublicPem(exchange.publicKey),
    exchangePrivateKey: exportPrivatePem(exchange.privateKey),
    createdAt: new Date().toISOString(),
  };
}

function publicIdentity(identity) {
  return {
    version: PROTOCOL_VERSION,
    deviceId: identity.deviceId,
    signingPublicKey: identity.signingPublicKey,
    exchangePublicKey: identity.exchangePublicKey,
  };
}

function signObject(value, privatePem) {
  return crypto.sign(null, Buffer.from(canonicalJson(value)), crypto.createPrivateKey(privatePem)).toString("base64url");
}

function verifyObject(value, signature, publicPem) {
  try {
    return crypto.verify(
      null,
      Buffer.from(canonicalJson(value)),
      crypto.createPublicKey(publicPem),
      Buffer.from(signature, "base64url"),
    );
  } catch {
    return false;
  }
}

function validatePublicIdentity(candidate) {
  if (!candidate || candidate.version !== PROTOCOL_VERSION) return false;
  if (typeof candidate.deviceId !== "string" || !/^[a-f0-9]{32}$/.test(candidate.deviceId)) return false;
  if (typeof candidate.signingPublicKey !== "string" || typeof candidate.exchangePublicKey !== "string") return false;
  try {
    if (publicKeyId(candidate.signingPublicKey) !== candidate.deviceId) return false;
    if (crypto.createPublicKey(candidate.signingPublicKey).asymmetricKeyType !== "ed25519") return false;
    if (crypto.createPublicKey(candidate.exchangePublicKey).asymmetricKeyType !== "x25519") return false;
    return true;
  } catch {
    return false;
  }
}

function validatePrivateIdentity(candidate) {
  if (!validatePublicIdentity(candidate) || typeof candidate.signingPrivateKey !== "string" || typeof candidate.exchangePrivateKey !== "string") return false;
  try {
    const signingPublic = exportPublicPem(crypto.createPublicKey(crypto.createPrivateKey(candidate.signingPrivateKey)));
    const exchangePublic = exportPublicPem(crypto.createPublicKey(crypto.createPrivateKey(candidate.exchangePrivateKey)));
    return signingPublic === candidate.signingPublicKey && exchangePublic === candidate.exchangePublicKey;
  } catch {
    return false;
  }
}

function fingerprint(publicPem) {
  const der = crypto.createPublicKey(publicPem).export({ type: "spki", format: "der" });
  return crypto.createHash("sha256").update(der).digest("hex").match(/.{1,4}/g).slice(0, 4).join("-").toUpperCase();
}

function createPairingSession() {
  return {
    code: String(crypto.randomInt(100000, 1000000)),
    token: crypto.randomBytes(24).toString("base64url"),
    expiresAt: Date.now() + 5 * 60 * 1000,
  };
}

function timingSafeStringEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function createEphemeralExchange() {
  const pair = crypto.generateKeyPairSync("x25519");
  return {
    privateKey: pair.privateKey,
    publicKey: exportPublicPem(pair.publicKey),
  };
}

function deriveTransferKey(privateKey, remotePublicPem, salt, transferId) {
  const shared = crypto.diffieHellman({
    privateKey: typeof privateKey === "string" ? crypto.createPrivateKey(privateKey) : privateKey,
    publicKey: crypto.createPublicKey(remotePublicPem),
  });
  return Buffer.from(crypto.hkdfSync(
    "sha256",
    shared,
    salt,
    Buffer.from(`DropSync transfer v1\0${transferId}`),
    32,
  ));
}

function createPairingEnvelope(remoteExchangePublicKey, payload) {
  const requestId = crypto.randomUUID();
  const ephemeral = createEphemeralExchange();
  const salt = crypto.randomBytes(32);
  const key = deriveTransferKey(ephemeral.privateKey, remoteExchangePublicKey, salt, `pairing:${requestId}`);
  const sealed = sealWithKey(key, requestId, payload);
  return {
    requestId,
    key,
    envelope: {
      version: PROTOCOL_VERSION,
      requestId,
      ephemeralPublicKey: ephemeral.publicKey,
      salt: salt.toString("base64url"),
      ...sealed,
    },
  };
}

function sealWithKey(key, requestId, payload) {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce, { authTagLength: 16 });
  cipher.setAAD(Buffer.from(`DropSync pairing v1\0${requestId}`));
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(payload), "utf8"), cipher.final()]);
  return {
    nonce: nonce.toString("base64url"),
    ciphertext: ciphertext.toString("base64url"),
    tag: cipher.getAuthTag().toString("base64url"),
  };
}

function openWithKey(key, requestId, sealed) {
  const nonce = Buffer.from(sealed?.nonce || "", "base64url");
  const ciphertext = Buffer.from(sealed?.ciphertext || "", "base64url");
  const tag = Buffer.from(sealed?.tag || "", "base64url");
  if (nonce.length !== 12 || tag.length !== 16 || ciphertext.length > 32 * 1024) throw new Error("Invalid pairing envelope");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, nonce, { authTagLength: 16 });
  decipher.setAAD(Buffer.from(`DropSync pairing v1\0${requestId}`));
  decipher.setAuthTag(tag);
  return JSON.parse(Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8"));
}

function openPairingEnvelope(exchangePrivateKey, envelope) {
  if (envelope?.version !== PROTOCOL_VERSION || typeof envelope.requestId !== "string") throw new Error("Unsupported pairing envelope");
  const salt = Buffer.from(envelope.salt || "", "base64url");
  if (salt.length !== 32) throw new Error("Invalid pairing salt");
  const key = deriveTransferKey(exchangePrivateKey, envelope.ephemeralPublicKey, salt, `pairing:${envelope.requestId}`);
  return { key, payload: openWithKey(key, envelope.requestId, envelope) };
}

function pairingProofPayload(payload) {
  return { code: payload.code, identity: payload.identity, name: payload.name, deviceType: payload.deviceType || "desktop", timestamp: payload.timestamp, ...(payload.port === undefined ? {} : { port: payload.port }) };
}

function sealFileInfo(key, transferId, info) {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(Buffer.from(`DropSync metadata v2\0${transferId}`));
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(info), "utf8"), cipher.final()]);
  return { nonce: nonce.toString("base64url"), ciphertext: ciphertext.toString("base64url"), tag: cipher.getAuthTag().toString("base64url") };
}

function openFileInfo(key, transferId, sealed) {
  const nonce = Buffer.from(sealed?.nonce || "", "base64url"), tag = Buffer.from(sealed?.tag || "", "base64url");
  const ciphertext = Buffer.from(sealed?.ciphertext || "", "base64url");
  if (nonce.length !== 12 || tag.length !== 16 || ciphertext.length > 4096) throw new Error("Invalid private file metadata");
  const cipher = crypto.createDecipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(Buffer.from(`DropSync metadata v2\0${transferId}`)); cipher.setAuthTag(tag);
  return JSON.parse(Buffer.concat([cipher.update(ciphertext), cipher.final()]).toString("utf8"));
}

function transferReceipt(key, { transferId, senderId, recipientId, size, sha256 }) {
  const payload = canonicalJson({ transferId, senderId, recipientId, size, sha256, status: "completed" });
  return crypto.createHmac("sha256", key).update(`DropSync receipt v2\0${payload}`).digest("base64url");
}

function chunkNonce(prefix, counter) {
  if (!Buffer.isBuffer(prefix) || prefix.length !== 8) throw new Error("Invalid nonce prefix");
  const nonce = Buffer.allocUnsafe(12);
  prefix.copy(nonce, 0);
  nonce.writeUInt32BE(counter, 8);
  return nonce;
}

function chunkAad(transferId, counter, plainLength) {
  return Buffer.from(`${transferId}\0${counter}\0${plainLength}`);
}

function encryptChunk(key, noncePrefix, transferId, counter, plain) {
  const cipher = crypto.createCipheriv("aes-256-gcm", key, chunkNonce(noncePrefix, counter), { authTagLength: 16 });
  cipher.setAAD(chunkAad(transferId, counter, plain.length), { plaintextLength: plain.length });
  const ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]);
  const frame = Buffer.allocUnsafe(8 + ciphertext.length + 16);
  frame.writeUInt32BE(counter, 0);
  frame.writeUInt32BE(ciphertext.length, 4);
  ciphertext.copy(frame, 8);
  cipher.getAuthTag().copy(frame, 8 + ciphertext.length);
  return frame;
}

function decryptChunk(key, noncePrefix, transferId, frame) {
  if (!Buffer.isBuffer(frame) || frame.length < 24) throw new Error("Invalid encrypted frame");
  const counter = frame.readUInt32BE(0);
  const length = frame.readUInt32BE(4);
  if (length > CHUNK_SIZE || frame.length !== 8 + length + 16) throw new Error("Invalid encrypted frame length");
  const ciphertext = frame.subarray(8, 8 + length);
  const authTag = frame.subarray(8 + length);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, chunkNonce(noncePrefix, counter), { authTagLength: 16 });
  decipher.setAAD(chunkAad(transferId, counter, length), { plaintextLength: length });
  decipher.setAuthTag(authTag);
  return { counter, plaintext: Buffer.concat([decipher.update(ciphertext), decipher.final()]) };
}

module.exports = {
  CHUNK_SIZE,
  PROTOCOL_VERSION,
  createEphemeralExchange,
  createIdentity,
  createPairingEnvelope,
  createPairingSession,
  decryptChunk,
  deriveTransferKey,
  encryptChunk,
  fingerprint,
  openPairingEnvelope,
  openFileInfo,
  sealFileInfo,
  transferReceipt,
  pairingProofPayload,
  openWithKey,
  publicIdentity,
  sealWithKey,
  signObject,
  timingSafeStringEqual,
  validatePrivateIdentity,
  validatePublicIdentity,
  verifyObject,
};
