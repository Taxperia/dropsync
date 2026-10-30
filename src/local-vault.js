"use strict";
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const vaults = new Map();
const protectedNames = new Set(["identity.json", "settings.json", "trusted-devices.json", "transfers.json", "staged-files.json", "secrets.json", "notifications.json", "diagnostics.json"]);
function register(directory, key, provider = "OS vault") {
  if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error("Invalid local vault key");
  vaults.set(path.resolve(directory), { key: Buffer.from(key), provider });
}
function protection(directory) { return vaults.get(path.resolve(directory))?.provider || null; }
function seal(key, value, context) {
  const nonce = crypto.randomBytes(12), cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(Buffer.from(context)); const data = Buffer.concat([cipher.update(JSON.stringify(value), "utf8"), cipher.final()]);
  return { dropsyncSealed: 1, nonce: nonce.toString("base64"), tag: cipher.getAuthTag().toString("base64"), data: data.toString("base64") };
}
function open(key, value, context) {
  if (value?.dropsyncSealed !== 1) throw new Error("Unsupported protected record");
  const nonce = Buffer.from(value.nonce || "", "base64"), tag = Buffer.from(value.tag || "", "base64");
  if (nonce.length !== 12 || tag.length !== 16) throw new Error("Invalid protected record");
  const cipher = crypto.createDecipheriv("aes-256-gcm", key, nonce); cipher.setAAD(Buffer.from(context)); cipher.setAuthTag(tag);
  return JSON.parse(Buffer.concat([cipher.update(Buffer.from(value.data, "base64")), cipher.final()]).toString("utf8"));
}
function encode(file, value) {
  const vault = vaults.get(path.dirname(path.resolve(file)));
  return vault && protectedNames.has(path.basename(file)) ? seal(vault.key, value, path.basename(file)) : value;
}
function decode(file, value) {
  if (value?.dropsyncSealed !== 1) return value;
  const vault = vaults.get(path.dirname(path.resolve(file)));
  if (!vault) throw new Error("This data is encrypted. Open the desktop app or unlock the service with DROPSYNC_VAULT_PASSPHRASE.");
  return open(vault.key, value, path.basename(file));
}
function passphraseKey(directory, passphrase) {
  if (typeof passphrase !== "string" || passphrase.length < 12) throw new Error("Use a vault passphrase of at least 12 characters");
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const file = path.join(directory, "vault-passphrase.json"); let box;
  try { box = JSON.parse(fs.readFileSync(file, "utf8")); } catch (error) { if (error.code !== "ENOENT") throw error; }
  const salt = box ? Buffer.from(box.salt, "base64") : crypto.randomBytes(32);
  if (salt.length !== 32) throw new Error("Invalid vault salt");
  const wrapping = crypto.scryptSync(passphrase, salt, 32, { N: 131072, r: 8, p: 1, maxmem: 256 * 1024 * 1024 });
  const key = box ? Buffer.from(open(wrapping, box.key, "DropSync local vault"), "base64") : crypto.randomBytes(32);
  if (!box) { fs.writeFileSync(file, JSON.stringify({ version: 1, salt: salt.toString("base64"), key: seal(wrapping, key.toString("base64"), "DropSync local vault") }), { mode: 0o600, flag: "wx" }); }
  wrapping.fill(0); if (key.length !== 32) throw new Error("Invalid vault key"); return key;
}
function migrate(directory) {
  const { atomicWriteJson, readJson } = require("./utils");
  for (const name of protectedNames) { const file = path.join(directory, name); if (fs.existsSync(file)) atomicWriteJson(file, readJson(file, null)); }
}
module.exports = { register, protection, encode, decode, passphraseKey, migrate };
