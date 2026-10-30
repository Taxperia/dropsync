"use strict";
const crypto = require("node:crypto");
function protect(value, encodedKey) {
  if (!encodedKey) return value;
  const key = Buffer.from(encodedKey, "base64"); if (key.length !== 32) throw new Error("Auth storage key must contain 32 random bytes in base64");
  const nonce = crypto.randomBytes(12), cipher = crypto.createCipheriv("aes-256-gcm", key, nonce); cipher.setAAD(Buffer.from("DropSync Auth storage v1"));
  const data = Buffer.concat([cipher.update(JSON.stringify(value), "utf8"), cipher.final()]);
  return { protected: 1, nonce: nonce.toString("base64"), tag: cipher.getAuthTag().toString("base64"), data: data.toString("base64") };
}
function unlock(value, encodedKey) {
  if (value?.protected !== 1) return value;
  if (!encodedKey) throw new Error("Existing account records are encrypted; supply the original auth storage key");
  const key = Buffer.from(encodedKey, "base64"), nonce = Buffer.from(value.nonce, "base64"), tag = Buffer.from(value.tag, "base64");
  if (key.length !== 32 || nonce.length !== 12 || tag.length !== 16) throw new Error("Invalid protected account record");
  const cipher = crypto.createDecipheriv("aes-256-gcm", key, nonce); cipher.setAAD(Buffer.from("DropSync Auth storage v1")); cipher.setAuthTag(tag);
  return JSON.parse(Buffer.concat([cipher.update(Buffer.from(value.data, "base64")), cipher.final()]).toString("utf8"));
}
module.exports = { protect, unlock };
