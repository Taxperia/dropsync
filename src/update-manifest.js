"use strict";
const crypto = require("node:crypto");

function versionParts(version) {
  if (typeof version !== "string" || !/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(version)) throw new Error("Only stable semantic versions are supported");
  const parts = version.split(".").map(Number);
  if (!parts.every((part) => Number.isSafeInteger(part) && part <= 2147483647)) throw new Error("Invalid version");
  return parts;
}
function newer(a, b) {
  const left = versionParts(a), right = versionParts(b);
  for (let i = 0; i < 3; i++) if (left[i] !== right[i]) return left[i] > right[i];
  return false;
}
function releaseBase(config, tag = "latest") {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9-]{0,38}$/.test(config.owner || "") || !/^[a-zA-Z0-9_.-]{1,100}$/.test(config.repo || "") || [".", ".."].includes(config.repo)) throw new Error("GitHub update repository is not configured");
  return `https://github.com/${config.owner}/${config.repo}/releases/${tag === "latest" ? "latest/download" : `download/${tag}`}/`;
}
function verifyManifest(bytes, signature, config, { currentVersion, platform, arch, now = Date.now() }) {
  releaseBase(config);
  if (!Buffer.isBuffer(bytes) || bytes.length > 64 * 1024) throw new Error("Update manifest too large");
  const key = crypto.createPublicKey(config.publicKey);
  if (key.asymmetricKeyType !== "ed25519" || !crypto.verify(null, bytes, key, Buffer.from(signature.trim(), "base64"))) throw new Error("Update signature is invalid");
  const manifest = JSON.parse(bytes.toString("utf8"));
  versionParts(manifest.version);
  if (manifest.schema !== 1 || manifest.tag !== `v${manifest.version}` || !Number.isFinite(manifest.publishedAt) || !Number.isFinite(manifest.expiresAt)
    || manifest.publishedAt > now + 300_000 || manifest.expiresAt <= now || manifest.expiresAt <= manifest.publishedAt
    || manifest.expiresAt - manifest.publishedAt > 31 * 86400_000) throw new Error("Update manifest is invalid or expired");
  if (!newer(manifest.version, currentVersion)) return { available: false, version: currentVersion };
  if (!Array.isArray(manifest.artifacts) || manifest.artifacts.length > 32) throw new Error("Invalid update artifacts");
  const matches = manifest.artifacts.filter((a) => a.platform === platform && a.arch === arch);
  if (matches.length !== 1) throw new Error("This release has no unique package for this platform");
  const artifact = matches[0];
  const arches = { win32: ["x64"], darwin: ["x64", "arm64"], linux: ["x64", "arm64"], android: ["universal"] };
  const suffix = { win32: ".exe", darwin: ".pkg", linux: ".AppImage", android: ".apk" }[platform];
  if (!suffix || !arches[platform]?.includes(arch) || typeof artifact.name !== "string" || !/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,180}$/.test(artifact.name) || !artifact.name.endsWith(suffix)
    || !/^[a-f0-9]{64}$/.test(artifact.sha256) || !Number.isSafeInteger(artifact.size) || artifact.size < 1 || artifact.size > 1024 * 1024 * 1024) throw new Error("Invalid update package");
  return { available: true, version: manifest.version, expiresAt: manifest.expiresAt, artifact,
    url: releaseBase(config, manifest.tag) + artifact.name };
}
module.exports = { verifyManifest, versionParts, newer, releaseBase };
