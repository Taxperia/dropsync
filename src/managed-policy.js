"use strict";
const fs = require("node:fs"), path = require("node:path");
const BOOLEAN = ["requireIncomingApproval", "allowExecutableFiles", "clipboardEnabled", "receivingEnabled", "sendingEnabled", "discoveryEnabled", "virusTotalEnabled", "virusTotalBlockUnknown", "virusTotalUploadUnknown"];
const NUMERIC = ["maxIncomingFileBytes", "maxConcurrentIncoming", "uploadLimitKBps", "downloadLimitKBps", "retryAttempts"];
function loadPolicy() {
  if (!process.env.DROPSYNC_POLICY_FILE) return { settings: {}, allowedPeerIds: null };
  const file = path.resolve(process.env.DROPSYNC_POLICY_FILE), value = JSON.parse(fs.readFileSync(file, "utf8"));
  if (!value.settings || typeof value.settings !== "object" || Array.isArray(value.settings)) throw new Error("Invalid managed settings policy");
  const settings = {};
  for (const [key, item] of Object.entries(value.settings)) {
    if (!BOOLEAN.includes(key) && !NUMERIC.includes(key)) throw new Error(`Unsupported managed setting: ${key}`);
    if (BOOLEAN.includes(key) && typeof item !== "boolean") throw new Error(`Invalid managed setting: ${key}`);
    if (NUMERIC.includes(key) && !Number.isSafeInteger(item)) throw new Error(`Invalid managed setting: ${key}`);
    settings[key] = item;
  }
  const ids = value.allowedPeerIds;
  if (ids !== undefined && (!Array.isArray(ids) || ids.length > 500 || ids.some((id) => typeof id !== "string" || !/^[a-f0-9]{32}$/.test(id)))) throw new Error("Invalid managed peer allowlist");
  return { settings, allowedPeerIds: ids ?? null };
}
module.exports = { loadPolicy, BOOLEAN, NUMERIC };
