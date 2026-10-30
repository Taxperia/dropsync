"use strict";

const fs = require("node:fs");
const path = require("node:path");
const vault = require("./local-vault");

function atomicWriteJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const tempPath = `${filePath}.${require("node:crypto").randomUUID()}.tmp`;
  fs.writeFileSync(tempPath, `${JSON.stringify(vault.encode(filePath, value), null, 2)}\n`, { mode: 0o600, flag: "wx" });
  fs.renameSync(tempPath, filePath);
}

function readJson(filePath, fallback) {
  try {
    return vault.decode(filePath, JSON.parse(fs.readFileSync(filePath, "utf8")));
  } catch (error) {
    if (error.code === "ENOENT") return fallback;
    throw error;
  }
}

function safeFileName(input) {
  const base = path.basename(String(input || "file"))
    .replace(/[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069<>:"/\\|?*]/g, "_")
    .replace(/[. ]+$/g, "")
    .slice(0, 180);
  if (!base || base === "." || base === "..") return "file";
  return /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(base) ? `_${base}` : base;
}

function uniquePath(directory, fileName) {
  const safe = safeFileName(fileName);
  const parsed = path.parse(safe);
  let candidate = path.join(directory, safe);
  let index = 1;
  while (fs.existsSync(candidate) || fs.existsSync(`${candidate}.part`)) {
    candidate = path.join(directory, `${parsed.name} (${index})${parsed.ext}`);
    index += 1;
  }
  return candidate;
}

function jsonResponse(res, status, payload) {
  const body = Buffer.from(JSON.stringify(payload));
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": body.length,
    "Cache-Control": "no-store",
  });
  res.end(body);
}

async function readJsonBody(req, maxBytes = 256 * 1024) {
  const deadline = setTimeout(() => req.destroy(new Error("Request body timed out")), 30_000);
  deadline.unref?.();
  try {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBytes) {
      const error = new Error("Request body is too large");
      error.statusCode = 413;
      throw error;
    }
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    const error = new Error("Invalid JSON body");
    error.statusCode = 400;
    throw error;
  }
  } finally { clearTimeout(deadline); }
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

module.exports = {
  atomicWriteJson,
  canonicalJson,
  jsonResponse,
  readJson,
  readJsonBody,
  safeFileName,
  sleep,
  uniquePath,
};
