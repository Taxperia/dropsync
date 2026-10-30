"use strict";
const fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
function dpapi(bytes, decrypt = false) {
  if (process.platform !== "win32") throw new Error("Windows vault is unavailable");
  const binary = path.join(process.env.SystemRoot || "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
  const method = decrypt ? "Unprotect" : "Protect";
  const code = `Add-Type -AssemblyName System.Security; $value=[Convert]::FromBase64String([Console]::In.ReadToEnd().Trim()); $entropy=[Text.Encoding]::UTF8.GetBytes('DropSync vault key v1'); $result=[Security.Cryptography.ProtectedData]::${method}($value,$entropy,[Security.Cryptography.DataProtectionScope]::CurrentUser); [Console]::Out.Write([Convert]::ToBase64String($result))`;
  const env = {}; for (const key of ["SystemRoot", "WINDIR", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP"]) if (process.env[key]) env[key] = process.env[key];
  const result = spawnSync(binary, ["-NoProfile", "-NonInteractive", "-Command", code], { input: bytes.toString("base64"), encoding: "utf8", windowsHide: true, timeout: 15000, maxBuffer: 1024 * 1024, env });
  if (result.status !== 0 || result.error) throw new Error("Windows could not unlock the protected DropSync vault. The existing identity has been preserved.");
  return Buffer.from(result.stdout.trim(), "base64");
}
function unlockWindowsVault(directory) {
  const file = path.join(directory, "vault-key.json"); fs.mkdirSync(directory, { recursive: true, mode: 0o700 }); let key;
  try {
    const box = JSON.parse(fs.readFileSync(file, "utf8"));
    if (box.provider !== "windows-dpapi") throw new Error("This vault must first be unlocked in the desktop edition");
    key = dpapi(Buffer.from(box.data, "base64"), true);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    const vault = require("./local-vault");
    key = fs.existsSync(path.join(directory, "vault-passphrase.json")) ? vault.passphraseKey(directory, process.env.DROPSYNC_VAULT_PASSPHRASE) : crypto.randomBytes(32);
    const data = dpapi(key), descriptor = fs.openSync(file, "wx", 0o600);
    try { fs.writeFileSync(descriptor, JSON.stringify({ version: 1, provider: "windows-dpapi", data: data.toString("base64") })); fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
  }
  if (key.length !== 32) throw new Error("Invalid protected vault key");
  return key;
}
module.exports = { unlockWindowsVault };
