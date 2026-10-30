"use strict";
const crypto = require("node:crypto"), fs = require("node:fs"), path = require("node:path");
const vault = require("../src/local-vault");
async function unlockDesktopVault(directory, safeStorage) {
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  if (process.platform === "win32") {
    const key = require("../src/windows-vault").unlockWindowsVault(directory);
    vault.register(directory, key, "Windows DPAPI"); return { key, provider: "Windows DPAPI" };
  }
  const available = typeof safeStorage.isAsyncEncryptionAvailable === "function" ? await safeStorage.isAsyncEncryptionAvailable() : safeStorage.isEncryptionAvailable();
  const weak = process.platform === "linux" && ["basic_text", "unknown"].includes(safeStorage.getSelectedStorageBackend());
  if (!available || weak) {
    const key = vault.passphraseKey(directory, process.env.DROPSYNC_VAULT_PASSPHRASE);
    vault.register(directory, key, "Passphrase vault"); return { key, provider: "Passphrase vault" };
  }
  const file = path.join(directory, "vault-key.json"); let key;
  try {
    const box = JSON.parse(fs.readFileSync(file, "utf8"));
    const decrypted = typeof safeStorage.decryptStringAsync === "function" ? (await safeStorage.decryptStringAsync(Buffer.from(box.data, "base64"))).result : safeStorage.decryptString(Buffer.from(box.data, "base64"));
    key = Buffer.from(decrypted, "base64");
    if (key.length !== 32) throw new Error("Invalid protected vault key");
  } catch (error) {
    if (error.code !== "ENOENT") throw new Error("The existing device vault could not be unlocked. Its identity was preserved; no replacement was generated.");
    key = fs.existsSync(path.join(directory, "vault-passphrase.json")) ? vault.passphraseKey(directory, process.env.DROPSYNC_VAULT_PASSPHRASE) : crypto.randomBytes(32);
    const encrypted = typeof safeStorage.encryptStringAsync === "function" ? await safeStorage.encryptStringAsync(key.toString("base64")) : safeStorage.encryptString(key.toString("base64"));
    fs.writeFileSync(file, JSON.stringify({ version: 1, data: encrypted.toString("base64") }), { flag: "wx", mode: 0o600 });
  }
  vault.register(directory, key, "OS vault"); return { key, provider: "OS vault" };
}
module.exports = { unlockDesktopVault };
