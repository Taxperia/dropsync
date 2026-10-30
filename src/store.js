"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { atomicWriteJson, readJson } = require("./utils");
const { createIdentity, fingerprint, validatePrivateIdentity, validatePublicIdentity } = require("./security");
const { loadPolicy } = require("./managed-policy");
const { protection } = require("./local-vault");

function defaultSettings(dataDir) {
  return {
    deviceName: os.hostname().slice(0, 48) || "DropSync Device",
    downloadDirectory: path.join(dataDir, "downloads"),
    maxIncomingFileBytes: 10 * 1024 * 1024 * 1024,
    discoveryEnabled: true,
    requireIncomingApproval: true,
    allowExecutableFiles: false,
    maxConcurrentIncoming: 3,
    receivingEnabled: true,
    sendingEnabled: true,
    clipboardEnabled: false,
    notificationsEnabled: true,
    keepRunningInBackground: true,
    keepAwakeWhileSharing: false,
    uploadLimitKBps: 0,
    downloadLimitKBps: 0,
    retryAttempts: 3,
    virusTotalEnabled: false,
    virusTotalBlockUnknown: true,
    virusTotalUploadUnknown: false,
    profile: { displayName: "", avatar: "" },
    ui: {},
  };
}

function sanitizeProfile(profile) {
  if (profile === undefined) return { displayName: "", avatar: "" };
  if (!profile || typeof profile !== "object" || Array.isArray(profile)) throw new Error("Invalid profile");
  const displayName = String(profile.displayName || "").trim(), avatar = String(profile.avatar || "");
  if (displayName.length > 80 || (avatar && !/^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+/=]{1,160000}$/.test(avatar))) throw new Error("Invalid profile name or avatar");
  return { displayName, avatar };
}

function sanitizeUi(ui) {
  if (!ui || typeof ui !== "object" || Array.isArray(ui)) return {};
  const clean = {};
  for (const [key, value] of Object.entries(ui).slice(0, 256)) {
    if (!/^[a-z0-9-]{1,80}$/.test(key)) continue;
    if (["string", "number", "boolean"].includes(typeof value)) {
      clean[key] = typeof value === "string" ? value.slice(0, 500) : value;
    }
  }
  return clean;
}

class Store {
  constructor(dataDir) {
    this.dataDir = dataDir;
    this.identityPath = path.join(dataDir, "identity.json");
    this.settingsPath = path.join(dataDir, "settings.json");
    this.devicesPath = path.join(dataDir, "trusted-devices.json");
    this.transfersPath = path.join(dataDir, "transfers.json");
    fs.mkdirSync(dataDir, { recursive: true });
    this.identity = this.loadIdentity();
    this.settings = this.loadSettings();
    this.policy = loadPolicy();
    this.updateSettings(this.policy.settings, true);
    this.secretValues = readJson(path.join(dataDir, "secrets.json"), {});
    this.notifications = readJson(path.join(dataDir, "notifications.json"), []);
    if (!Array.isArray(this.notifications)) this.notifications = [];
    this.devices = this.loadDevices();
    const history = readJson(this.transfersPath, []);
    this.transfers = Array.isArray(history) ? history.filter((item) => item && typeof item.id === "string") : [];
    let interrupted = false;
    this.transfers = this.transfers.map((item) => {
      if (!["connecting", "sending", "receiving", "paused", "awaiting-approval", "waiting-for-sender", "awaiting-acceptance", "scanning", "publishing", "retrying"].includes(item.status)) return item;
      interrupted = true;
      if (item.direction === "receive" && typeof item.partialPath === "string" && typeof item.receivingDirectory === "string"
        && path.isAbsolute(item.partialPath) && path.dirname(path.resolve(item.partialPath)) === path.resolve(item.receivingDirectory)
        && path.basename(item.partialPath) === `.dropsync-${this.identity.deviceId}-${item.id}.part`) {
        try { fs.unlinkSync(item.partialPath); } catch (error) { if (error.code !== "ENOENT") item.cleanupError = "The interrupted private partial file could not be removed"; }
      }
      return { ...item, status: "failed", error: "Transfer interrupted by service restart. Select the file to retry.", updatedAt: new Date().toISOString() };
    });
    if (interrupted) atomicWriteJson(this.transfersPath, this.transfers);
    fs.mkdirSync(this.settings.downloadDirectory, { recursive: true });
    fs.mkdirSync(path.join(dataDir, "staging"), { recursive: true });
  }

  loadIdentity() {
    const existing = readJson(this.identityPath, null);
    if (validatePrivateIdentity(existing)) return existing;
    if (fs.existsSync(this.identityPath)) throw new Error("Existing device identity is invalid. Its file was preserved; restore the original protected identity instead of silently replacing it.");
    const identity = createIdentity();
    atomicWriteJson(this.identityPath, identity);
    return identity;
  }

  loadSettings() {
    const defaults = defaultSettings(this.dataDir);
    const raw = readJson(this.settingsPath, {});
    const settings = {
      ...defaults,
      deviceName: typeof raw.deviceName === "string" && raw.deviceName.trim() ? raw.deviceName.trim().slice(0, 48) : defaults.deviceName,
      downloadDirectory: typeof raw.downloadDirectory === "string" && raw.downloadDirectory.trim()
        ? path.resolve(raw.downloadDirectory)
        : defaults.downloadDirectory,
      maxIncomingFileBytes: Number.isSafeInteger(raw.maxIncomingFileBytes)
        ? Math.min(Math.max(raw.maxIncomingFileBytes, 1024), 100 * 1024 * 1024 * 1024)
        : defaults.maxIncomingFileBytes,
      discoveryEnabled: raw.discoveryEnabled !== false,
      requireIncomingApproval: raw.requireIncomingApproval !== false,
      allowExecutableFiles: raw.allowExecutableFiles === true,
      maxConcurrentIncoming: Number.isInteger(raw.maxConcurrentIncoming) ? Math.min(8, Math.max(1, raw.maxConcurrentIncoming)) : 3,
      receivingEnabled: raw.receivingEnabled !== false,
      sendingEnabled: raw.sendingEnabled !== false,
      clipboardEnabled: raw.clipboardEnabled === true,
      notificationsEnabled: raw.notificationsEnabled !== false,
      keepRunningInBackground: raw.keepRunningInBackground !== false,
      keepAwakeWhileSharing: raw.keepAwakeWhileSharing === true,
      uploadLimitKBps: Number.isSafeInteger(raw.uploadLimitKBps) ? Math.max(0, Math.min(1048576, raw.uploadLimitKBps)) : 0,
      downloadLimitKBps: Number.isSafeInteger(raw.downloadLimitKBps) ? Math.max(0, Math.min(1048576, raw.downloadLimitKBps)) : 0,
      retryAttempts: Number.isInteger(raw.retryAttempts) ? Math.max(0, Math.min(5, raw.retryAttempts)) : 3,
      virusTotalEnabled: raw.virusTotalEnabled === true,
      virusTotalBlockUnknown: raw.virusTotalBlockUnknown !== false,
      virusTotalUploadUnknown: raw.virusTotalUploadUnknown === true,
      profile: sanitizeProfile(raw.profile),
      ui: sanitizeUi(raw.ui),
      manualPeers: Array.isArray(raw.manualPeers) ? raw.manualPeers.filter((v) => typeof v === "string").slice(0, 50) : [],
    };
    atomicWriteJson(this.settingsPath, settings);
    return settings;
  }

  updateSettings(patch, managed = false) {
    if (!patch || typeof patch !== "object" || Array.isArray(patch)) throw new Error("Invalid settings patch");
    const next = { ...this.settings };
    if (!managed) for (const [key, value] of Object.entries(this.policy?.settings || {})) if (Object.hasOwn(patch, key) && patch[key] !== value) throw new Error(`This setting is managed by your organization: ${key}`);
    if (Object.hasOwn(patch, "deviceName")) {
      if (typeof patch.deviceName !== "string" || !patch.deviceName.trim()) throw new Error("Device name is required");
      next.deviceName = patch.deviceName.trim().slice(0, 48);
    }
    if (Object.hasOwn(patch, "downloadDirectory")) {
      if (typeof patch.downloadDirectory !== "string" || !patch.downloadDirectory.trim()) throw new Error("Download directory is required");
      next.downloadDirectory = path.resolve(patch.downloadDirectory.trim());
      fs.mkdirSync(next.downloadDirectory, { recursive: true });
    }
    for (const key of ["discoveryEnabled", "requireIncomingApproval", "allowExecutableFiles", "receivingEnabled", "sendingEnabled", "clipboardEnabled", "notificationsEnabled", "keepRunningInBackground", "keepAwakeWhileSharing", "virusTotalEnabled", "virusTotalBlockUnknown", "virusTotalUploadUnknown"]) if (Object.hasOwn(patch, key)) {
      if (typeof patch[key] !== "boolean") throw new Error(`Invalid setting: ${key}`); next[key] = patch[key];
    }
    for (const [key, min, max] of [["uploadLimitKBps", 0, 1048576], ["downloadLimitKBps", 0, 1048576], ["retryAttempts", 0, 5], ["maxConcurrentIncoming", 1, 8], ["maxIncomingFileBytes", 1024, 100 * 1024 ** 3]]) if (Object.hasOwn(patch, key)) {
      if (!Number.isSafeInteger(patch[key]) || patch[key] < min || patch[key] > max) throw new Error(`Invalid setting: ${key}`); next[key] = patch[key];
    }
    if (Object.hasOwn(patch, "profile")) next.profile = sanitizeProfile(patch.profile);
    if (Object.hasOwn(patch, "ui")) next.ui = { ...next.ui, ...sanitizeUi(patch.ui) };
    atomicWriteJson(this.settingsPath, next);
    this.settings = next;
    return next;
  }

  peerAllowed(id) { return !this.policy.allowedPeerIds || this.policy.allowedPeerIds.includes(id); }
  vaultStatus() { return { protected: Boolean(protection(this.dataDir)), provider: protection(this.dataDir) || "Session secrets only" }; }
  getSecret(name) { return this.secretValues[name] || ""; }
  setSecret(name, value) {
    if (!["virusTotalApiKey"].includes(name)) throw new Error("Unsupported secret");
    if (typeof value !== "string" || (value && !/^[a-fA-F0-9]{64}$/.test(value))) throw new Error("Enter a valid VirusTotal API key");
    if (value) this.secretValues[name] = value; else delete this.secretValues[name];
    if (protection(this.dataDir)) atomicWriteJson(path.join(this.dataDir, "secrets.json"), this.secretValues);
    return { configured: Boolean(value), persisted: Boolean(protection(this.dataDir)) };
  }
  notify(item) {
    const record = { ...item, id: require("node:crypto").randomUUID(), createdAt: new Date().toISOString(), read: false };
    this.notifications = [record, ...this.notifications].slice(0, 100); atomicWriteJson(path.join(this.dataDir, "notifications.json"), this.notifications); return record;
  }
  readNotifications() { this.notifications = this.notifications.map((item) => ({ ...item, read: true })); atomicWriteJson(path.join(this.dataDir, "notifications.json"), this.notifications); }

  loadDevices() {
    const raw = readJson(this.devicesPath, []);
    return Array.isArray(raw) ? raw.filter((item) => validatePublicIdentity(item) && typeof item.name === "string") : [];
  }

  trustDevice(device) {
    if (!validatePublicIdentity(device)) throw new Error("Invalid peer identity");
    const record = {
      version: device.version,
      deviceId: device.deviceId,
      name: String(device.name || "DropSync Device").slice(0, 48),
      deviceType: ["phone", "desktop", "browser", "tv"].includes(device.deviceType) ? device.deviceType : undefined,
      signingPublicKey: device.signingPublicKey,
      exchangePublicKey: device.exchangePublicKey,
      fingerprint: fingerprint(device.signingPublicKey),
      pairedAt: new Date().toISOString(),
      address: device.address || null,
      port: device.port || null,
    };
    this.devices = [record, ...this.devices.filter((item) => item.deviceId !== record.deviceId)].slice(0, 200);
    atomicWriteJson(this.devicesPath, this.devices);
    return record;
  }

  getTrustedDevice(deviceId) {
    return this.devices.find((item) => item.deviceId === deviceId) || null;
  }

  rememberDeviceType(deviceId, deviceType) {
    const device = this.getTrustedDevice(deviceId);
    if (!device || device.deviceType === deviceType || !["phone", "desktop", "browser", "tv"].includes(deviceType)) return;
    device.deviceType = deviceType;
    atomicWriteJson(this.devicesPath, this.devices);
  }

  rememberPeer(address) {
    this.settings.manualPeers = [...new Set([address, ...(this.settings.manualPeers || [])])].slice(0, 50);
    atomicWriteJson(this.settingsPath, this.settings);
  }

  removeTrustedDevice(deviceId) {
    const before = this.devices.length;
    this.devices = this.devices.filter((item) => item.deviceId !== deviceId);
    if (this.devices.length !== before) atomicWriteJson(this.devicesPath, this.devices);
    return this.devices.length !== before;
  }

  addTransfer(record) {
    this.transfers = [record, ...this.transfers.filter((item) => item.id !== record.id)].slice(0, 500);
    atomicWriteJson(this.transfersPath, this.transfers);
  }

  updateTransfer(id, patch) {
    const index = this.transfers.findIndex((item) => item.id === id);
    if (index === -1) return;
    this.transfers[index] = { ...this.transfers[index], ...patch, updatedAt: new Date().toISOString() };
    atomicWriteJson(this.transfersPath, this.transfers);
  }

  clearTransfers(status) {
    const before = this.transfers.length;
    this.transfers = this.transfers.filter((item) => item.status !== status);
    if (this.transfers.length !== before) atomicWriteJson(this.transfersPath, this.transfers);
    return before - this.transfers.length;
  }
}

module.exports = { Store, defaultSettings, sanitizeUi };
