"use strict";

const crypto = require("node:crypto");
const dgram = require("node:dgram");
const os = require("node:os");
const { publicIdentity, signObject, validatePublicIdentity, verifyObject } = require("./security");
const { isPrivateIpv4 } = require("./peer-address");

const MULTICAST_ADDRESS = process.env.DROPSYNC_MULTICAST || "239.255.42.99";
const DISCOVERY_PORT = Number(process.env.DROPSYNC_DISCOVERY_PORT || 45555);
const ANNOUNCE_INTERVAL_MS = 4000;
const DEVICE_TTL_MS = 15000;

function ipv4Number(value) {
  const parts = String(value).split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
  return parts.reduce((result, part) => ((result << 8) | part) >>> 0, 0);
}

function numberToIpv4(value) {
  return [24, 16, 8, 0].map((shift) => (value >>> shift) & 255).join(".");
}

function subnetBroadcast(address, netmask) {
  const ip = ipv4Number(address);
  const mask = ipv4Number(netmask);
  if (ip === null || mask === null || mask === 0xffffffff) return null;
  return numberToIpv4((ip | (~mask >>> 0)) >>> 0);
}

function activeIpv4Interfaces() {
  const result = [];
  for (const [name, entries] of Object.entries(os.networkInterfaces())) {
    for (const entry of entries || []) {
      if (entry.family !== "IPv4" || entry.internal) continue;
      result.push({ name, address: entry.address, netmask: entry.netmask, broadcast: subnetBroadcast(entry.address, entry.netmask) });
    }
  }
  return [...new Map(result.map((entry) => [entry.address, entry])).values()];
}

class DiscoveryService {
  constructor({ identity, getName, getPort, getDeviceType = () => "desktop", isTrusted, getTrustedIdentity = () => null, onChange, logger = console }) {
    this.identity = identity;
    this.getName = getName;
    this.getPort = getPort;
    this.getDeviceType = getDeviceType;
    this.isTrusted = isTrusted;
    this.getTrustedIdentity = getTrustedIdentity;
    this.onChange = onChange;
    this.logger = logger;
    this.socket = null;
    this.devices = new Map();
    this.timer = null;
    this.cleanupTimer = null;
    this.interfaces = [];
    this.joinedAddresses = new Set();
    this.lastAnnouncedAt = null;
    this.lastReceivedAt = null;
    this.receivedCount = 0;
    this.lastError = null;
  }

  warn(message) {
    this.lastError = message;
    this.logger.warn(message);
  }

  refreshInterfaces() {
    this.interfaces = activeIpv4Interfaces();
    if (!this.socket) return;
    for (const entry of this.interfaces) {
      if (this.joinedAddresses.has(entry.address)) continue;
      try {
        this.socket.addMembership(MULTICAST_ADDRESS, entry.address);
        this.joinedAddresses.add(entry.address);
      } catch (error) {
        this.warn(`Discovery could not join ${entry.name} (${entry.address}): ${error.message}`);
      }
    }
    if (!this.interfaces.length && !this.joinedAddresses.has("default")) {
      try {
        this.socket.addMembership(MULTICAST_ADDRESS);
        this.joinedAddresses.add("default");
      } catch (error) {
        this.warn(`Discovery multicast unavailable: ${error.message}`);
      }
    }
  }

  start() {
    if (this.socket) return;
    const socket = dgram.createSocket({ type: "udp4", reuseAddr: true });
    this.socket = socket;
    socket.on("error", (error) => this.warn(`Discovery error: ${error.message}`));
    socket.on("message", (message, remote) => this.handleMessage(message, remote));
    socket.bind(DISCOVERY_PORT, () => {
      try {
        socket.setMulticastTTL(1);
        socket.setMulticastLoopback(true);
        socket.setBroadcast(true);
        this.refreshInterfaces();
        this.announce();
      } catch (error) {
        this.warn(`Discovery multicast unavailable: ${error.message}`);
      }
    });
    this.timer = setInterval(() => this.announce(), ANNOUNCE_INTERVAL_MS);
    this.cleanupTimer = setInterval(() => this.cleanup(), 5000);
    this.timer.unref?.();
    this.cleanupTimer.unref?.();
  }

  stop() {
    clearInterval(this.timer);
    clearInterval(this.cleanupTimer);
    this.timer = null;
    this.cleanupTimer = null;
    if (this.socket) {
      try { this.socket.close(); } catch { /* already closed */ }
      this.socket = null;
    }
    this.interfaces = [];
    this.joinedAddresses.clear();
    if (this.devices.size) {
      this.devices.clear();
      this.onChange?.([]);
    }
  }

  createAnnouncement() {
    const data = {
      ...publicIdentity(this.identity),
      name: this.getName(),
      deviceType: this.getDeviceType(),
      port: this.getPort(),
      capabilities: { pairing: true, transferSend: true, transferReceive: true },
      timestamp: Date.now(),
      nonce: crypto.randomBytes(12).toString("base64url"),
    };
    return {
      type: "dropsync-announce",
      data,
      signature: signObject(data, this.identity.signingPrivateKey),
    };
  }

  announce() {
    if (!this.socket) return;
    this.refreshInterfaces();
    const packet = Buffer.from(JSON.stringify(this.createAnnouncement()));
    if (packet.length > 8192) return;
    const targets = new Set();
    let multicastSent = false;
    for (const entry of this.interfaces) {
      try {
        this.socket.setMulticastInterface(entry.address);
        this.socket.send(packet, DISCOVERY_PORT, MULTICAST_ADDRESS, (error) => {
          if (error) this.warn(`Discovery announce failed on ${entry.name}: ${error.message}`);
        });
        multicastSent = true;
      } catch (error) {
        this.warn(`Discovery could not announce on ${entry.name}: ${error.message}`);
      }
      if (entry.broadcast) targets.add(entry.broadcast);
    }
    if (!multicastSent) targets.add(MULTICAST_ADDRESS);
    for (const address of targets) {
      this.socket.send(packet, DISCOVERY_PORT, address, (error) => {
        if (error) this.warn(`Discovery announce failed for ${address}: ${error.message}`);
      });
    }
    this.lastAnnouncedAt = Date.now();
  }

  handleMessage(message, remote) {
    if (!isPrivateIpv4(remote.address)) return;
    if (message.length > 8192) return;
    let packet;
    try { packet = JSON.parse(message.toString("utf8")); } catch { return; }
    if (packet?.type !== "dropsync-announce" || !packet.data || typeof packet.signature !== "string") return;
    const data = packet.data;
    if (data.deviceId === this.identity.deviceId) return;
    if (!validatePublicIdentity(data)) return;
    if (!Number.isInteger(data.port) || data.port < 1 || data.port > 65535) return;
    if (typeof data.name !== "string" || !data.name.trim() || data.name.length > 48) return;
    if (!Number.isFinite(data.timestamp) || Math.abs(Date.now() - data.timestamp) > 2 * 60 * 1000) return;
    if (!verifyObject(data, packet.signature, data.signingPublicKey)) return;
    const pinned = this.getTrustedIdentity(data.deviceId);
    if (pinned && (pinned.signingPublicKey !== data.signingPublicKey || pinned.exchangePublicKey !== data.exchangePublicKey)) return;
    if (!this.devices.has(data.deviceId) && this.devices.size >= 256) {
      const untrusted = [...this.devices.keys()].find((id) => !this.isTrusted(id));
      if (!pinned || !untrusted) return;
      this.devices.delete(untrusted);
    }
    this.receivedCount += 1;
    this.lastReceivedAt = Date.now();

    const previous = this.devices.get(data.deviceId);
    const next = {
      deviceId: data.deviceId,
      name: data.name,
      deviceType: ["phone", "desktop", "browser", "tv"].includes(data.deviceType) ? data.deviceType : data.capabilities?.transferReceive === false ? "phone" : "desktop",
      address: remote.address,
      port: data.port,
      signingPublicKey: data.signingPublicKey,
      exchangePublicKey: data.exchangePublicKey,
      capabilities: data.capabilities && typeof data.capabilities === "object" ? data.capabilities : { pairing: true, transferSend: true, transferReceive: true },
      trusted: this.isTrusted(data.deviceId),
      lastSeen: Date.now(),
      online: true,
    };
    this.devices.set(data.deviceId, next);
    if (!previous || previous.address !== next.address || previous.port !== next.port || previous.name !== next.name || previous.trusted !== next.trusted || previous.deviceType !== next.deviceType) {
      this.onChange?.(this.list());
    }
    return next;
  }

  cleanup() {
    let changed = false;
    const now = Date.now();
    for (const [id, device] of this.devices) {
      if (now - device.lastSeen > DEVICE_TTL_MS) {
        this.devices.delete(id);
        changed = true;
      }
    }
    if (changed) this.onChange?.(this.list());
  }

  markTrust(deviceId) {
    const device = this.devices.get(deviceId);
    if (device) {
      device.trusted = this.isTrusted(deviceId);
      this.onChange?.(this.list());
    }
  }

  get(deviceId) {
    return this.devices.get(deviceId) || null;
  }

  list() {
    return [...this.devices.values()]
      .map((device) => ({ ...device }))
      .sort((a, b) => Number(b.trusted) - Number(a.trusted) || a.name.localeCompare(b.name));
  }

  status() {
    return {
      port: DISCOVERY_PORT,
      multicastAddress: MULTICAST_ADDRESS,
      interfaces: this.interfaces.map(({ name, address, broadcast }) => ({ name, address, broadcast })),
      lastAnnouncedAt: this.lastAnnouncedAt,
      lastReceivedAt: this.lastReceivedAt,
      receivedCount: this.receivedCount,
      lastError: this.lastError,
    };
  }
}

module.exports = { DiscoveryService, DISCOVERY_PORT, MULTICAST_ADDRESS, activeIpv4Interfaces, subnetBroadcast };
