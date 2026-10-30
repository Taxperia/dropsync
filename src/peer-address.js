"use strict";

const net = require("node:net");
const dns = require("node:dns/promises");

function isPrivateIpv4(address) {
  if (net.isIP(address) !== 4) return false;
  const [a, b] = address.split(".").map(Number);
  return a === 10 || a === 127 || (a === 169 && b === 254)
    || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)
    || (a === 100 && b >= 64 && b <= 127);
}

async function resolvePeer(value, lookup = dns.lookup) {
  const match = String(value || "").trim().match(/^([a-z0-9.-]{1,253})(?::(\d{1,5}))?$/i);
  if (!match) return null;
  const port = Number(match[2] || 47821);
  if (port < 1 || port > 65535) return null;
  let host = match[1].toLowerCase().replace(/\.$/, "");
  if (net.isIP(host) !== 4) {
    // Only explicit MagicDNS names. Pin the resolved IP for this request.
    if (!/^[a-z0-9-]+(?:\.[a-z0-9-]+)*\.ts\.net$/.test(host)) return null;
    try { host = (await lookup(host, { family: 4 })).address; } catch { return null; }
    const [a, b] = host.split(".").map(Number);
    if (a !== 100 || b < 64 || b > 127) return null;
  }
  return isPrivateIpv4(host) ? { host, port } : null;
}

module.exports = { resolvePeer, isPrivateIpv4 };
