"use strict";
const fs = require("node:fs");
const path = require("node:path");

function volumeStats(directory) {
  try {
    const s = fs.statfsSync(directory);
    const total = Number(s.blocks) * Number(s.bsize);
    const free = Number(s.bavail) * Number(s.bsize);
    return total ? { directory, total, free, used: Math.max(0, total - free) } : null;
  } catch { return null; }
}

function listVolumes(downloadDirectory) {
  const roots = process.platform === "win32"
    ? Array.from({ length: 26 }, (_, i) => `${String.fromCharCode(65 + i)}:\\`)
    : ["/", ...["/Volumes", "/media", "/mnt"].flatMap((root) => {
      try { return fs.readdirSync(root, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => path.join(root, e.name)); }
      catch { return []; }
    })];
  return roots.map(volumeStats).filter(Boolean).map((v) => ({ ...v, downloads: path.resolve(downloadDirectory).startsWith(v.directory) }));
}
module.exports = { volumeStats, listVolumes };
