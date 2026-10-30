"use strict";
const fs = require("node:fs");
function imageInfo(bytes) {
  if (bytes.length >= 24 && bytes.subarray(0, 8).equals(Buffer.from([137,80,78,71,13,10,26,10]))) return { type: "image/png", width: bytes.readUInt32BE(16), height: bytes.readUInt32BE(20) };
  if (bytes.length >= 4 && bytes[0] === 255 && bytes[1] === 216) {
    let offset = 2;
    while (offset + 4 < bytes.length) {
      if (bytes[offset] !== 255) return null;
      while (bytes[offset] === 255) offset++;
      const marker = bytes[offset++]; if (marker === 0xda || marker === 0xd9) return null;
      if (marker === 1 || (marker >= 0xd0 && marker <= 0xd7)) continue;
      if (offset + 2 > bytes.length) return null; const length = bytes.readUInt16BE(offset);
      if (length < 2 || offset + length > bytes.length) return null;
      if ([0xc0,0xc1,0xc2,0xc3,0xc5,0xc6,0xc7,0xc9,0xca,0xcb,0xcd,0xce,0xcf].includes(marker) && length >= 7) return { type: "image/jpeg", width: bytes.readUInt16BE(offset + 5), height: bytes.readUInt16BE(offset + 3) };
      offset += length;
    }
  }
  if (bytes.length >= 30 && bytes.toString("ascii", 0, 4) === "RIFF" && bytes.toString("ascii", 8, 12) === "WEBP") {
    const format = bytes.toString("ascii", 12, 16);
    if (format === "VP8X") return { type: "image/webp", width: bytes.readUIntLE(24, 3) + 1, height: bytes.readUIntLE(27, 3) + 1 };
    if (format === "VP8 " && bytes.subarray(23,26).equals(Buffer.from([0x9d,1,0x2a]))) return { type: "image/webp", width: bytes.readUInt16LE(26) & 0x3fff, height: bytes.readUInt16LE(28) & 0x3fff };
    if (format === "VP8L" && bytes[20] === 0x2f) { const bits = bytes.readUInt32LE(21); return { type: "image/webp", width: (bits & 0x3fff) + 1, height: ((bits >>> 14) & 0x3fff) + 1 }; }
  }
  return null;
}
async function previewInfo(file) {
  const handle = await fs.promises.open(file, "r");
  try {
    const stat = await handle.stat(); if (stat.size > 20 * 1024 * 1024) throw new Error("Image exceeds preview size limit");
    const prefix = Buffer.alloc(Math.min(stat.size, 512 * 1024)); await handle.read(prefix, 0, prefix.length, 0);
    const info = imageInfo(prefix);
    if (!info || !info.width || !info.height || info.width * info.height > 16000000 || info.width > 32000 || info.height > 32000) throw new Error("No bounded raster preview is available");
    return { ...info, size: stat.size };
  } finally { await handle.close(); }
}
module.exports = { imageInfo, previewInfo };
