"use strict";
const path = require("node:path");
const fs = require("node:fs");
const { safeFileName } = require("./utils");

const EXECUTABLE_EXTENSIONS = new Set([".exe", ".com", ".scr", ".msi", ".msp", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".url", ".reg", ".pif", ".gadget", ".cpl", ".chm", ".scf", ".sct", ".sh", ".bash", ".zsh", ".py", ".pyw", ".pl", ".rb", ".desktop", ".appimage", ".app", ".pkg", ".dmg", ".deb", ".rpm", ".jar", ".apk", ".iso", ".img", ".docm", ".xlsm", ".pptm", ".xlam"]);

function enforceIncomingPolicy(name, settings) {
  const fileName = safeFileName(name);
  if (!settings.allowExecutableFiles && EXECUTABLE_EXTENSIONS.has(path.extname(fileName).toLowerCase())) throw new Error("Executable files and installers are blocked. The receiving device can allow them in Security settings.");
  return fileName;
}
function markReceivedFile(filePath) {
  if (process.platform !== "win32") return "not-scanned";
  try { fs.writeFileSync(`${filePath}:Zone.Identifier`, "[ZoneTransfer]\r\nZoneId=3\r\n", { mode: 0o600 }); return "marked-untrusted-not-scanned"; }
  catch { return "not-scanned"; }
}
module.exports = { enforceIncomingPolicy, markReceivedFile, EXECUTABLE_EXTENSIONS };
