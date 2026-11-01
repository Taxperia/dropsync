"use strict";
const { spawn } = require("node:child_process");
const path = require("node:path");
const fs = require("node:fs");
const crypto = require("node:crypto");
const { Store } = require("../src/store");
const { createIdentity, publicIdentity } = require("../src/security");
const profile = path.resolve(`.cache/desktop-smoke-profile-${Date.now()}`);
fs.mkdirSync(profile, { recursive: true });
const dataDir = path.join(profile, "data");
const store = new Store(dataDir);
const peer = createIdentity(); store.trustDevice({ ...publicIdentity(peer), name: "Smoke phone" });
const peerFile = path.join(profile, "peer.json"); fs.writeFileSync(peerFile, JSON.stringify(peer));
const fileId = crypto.randomUUID(); const savedPath = path.join(store.settings.downloadDirectory, "smoke-received.txt");
fs.writeFileSync(savedPath, "Verified smoke fixture");
store.addTransfer({ id: fileId, direction: "receive", status: "completed", deviceName: "Smoke phone", fileName: "smoke-received.txt",
  savedPath, size: 22, createdAt: new Date().toISOString() });
const environment = { ...process.env };
delete environment.ELECTRON_RUN_AS_NODE;
function runPhase(reopen) {
  return new Promise((resolve, reject) => {
    const logFile = path.join(profile, "smoke.log");
    const logOffset = fs.existsSync(logFile) ? fs.readFileSync(logFile, "utf8").length : 0;
    const child = spawn(path.resolve("dist/desktop/win-unpacked/DropSync.exe"), ["--smoke-test", ...process.argv.slice(2)], {
      env: { ...environment, DROPSYNC_PORT: "47941", DROPSYNC_DATA_DIR: dataDir, DROPSYNC_DESKTOP_PROFILE: profile, DROPSYNC_DISCOVERY_PORT: "47942", ...(reopen ? { DROPSYNC_SMOKE_REOPEN: "1" } : { DROPSYNC_SMOKE_FILE_ID: fileId, DROPSYNC_SMOKE_PEER_FILE: peerFile }), DROPSYNC_SMOKE_SCREENSHOT: path.resolve("shots/verified-desktop-package.png") },
      windowsHide: true, stdio: ["ignore", "pipe", "pipe"],
    });
    let output = "";
    child.stdout.on("data", (data) => { output += data; });
    child.stderr.on("data", (data) => { output += data; });
    const timer = setTimeout(() => { child.kill(); reject(new Error("Desktop launch timed out: " + output)); }, 60000);
    child.once("error", (error) => { clearTimeout(timer); reject(error); });
    child.once("exit", (code) => {
      clearTimeout(timer);
      const log = fs.existsSync(logFile) ? fs.readFileSync(logFile, "utf8").slice(logOffset) : "No main process log";
      if (code === 0 && (output.includes("DROPSYNC_SMOKE_OK") || log.includes("DROPSYNC_SMOKE_OK"))) resolve();
      else reject(new Error((output || `Desktop exited with ${code}`) + "\n" + log));
    });
  });
}
runPhase(false).then(() => runPhase(true)).then(() => {
  console.log("Packaged desktop smoke passed: first-run setup saves settings; full restart skips setup; file actions, receiver approvals, and sandboxed renderer verified.");
}).catch((error) => { console.error(error); process.exitCode = 1; });
