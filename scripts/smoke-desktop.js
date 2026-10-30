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
const child = spawn(path.resolve("dist/desktop/win-unpacked/DropSync.exe"), ["--smoke-test", ...process.argv.slice(2)], {
  env: { ...environment, DROPSYNC_PORT: "47941", DROPSYNC_DATA_DIR: dataDir, DROPSYNC_DESKTOP_PROFILE: profile, DROPSYNC_DISCOVERY_PORT: "47942", DROPSYNC_SMOKE_FILE_ID: fileId, DROPSYNC_SMOKE_PEER_FILE: peerFile, DROPSYNC_SMOKE_SCREENSHOT: path.resolve("shots/verified-desktop-package.png") },
  windowsHide: true, stdio: ["ignore", "pipe", "pipe"],
});
let output = "";
child.stdout.on("data", (data) => { output += data; });
child.stderr.on("data", (data) => { output += data; });
const log = () => { try { return fs.readFileSync(path.join(profile, "smoke.log"), "utf8"); } catch { return "No main process log"; } };
const timer = setTimeout(() => { console.error("Desktop launch timed out.", output, log()); child.kill(); process.exitCode = 1; }, 60000);
child.once("error", (error) => { clearTimeout(timer); console.error(error); process.exitCode = 1; });
child.once("exit", (code) => {
  clearTimeout(timer);
  if (code === 0 && (output.includes("DROPSYNC_SMOKE_OK") || log().includes("DROPSYNC_SMOKE_OK"))) console.log("Packaged desktop smoke passed: landing -> login -> explicit local entry -> dashboard; connected service and sandboxed renderer.");
  else { console.error(output || `Desktop exited with ${code}`, log()); process.exitCode = 1; }
});
