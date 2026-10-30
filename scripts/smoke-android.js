"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const net = require("node:net");
const os = require("node:os");
const { spawn } = require("node:child_process");
const serial = process.env.DROPSYNC_TEST_SERIAL;
assert.match(serial || "", /^emulator-\d+$/, "Set DROPSYNC_TEST_SERIAL to an isolated Android emulator. This smoke test resets only that emulator's DropSync test data.");
const root = path.resolve(__dirname, "..");
const temp = fs.mkdtempSync(path.join(os.tmpdir(), "dropsync-apk-smoke-"));
const sdk = process.env.ANDROID_HOME || process.env.ANDROID_SDK_ROOT || path.join(process.env.LOCALAPPDATA, "Android/Sdk");
const adb = path.join(sdk, "platform-tools", process.platform === "win32" ? "adb.exe" : "adb");
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
function command(args, timeoutMs = 45_000, binary = false) {
  return new Promise((resolve, reject) => {
    const child = spawn(adb, ["-s", serial, ...args], { windowsHide: true });
    const chunks = []; let errors = "";
    const timer = setTimeout(() => { child.kill(); reject(new Error(`ADB timed out: ${args[0]}`)); }, timeoutMs);
    child.stdout.on("data", (chunk) => chunks.push(chunk)); child.stderr.on("data", (chunk) => { errors += chunk; });
    child.once("error", (error) => { clearTimeout(timer); reject(error); });
    child.once("exit", (code) => { clearTimeout(timer); if (code !== 0) reject(new Error(errors || Buffer.concat(chunks).toString())); else resolve(binary ? Buffer.concat(chunks) : Buffer.concat(chunks).toString()); });
  });
}
let server;
async function main() {
  const deadline = Date.now() + 180_000;
  while (true) {
    let booted = false;
    try { booted = (await command(["shell", "getprop", "sys.boot_completed"], 5000)).trim() === "1"; } catch { }
    if (booted) break;
    if (Date.now() > deadline) throw new Error("Emulator did not boot");
    await delay(1000);
  }
  console.log("Isolated emulator booted; installing application and smoke-test APKs.");
  for (const file of ["android/app/build/outputs/apk/debug/app-debug.apk", "android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk"]) {
    assert.match(await command(["install", "-r", path.join(root, file)]), /Success/);
  }
  assert.match(await command(["shell", "pm", "clear", "com.dropsync.app"]), /Success/);
  const port = await new Promise((resolve) => { const listener = net.createServer(); listener.listen(0, "0.0.0.0", () => { const port = listener.address().port; listener.close(() => resolve(port)); }); });
  server = spawn(process.execPath, ["server.js"], { cwd: root, env: { ...process.env, DROPSYNC_PORT: String(port), DROPSYNC_DATA_DIR: temp, DROPSYNC_VAULT_PASSPHRASE: "isolated-android-fixture-passphrase", DROPSYNC_DISCOVERY_PORT: "47948" }, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
  let output = ""; server.stdout.on("data", (chunk) => { output += chunk; }); server.stderr.on("data", (chunk) => { output += chunk; });
  for (let i = 0; i < 100 && !output.includes("DropSync is running"); i++) { assert.equal(server.exitCode, null, output); await delay(100); }
  assert.ok(output.includes("DropSync is running"), output);
  const bootstrap = await fetch(`http://127.0.0.1:${port}/api/bootstrap`).then((response) => response.json());
  const session = await fetch(`http://127.0.0.1:${port}/api/pairing/session`, { method: "POST", headers: { "X-DropSync-CSRF": bootstrap.csrfToken } }).then((response) => response.json());
  let approving = false, approvalCount = 0;
  const approvalTimer = setInterval(async () => {
    if (approving) return; approving = true;
    try {
      const pending = await fetch(`http://127.0.0.1:${port}/api/incoming`).then((response) => response.json());
      for (const item of pending.requests) {
        assert.equal(fs.readdirSync(path.join(temp, "downloads")).some((name) => name.endsWith(".part")), false);
        await fetch(`http://127.0.0.1:${port}/api/incoming/${item.id}`, { method: "POST",
          headers: { "Content-Type": "application/json", "X-DropSync-CSRF": bootstrap.csrfToken }, body: JSON.stringify({ accept: true }) });
        approvalCount++;
      }
    } finally { approving = false; }
  }, 200);
  let result;
  try { result = await command(["shell", "am", "instrument", "-w", "-r", "-e", "address", `10.0.2.2:${port}`, "-e", "code", session.code, "com.dropsync.app.test/com.dropsync.app.ShareSmoke"], 150_000); }
  finally { clearInterval(approvalTimer); }
  console.log(result.trim()); assert.match(result, /INSTRUMENTATION_CODE: -1/);
  assert.equal(approvalCount, 4);
  for (const [name, size] of [["smoke-single.bin",600_003], ["smoke-multi-one.bin",31], ["smoke-multi-two.bin",0], ["smoke-single (1).bin",600_003]]) {
    const expected = Buffer.alloc(size); for (let i = 0; i < size; i++) expected[i] = (i * 31 + 7) & 255;
    assert.deepEqual(fs.readFileSync(path.join(temp, "downloads", name)), expected);
  }
  fs.mkdirSync(path.join(root, "shots"), { recursive: true });
  fs.writeFileSync(path.join(root, "shots/verified-android-apk.png"), await command(["exec-out", "run-as", "com.dropsync.app", "cat", "files/smoke-screen.png"], 15_000, true));
  console.log("APK → Node: cold/warm shares and document-picker result sent 4 files with identical bytes; no broad storage permission was requested.");
}
main().catch((error) => { console.error(error); process.exitCode = 1; }).finally(async () => {
  if (server && server.exitCode === null) { server.kill(); await new Promise((resolve) => server.once("exit", resolve)); }
  assert.equal(path.dirname(temp), path.resolve(os.tmpdir())); assert.ok(path.basename(temp).startsWith("dropsync-apk-smoke-"));
  fs.rmSync(temp, { recursive: true, force: true });
});
