"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { spawn, spawnSync } = require("node:child_process");
const { createIdentity } = require("../src/security");
const { Store } = require("../src/store");
const { TransferManager } = require("../src/transfer-manager");

const root = path.resolve(__dirname, "..");
const sdk = process.env.ANDROID_HOME || process.env.ANDROID_SDK_ROOT || path.join(process.env.LOCALAPPDATA || "", "Android", "Sdk");
const versions = fs.readdirSync(path.join(sdk, "sources")).filter((name) => /^android-\d+$/.test(name)).sort((a,b) => Number(b.slice(8)) - Number(a.slice(8)));
const sourceRoot = path.join(sdk, "sources", versions[0], "org/json");
const bcRoot = path.join(process.env.GRADLE_USER_HOME || path.join(root, ".cache/gradle"), "caches/modules-2/files-2.1/org.bouncycastle/bcprov-jdk18on/1.79");
const bcJar = fs.readdirSync(bcRoot).map((dir) => path.join(bcRoot, dir, "bcprov-jdk18on-1.79.jar")).find((file) => fs.existsSync(file));
assert.ok(bcJar, "Build the Android app first to cache Bouncy Castle.");
const temp = fs.mkdtempSync(path.join(os.tmpdir(), "dropsync-android-transfer-"));
const executable = (name) => process.env.JAVA_HOME ? path.join(process.env.JAVA_HOME, "bin", name + (process.platform === "win32" ? ".exe" : "")) : name;

async function main() {
  const sources = [];
  for (const name of fs.readdirSync(sourceRoot).filter((name) => name.endsWith(".java"))) {
    const source = fs.readFileSync(path.join(sourceRoot, name), "utf8")
      .replace(/^import (?:static )?(?:android\.|libcore\.).*;\r?\n/gm, "")
      .replace(/@(?:UnsupportedAppUsage|SystemApi)(?:\([^)]*\))?/g, "").replace(/@(?:NonNull|Nullable)\b/g, "");
    const file = path.join(temp, name); fs.writeFileSync(file, source); sources.push(file);
  }
  const compiled = spawnSync(executable("javac"), ["-encoding", "UTF-8", "-cp", bcJar, "-d", temp, ...sources,
    path.join(root, "android/app/src/main/java/com/dropsync/app/ProtocolJson.java"),
    path.join(root, "android/app/src/main/java/com/dropsync/app/EncryptedSender.java"), path.join(root, "test/android/TransferInterop.java")], { encoding: "utf8", windowsHide: true });
  assert.equal(compiled.status, 0, compiled.stderr || compiled.error?.message);
  const store = new Store(path.join(temp, "receiver"));
  const sender = createIdentity(); store.trustDevice({ ...sender, name: "Android test phone" });
  const manager = new TransferManager({ store, discovery: {}, logger: { warn() {} } });
  const server = http.createServer((req, res) => req.url === "/peer/transfers/prepare" ? manager.prepareIncoming(req, res) : manager.receive(req, res));
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    for (const [name, size, negative] of [["empty.txt", 0], ["fotoğraf 📱.jpg", 31], ["video.bin", 900_000], ["declined.bin", 20, "decline"], ["bad-hash.bin", 400_000, "hash"], ["bad-signature.bin", 10, "signature"]]) {
      const contents = crypto.randomBytes(size), id = crypto.randomUUID();
      const file = path.join(temp, id + ".bin"); fs.writeFileSync(file, contents);
      const config = { port: server.address().port, id, file, name, size,
        sha256: negative === "hash" ? "0".repeat(64) : crypto.createHash("sha256").update(contents).digest("hex"),
        senderId: sender.deviceId, recipientId: store.identity.deviceId, exchangeKey: store.identity.exchangePublicKey,
        seed: crypto.createPrivateKey(negative === "signature" ? createIdentity().signingPrivateKey : sender.signingPrivateKey).export({ format: "jwk" }).d,
        pauseFirst: name === "video.bin" };
      const fixture = path.join(temp, "fixture.json"); fs.writeFileSync(fixture, JSON.stringify(config));
      let observedApproval = false;
      const approvalTimer = setInterval(() => {
        if (!manager.approvals.list().some((item) => item.id === id)) return;
        assert.equal(fs.existsSync(path.join(store.settings.downloadDirectory, name)), false);
        assert.equal(fs.readdirSync(store.settings.downloadDirectory).some((name) => name.endsWith(".part")), false);
        observedApproval = true;
        manager.approvals.decide(id, negative !== "decline");
      }, 50);
      let result;
      try { result = await new Promise((resolve, reject) => {
        const child = spawn(executable("java"), ["-Dfile.encoding=UTF-8", "-Dstdout.encoding=UTF-8", "-cp", [temp, bcJar].join(path.delimiter), "com.dropsync.app.TransferInterop", fixture], { windowsHide: true });
        let output = "", errors = "";
        const timeout = setTimeout(() => { child.kill(); reject(new Error("Java sender timed out")); }, 30_000);
        child.stdout.on("data", (chunk) => { output += chunk; }); child.stderr.on("data", (chunk) => { errors += chunk; });
        child.on("error", (error) => { clearTimeout(timeout); reject(error); });
        child.on("exit", (code) => { clearTimeout(timeout); try { assert.equal(code, 0, errors); resolve(JSON.parse(output)); } catch (error) { reject(error); } });
      }); } finally { clearInterval(approvalTimer); }
      assert.equal(observedApproval, negative !== "signature");
      if (negative) {
        assert.equal(result.ok, false, `${name} must be rejected`);
        assert.equal(fs.existsSync(path.join(store.settings.downloadDirectory, name)), false);
        assert.equal(fs.readdirSync(store.settings.downloadDirectory).some((name) => name.endsWith(".part")), false);
        if (negative === "hash") assert.equal(manager.list().find((transfer) => transfer.id === id)?.status, "failed");
        console.log(`Java → Node: ${name} rejected without publishing a file.`);
      } else {
        assert.equal(result.ok, true, result.error); assert.equal(result.bytes, size);
        assert.deepEqual(fs.readFileSync(path.join(store.settings.downloadDirectory, name)), contents);
        assert.equal(manager.list().find((transfer) => transfer.id === id)?.status, "completed");
        console.log(`Java → Node: ${name} (${size} bytes), AES-GCM stream and SHA-256 verified.`);
      }
    }
  } finally { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); }
}

main().catch((error) => { console.error(error); process.exitCode = 1; }).finally(() => {
  assert.equal(path.dirname(temp), path.resolve(os.tmpdir())); assert.ok(path.basename(temp).startsWith("dropsync-android-transfer-"));
  fs.rmSync(temp, { recursive: true, force: true });
});
