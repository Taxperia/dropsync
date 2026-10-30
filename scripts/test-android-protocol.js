"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { canonicalJson } = require("../src/utils");
const { createIdentity, publicIdentity, signObject, verifyObject } = require("../src/security");
const { DiscoveryService } = require("../src/discovery");

const root = path.resolve(__dirname, "..");
const sdk = process.env.ANDROID_HOME || process.env.ANDROID_SDK_ROOT
  || path.join(process.env.LOCALAPPDATA || "", "Android", "Sdk");
const sourceRoot = path.join(sdk, "sources");
const versions = fs.existsSync(sourceRoot) ? fs.readdirSync(sourceRoot).filter((name) => /^android-\d+$/.test(name))
  .sort((a, b) => Number(b.slice(8)) - Number(a.slice(8))) : [];
if (!versions.length) throw new Error("Install an Android SDK Sources package; this test uses Android's real org.json, not a mock.");
const jsonSource = path.join(sourceRoot, versions[0], "org", "json");
const temp = fs.mkdtempSync(path.join(os.tmpdir(), "dropsync-android-protocol-"));

function run(command, args) {
  const executable = process.env.JAVA_HOME ? path.join(process.env.JAVA_HOME, "bin", command + (process.platform === "win32" ? ".exe" : "")) : command;
  const result = spawnSync(executable, args, { encoding: "utf8", windowsHide: true });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return result.stdout;
}

try {
  const sources = [];
  for (const name of fs.readdirSync(jsonSource).filter((name) => name.endsWith(".java"))) {
    // Remove Android-only metadata annotations from temporary copies; keep the JSON
    // parser/stringifier implementations intact, including the slash-escaping bug.
    const source = fs.readFileSync(path.join(jsonSource, name), "utf8")
      .replace(/^import (?:static )?(?:android\.|libcore\.).*;\r?\n/gm, "")
      .replace(/@(?:UnsupportedAppUsage|SystemApi)(?:\([^)]*\))?/g, "")
      .replace(/@(?:NonNull|Nullable)\b/g, "");
    const target = path.join(temp, name);
    fs.writeFileSync(target, source);
    sources.push(target);
  }
  run("javac", ["-encoding", "UTF-8", "-d", temp, ...sources,
    path.join(root, "android/app/src/main/java/com/dropsync/app/ProtocolJson.java"),
    path.join(root, "test/android/ProtocolInterop.java")]);

  let peer;
  do { peer = createIdentity(); } while (!peer.signingPublicKey.includes("/") || !peer.exchangePublicKey.includes("/"));
  const data = { ...publicIdentity(peer), name: "Telefon / Türkçe 📱", port: 47821,
    capabilities: { transferReceive: false, pairing: true, transferSend: false }, timestamp: Date.now(), nonce: "interop/fixture" };
  const values = [data, { "z/key": [true, false, null, 47821], a: { b: "slash/ and backslash\\/" } },
    '"\\\b\f\n\r\t\u0000\u001f', "Türkçe 📱 \u2028 \u2029", "\ud800 / \udfff", ""];
  const fixture = path.join(temp, "fixture.json");
  fs.writeFileSync(fixture, JSON.stringify({ data, privateKey: peer.signingPrivateKey,
    nodeSignature: signObject(data, peer.signingPrivateKey), cases: values.map((value) => ({ value, expected: canonicalJson(value) })) }));
  const packet = JSON.parse(run("java", ["-Dfile.encoding=UTF-8", "-Dstdout.encoding=UTF-8", "-cp", temp, "com.dropsync.app.ProtocolInterop", fixture]));
  assert.deepEqual(packet.data, data);
  assert.equal(verifyObject(packet.data, packet.signature, packet.data.signingPublicKey), true);
  const discovery = new DiscoveryService({ identity: createIdentity(), getName: () => "PC", getPort: () => 47821,
    isTrusted: () => false, onChange() {}, logger: { warn() {} } });
  const accepted = discovery.handleMessage(Buffer.from(JSON.stringify(packet)), { address: "192.168.1.50" });
  assert.equal(accepted?.deviceId, peer.deviceId);
  assert.equal(accepted.capabilities.transferReceive, false);
  packet.data.name = "Tampered";
  assert.equal(discovery.handleMessage(Buffer.from(JSON.stringify(packet)), { address: "192.168.1.51" }), undefined);
  console.log(`Android/Node canonical bytes match (${values.length} cases); signatures verify both ways, discovery accepts Java packets and rejects tampering.`);
} finally {
  assert.equal(path.dirname(temp), path.resolve(os.tmpdir()));
  assert.ok(path.basename(temp).startsWith("dropsync-android-protocol-"));
  fs.rmSync(temp, { recursive: true, force: true });
}
