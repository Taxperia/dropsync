"use strict";
// Run only on a trusted release machine after reviewing the exact built packages.
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { versionParts, verifyManifest } = require("../src/update-manifest");

async function main() {
  const [input, output] = process.argv.slice(2);
  if (!input || !output || !process.env.DROPSYNC_RELEASE_KEY_FILE) throw new Error("Usage: node scripts/sign-update.js artifacts.json output-directory (DROPSYNC_RELEASE_KEY_FILE points to an external Ed25519 private PEM)");
  const keyPath = path.resolve(process.env.DROPSYNC_RELEASE_KEY_FILE);
  const root = path.resolve(__dirname, "..");
  const relativeKey = path.relative(root, keyPath);
  if (!relativeKey.startsWith(`..${path.sep}`) && relativeKey !== ".." && !path.isAbsolute(relativeKey)) throw new Error("Keep the release private key outside the repository");
  const key = crypto.createPrivateKey(fs.readFileSync(keyPath));
  if (key.asymmetricKeyType !== "ed25519") throw new Error("An Ed25519 release key is required");
  const config = require("../update-config.json");
  const publicKey = crypto.createPublicKey(key).export({ format: "pem", type: "spki" }).toString();
  if (publicKey.trim() !== config.publicKey.trim()) throw new Error("Release key does not match the public key embedded in the clients");
  const specification = JSON.parse(fs.readFileSync(input, "utf8"));
  const version = require("../package.json").version; versionParts(version);
  if (!Array.isArray(specification.artifacts) || !specification.artifacts.length || specification.artifacts.length > 32) throw new Error("Provide 1–32 artifacts");
  const artifacts = [];
  for (const artifact of specification.artifacts) {
    const file = path.resolve(path.dirname(path.resolve(input)), artifact.file);
    const stat = fs.statSync(file);
    if (!stat.isFile() || stat.size < 1 || stat.size > 1024 * 1024 * 1024) throw new Error("Invalid artifact size");
    const hash = crypto.createHash("sha256");
    for await (const chunk of fs.createReadStream(file)) hash.update(chunk);
    artifacts.push({ platform: artifact.platform, arch: artifact.arch, name: path.basename(file), size: stat.size, sha256: hash.digest("hex") });
  }
  const now = Date.now();
  const manifest = { schema: 1, version, tag: `v${version}`, publishedAt: now, expiresAt: now + 30 * 86400_000, artifacts };
  const bytes = Buffer.from(JSON.stringify(manifest, null, 2) + "\n");
  const signature = crypto.sign(null, bytes, key).toString("base64");
  for (const artifact of artifacts) verifyManifest(bytes, signature, config, { currentVersion: "0.0.0", platform: artifact.platform, arch: artifact.arch });
  const directory = path.resolve(output); fs.mkdirSync(directory, { recursive: true });
  // Exclusive creation prevents accidentally replacing an already reviewed manifest.
  fs.writeFileSync(path.join(directory, "dropsync-update.json"), bytes, { flag: "wx", mode: 0o600 });
  fs.writeFileSync(path.join(directory, "dropsync-update.sig"), signature + "\n", { flag: "wx", mode: 0o600 });
  console.log(`Signed update manifest for ${version}; ${artifacts.length} packages. No upload performed.`);
}
main().catch((error) => { console.error(error.message); process.exitCode = 1; });
