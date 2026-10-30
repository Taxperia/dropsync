"use strict";
const https = require("node:https");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { pipeline } = require("node:stream/promises");
const { Transform } = require("node:stream");
const { spawn } = require("node:child_process");
const { verifyManifest, releaseBase } = require("../src/update-manifest");

// No renderer-supplied URL, package path, arguments or public key is accepted.
const CDN = new Set(["github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"]);
function response(url, redirects = 0) {
  return new Promise((resolve, reject) => {
    const target = new URL(url);
    if (target.protocol !== "https:" || !CDN.has(target.hostname) || target.username || target.password || (target.port && target.port !== "443")) return reject(new Error("Untrusted update URL"));
    const request = https.get(target, { headers: { "User-Agent": "DropSync-Updater", "Accept-Encoding": "identity" }, timeout: 20_000 }, (res) => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode)) {
        res.resume();
        if (redirects >= 4 || !res.headers.location) return reject(new Error("Too many update redirects"));
        return response(new URL(res.headers.location, target).href, redirects + 1).then(resolve, reject);
      }
      if (res.statusCode !== 200 || (res.headers["content-encoding"] && res.headers["content-encoding"] !== "identity")) { res.resume(); return reject(new Error(`Update server returned ${res.statusCode}`)); }
      res.on("error", reject); resolve(res);
    });
    request.on("timeout", () => request.destroy(new Error("Update request timed out")));
    request.on("error", reject);
  });
}
async function small(url, limit) {
  const res = await response(url), chunks = []; let size = 0;
  const timer = setTimeout(() => res.destroy(new Error("Update request expired")), 30_000);
  try {
    for await (const chunk of res) { size += chunk.length; if (size > limit) throw new Error("Update response too large"); chunks.push(chunk); }
    return Buffer.concat(chunks);
  } finally { clearTimeout(timer); res.destroy(); }
}
async function digest(file) {
  const hash = crypto.createHash("sha256"); for await (const chunk of fs.createReadStream(file)) hash.update(chunk); return hash.digest("hex");
}
class DesktopUpdater {
  constructor({ app, shell }) {
    this.app = app; this.shell = shell; this.busy = false; this.candidate = null; this.file = null;
    this.config = require("../update-config.json");
    this.directory = path.join(app.getPath("userData"), "updates");
    this.preferences = path.join(app.getPath("userData"), "update-preferences.json");
    this.automatic = false;
    try { this.automatic = JSON.parse(fs.readFileSync(this.preferences, "utf8")).automatic === true; } catch { /* opt in */ }
    try { releaseBase(this.config); if (crypto.createPublicKey(this.config.publicKey).asymmetricKeyType !== "ed25519") throw new Error(); this.configured = app.isPackaged; }
    catch { this.configured = false; }
    this.state = { status: this.configured ? "idle" : "unconfigured", currentVersion: app.getVersion() };
  }
  status() { return { ...this.state, configured: this.configured, automatic: this.automatic, platform: process.platform }; }
  async request(action, body = {}) {
    if (action === "status") return this.status();
    if (action === "preferences") {
      this.automatic = body.automatic === true;
      fs.writeFileSync(this.preferences, JSON.stringify({ automatic: this.automatic }), { mode: 0o600 });
      return this.status();
    }
    if (!this.configured) throw new Error("Signed updates require a packaged app with a configured GitHub repository and release public key");
    if (this.busy) throw new Error("An update operation is already running");
    this.busy = true;
    try {
      if (action === "check") {
        this.state.status = "checking"; delete this.state.error; this.file = null; this.candidate = null;
        const base = releaseBase(this.config);
        const [bytes, sig] = await Promise.all([small(base + "dropsync-update.json", 65_536), small(base + "dropsync-update.sig", 256)]);
        this.candidate = verifyManifest(bytes, sig.toString("ascii"), this.config, { currentVersion: this.app.getVersion(), platform: process.platform, arch: process.arch });
        this.state = { status: this.candidate.available ? "available" : "current", currentVersion: this.app.getVersion(), version: this.candidate.version };
      } else if (action === "download") {
        if (!this.candidate?.available || this.candidate.expiresAt <= Date.now()) throw new Error("Check for updates first");
        this.state.status = "downloading";
        fs.mkdirSync(this.directory, { recursive: true, mode: 0o700 });
        const final = path.join(this.directory, "verified-update" + { win32: ".exe", darwin: ".pkg", linux: ".AppImage" }[process.platform]);
        const part = path.join(this.directory, crypto.randomUUID() + ".part");
        const res = await response(this.candidate.url); let bytes = 0;
        const hash = crypto.createHash("sha256");
        const meter = new Transform({ transform: (chunk, _encoding, done) => {
          bytes += chunk.length;
          if (bytes > this.candidate.artifact.size) return done(new Error("Update package exceeded signed size"));
          hash.update(chunk); done(null, chunk);
        } });
        const timer = setTimeout(() => res.destroy(new Error("Update download expired")), 10 * 60_000);
        try {
          await pipeline(res, meter, fs.createWriteStream(part, { flags: "wx", mode: 0o600 }));
          if (bytes !== this.candidate.artifact.size || hash.digest("hex") !== this.candidate.artifact.sha256) throw new Error("Update package checksum mismatch");
          fs.rmSync(final, { force: true }); fs.renameSync(part, final); this.file = final; this.state.status = "downloaded";
        } finally { clearTimeout(timer); res.destroy(); fs.rmSync(part, { force: true }); }
      } else if (action === "install") {
        if (!this.file || !this.candidate?.available || this.candidate.expiresAt <= Date.now()) throw new Error("Download a verified update first");
        if (fs.lstatSync(this.file).isSymbolicLink() || await digest(this.file) !== this.candidate.artifact.sha256) throw new Error("Downloaded package changed");
        if (process.platform === "linux") {
          // Distribution packages use their package manager. Replace only an owned AppImage.
          const target = process.env.APPIMAGE;
          if (!target || !path.isAbsolute(target)) throw new Error("Install the AppImage edition for in-app updates; DEB/RPM editions use the system package manager");
          const stat = fs.lstatSync(target), parent = fs.statSync(path.dirname(target));
          if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== process.getuid() || parent.uid !== process.getuid() || (parent.mode & 0o022)) throw new Error("AppImage and its directory must belong to you and not be group/world writable");
          const temp = target + "." + crypto.randomUUID() + ".update";
          try { fs.copyFileSync(this.file, temp, fs.constants.COPYFILE_EXCL); fs.chmodSync(temp, 0o700); fs.renameSync(temp, target); }
          finally { fs.rmSync(temp, { force: true }); }
          this.app.relaunch({ execPath: target }); setTimeout(() => this.app.quit(), 300);
        } else if (process.platform === "win32") {
          await new Promise((resolve, reject) => {
            const child = spawn(this.file, [], { detached: true, stdio: "ignore", windowsHide: true });
            child.once("error", reject); child.once("spawn", () => { child.unref(); resolve(); });
          });
          setTimeout(() => this.app.quit(), 300);
        } else {
          const error = await this.shell.openPath(this.file); if (error) throw new Error(error);
        }
        this.state.status = "installing";
      } else throw new Error("Unknown update action");
      return this.status();
    } catch (error) { this.state.status = "error"; this.state.error = error.message; throw error; }
    finally { this.busy = false; }
  }
  start() {
    if (!this.configured) return;
    const check = () => { if (this.automatic && !this.busy) this.request("check").catch(() => {}); };
    this.startupTimer = setTimeout(check, 30_000); this.timer = setInterval(check, 6 * 60 * 60_000);
    this.startupTimer.unref(); this.timer.unref();
  }
}
module.exports = { DesktopUpdater };
