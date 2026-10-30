"use strict";
const fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto");
const owned = new Map();
function acquire(directory) {
  directory = path.resolve(directory); if (owned.has(directory)) return;
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const file = path.join(directory, ".runtime-lock"), value = JSON.stringify({ pid: process.pid, token: crypto.randomUUID() });
  for (let attempt = 0; attempt < 2; attempt++) {
    try { fs.writeFileSync(file, value, { flag: "wx", mode: 0o600 }); owned.set(directory, value); return; }
    catch (error) {
      if (error.code !== "EEXIST") throw error;
      let previous;
      try { previous = fs.readFileSync(file, "utf8"); } catch { continue; }
      let pid; try { pid = JSON.parse(previous).pid; } catch { throw new Error("The local data lock is invalid; preserve it for manual recovery"); }
      if (!Number.isSafeInteger(pid) || pid < 1) throw new Error("Invalid local data lock");
      let alive = true; try { process.kill(pid, 0); } catch (probe) { if (probe.code === "ESRCH") alive = false; }
      if (alive) throw new Error("Another DropSync process is using this data directory. Close it before starting another instance.");
      if (fs.readFileSync(file, "utf8") === previous && path.dirname(path.resolve(file)) === directory) fs.unlinkSync(file);
    }
  }
  throw new Error("Could not acquire the local data lock");
}
process.on("exit", () => { for (const [directory, value] of owned) { const file = path.join(directory, ".runtime-lock"); try { if (fs.readFileSync(file, "utf8") === value) fs.unlinkSync(file); } catch { /* A stale lock is checked on next launch. */ } } });
module.exports = { acquire };
