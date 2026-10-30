"use strict";
const os = require("node:os"), path = require("node:path");
function dataDirectory() {
  const base = process.platform === "win32" ? path.join(process.env.LOCALAPPDATA || path.join(os.homedir(), "AppData", "Local"), "DropSync")
    : process.platform === "darwin" ? path.join(os.homedir(), "Library", "Application Support", "DropSync")
    : path.join(process.env.XDG_STATE_HOME || path.join(os.homedir(), ".local", "state"), "dropsync");
  return path.resolve(process.env.DROPSYNC_DATA_DIR || base);
}
module.exports = { dataDirectory };
