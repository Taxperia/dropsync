"use strict";
const fs = require("node:fs");
const path = require("node:path");
const { spawn } = require("node:child_process");
const crypto = require("node:crypto");

async function receivedFile(store, id) {
  const transfer = store.transfers.find((item) => item.id === id && item.direction === "receive" && item.status === "completed");
  if (!transfer) throw Object.assign(new Error("Completed received file not found"), { statusCode: 404 });
  // Old history did not store the path. Only infer a plain filename in the current
  // downloads directory; new records keep their original path after settings change.
  const target = transfer.savedPath || (typeof transfer.fileName === "string" && path.basename(transfer.fileName) === transfer.fileName
    ? path.join(store.settings.downloadDirectory, transfer.fileName) : null);
  if (!target || !path.isAbsolute(target) || !fs.existsSync(target) || !fs.statSync(target).isFile()) {
    throw Object.assign(new Error("This file was moved or deleted. Check the saved folder."), { statusCode: 404 });
  }
  if (!transfer.savedPath) {
    if (!/^[a-f0-9]{64}$/.test(transfer.sha256 || "") || fs.statSync(target).size !== transfer.size) {
      throw Object.assign(new Error("The original location was not recorded. Open the downloads folder to locate this file."), { statusCode: 404 });
    }
    const hash = crypto.createHash("sha256");
    for await (const chunk of fs.createReadStream(target)) hash.update(chunk);
    if (hash.digest("hex") !== transfer.sha256) throw Object.assign(new Error("A different file has this name in the current downloads folder."), { statusCode: 404 });
    store.updateTransfer(id, { savedPath: target });
  }
  return { path: target, name: path.basename(target), directory: path.dirname(target) };
}

function showFolder(target, selectFile = false) {
  let executable, args;
  if (process.platform === "win32") { executable = "explorer.exe"; args = selectFile ? ["/select,", target] : [target]; }
  else if (process.platform === "darwin") { executable = "open"; args = selectFile ? ["-R", target] : [target]; }
  else { executable = "xdg-open"; args = [selectFile ? path.dirname(target) : target]; }
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, { detached: true, stdio: "ignore", windowsHide: false });
    child.once("error", reject);
    child.once("spawn", () => { child.unref(); resolve(); });
  });
}

module.exports = { receivedFile, showFolder };
