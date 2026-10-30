"use strict";
const { spawn } = require("node:child_process");
const { once } = require("node:events");
module.exports = async () => {
  const service = spawn(process.execPath, ["server.js"], {
    env: { ...process.env, DROPSYNC_PORT: "47931", DROPSYNC_DATA_DIR: ".cache/ui-test-data", DROPSYNC_DISCOVERY_PORT: "47932", DROPSYNC_VAULT_PASSPHRASE: "isolated-ui-fixture-passphrase" },
    stdio: ["ignore", "pipe", "pipe"], windowsHide: true,
  });
  let output = "";
  service.stdout.on("data", (chunk) => { output += chunk; });
  service.stderr.on("data", (chunk) => { output += chunk; });
  const stop = async () => { if (service.exitCode === null) { const done = once(service, "exit"); service.kill(); await done; } };
  try {
    for (let i = 0; i < 100; i++) {
      if (service.exitCode !== null) throw new Error(output);
      if (output.includes("DropSync is running")) return stop;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    throw new Error(`UI test server timed out: ${output}`);
  } catch (error) { await stop(); throw error; }
};
