"use strict";
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const files = ["server.js", "app.js", "runtime.js", "updates-ui.js", "project-info.js", "feature-settings.js", "workspace-features.js", "product.js", "auth.js", "auth-config.js", "welcome.js", "scripts/sign-update.js", ...["src", "desktop", "auth-server"].flatMap((dir) => fs.readdirSync(dir).filter((f) => f.endsWith(".js")).map((f) => path.join(dir, f)))];
for (const file of files) {
  const result = spawnSync(process.execPath, ["--check", file], { stdio: "inherit", windowsHide: true });
  if (result.status) process.exit(result.status);
}
console.log(`${files.length} JavaScript files checked.`);
