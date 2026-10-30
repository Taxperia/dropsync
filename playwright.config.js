"use strict";
const { defineConfig } = require("@playwright/test");
module.exports = defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  globalSetup: "./e2e/setup.js",
  use: { channel: "chrome", baseURL: "http://127.0.0.1:47931", screenshot: "only-on-failure", trace: "retain-on-failure" },
});
