"use strict";
// Keys arrive over process IPC; they are never placed in argv, env or renderer IPC.
process.parentPort.once("message", ({ data }) => {
  if (data?.type !== "vault-unlock") throw new Error("Missing vault initialization");
  require("../src/data-lock").acquire(data.directory);
  const { register, migrate } = require("../src/local-vault");
  register(data.directory, Buffer.from(data.key), data.provider); migrate(data.directory);
  require("../server");
});
