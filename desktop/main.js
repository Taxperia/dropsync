"use strict";
const { app, BrowserWindow, dialog, shell, utilityProcess, safeStorage, Tray, Menu, Notification, powerSaveBlocker, nativeImage } = require("electron");
const path = require("node:path");
const fs = require("node:fs");
const { DesktopUpdater } = require("./updater");
const { unlockDesktopVault } = require("./vault");
const { dataDirectory } = require("../src/data-directory");

let service;
let mainWindow;
let shuttingDown = false;
let tray;
let keepRunning = true;
let sleepBlocker;
let clipboardEnabled = false;
function trayIcon() {
  // Platform-neutral bitmap: two sharing arrows, drawn through Electron's image API.
  const size = 32, pixels = Buffer.alloc(size * size * 4);
  const draw = (x, y) => { const at = (y * size + x) * 4; pixels[at] = 174; pixels[at + 1] = 201; pixels[at + 2] = 79; pixels[at + 3] = 255; };
  for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) {
    if ((y >= 8 && y <= 11 && x >= 6 && x <= 25) || (x >= 20 && x <= 26 && Math.abs(y - 10) <= x - 19)
      || (y >= 20 && y <= 23 && x >= 6 && x <= 25) || (x >= 5 && x <= 11 && Math.abs(y - 22) <= 12 - x)) draw(x, y);
  }
  const icon = nativeImage.createFromBitmap(pixels, { width: size, height: size, scaleFactor: 2 });
  if (process.platform === "darwin") icon.setTemplateImage(true); return icon;
}
function reservePortCheck(port) {
  return new Promise((resolve, reject) => {
    const server = require("node:net").createServer();
    server.once("error", () => reject(new Error("Another service is using the DropSync port. Quit the existing DropSync service before upgrading; local files were preserved.")));
    server.listen({ host: "127.0.0.1", port }, () => server.close(resolve));
  });
}
const smokeTest = process.argv.includes("--smoke-test");
if (process.env.DROPSYNC_DESKTOP_PROFILE) app.setPath("userData", path.resolve(process.env.DROPSYNC_DESKTOP_PROFILE));
function smokeLog(value) {
  if (!smokeTest) return;
  fs.appendFileSync(path.join(app.getPath("userData"), "smoke.log"), `${value}\n`);
}
smokeLog("main started");
if (!app.requestSingleInstanceLock()) app.quit();
else {
  app.on("second-instance", () => { mainWindow?.show(); mainWindow?.focus(); });
  app.whenReady().then(async () => {
    const port = Number(process.env.DROPSYNC_PORT || 47821);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Invalid DropSync port");
    await reservePortCheck(port);
    const directory = dataDirectory();
    const unlocked = await unlockDesktopVault(directory, safeStorage);
    const updater = new DesktopUpdater({ app, shell });
    if (!smokeTest) updater.start();
    smokeLog("app ready");
    delete process.env.DROPSYNC_VAULT_PASSPHRASE;
    // Same machine-local data directory as the CLI, so upgrading preserves history.
    service = utilityProcess.fork(path.join(__dirname, "service.js"), [], {
      env: { ...Object.fromEntries(Object.entries(process.env).filter(([key]) => /^(DROPSYNC_|PATH$|Path$|SystemRoot$|WINDIR$|COMSPEC$|TEMP$|TMP$|HOME$|USERPROFILE$|LOCALAPPDATA$|APPDATA$|XDG_|LANG$|LC_|DBUS_SESSION_BUS_ADDRESS$)/.test(key))), DROPSYNC_PORT: String(port) }, stdio: "pipe", serviceName: "DropSync encrypted transfer service",
    });
    let startupError = "";
    service.stdout?.on("data", (data) => smokeLog(data.toString()));
    service.stderr?.on("data", (data) => { startupError = (startupError + data.toString()).slice(-2000); smokeLog(data.toString()); });
    service.on("spawn", () => { service.postMessage({ type: "vault-unlock", directory, key: unlocked.key, provider: unlocked.provider }); unlocked.key.fill(0); smokeLog("service spawned"); });
    service.on("message", (message) => {
      smokeLog(`service message ${JSON.stringify(message)}`);
      if (message.type === "runtime-state") {
        keepRunning = message.keepRunning !== false;
        clipboardEnabled = message.clipboardEnabled === true;
        if ((message.active > 0 || message.keepAwake) && sleepBlocker === undefined) sleepBlocker = powerSaveBlocker.start("prevent-app-suspension");
        else if (!message.active && !message.keepAwake && sleepBlocker !== undefined) { powerSaveBlocker.stop(sleepBlocker); sleepBlocker = undefined; }
        return;
      }
      if (message.type === "notification") {
        if (!smokeTest && Notification.isSupported()) { const notification = new Notification({ title: message.title, body: message.body }); notification.on("click", () => { mainWindow?.show(); mainWindow?.focus(); }); notification.show(); }
        return;
      }
      if (message.type === "update-action") {
        updater.request(message.action, message.body).then(
          (result) => service.postMessage({ type: "update-result", requestId: message.requestId, result }),
          (error) => service.postMessage({ type: "update-result", requestId: message.requestId, error: error.message }));
        return;
      }
      if (message.type === "incoming-pending") {
        if (!smokeTest && mainWindow) { if (mainWindow.isMinimized()) mainWindow.restore(); mainWindow.show(); mainWindow.flashFrame(true); }
        return;
      }
      if (message.type === "file-action") {
        (async () => {
          try {
            if (!path.isAbsolute(message.target) || !fs.existsSync(message.target)) throw new Error("Saved file or folder no longer exists");
            if (smokeTest) smokeLog(`FILE_ACTION_OK ${message.action} ${path.basename(message.target)}`);
            else if (message.action === "show") shell.showItemInFolder(message.target);
            else if (["open", "folder"].includes(message.action)) {
              const error = await shell.openPath(message.target); if (error) throw new Error(error);
            } else throw new Error("Unknown file action");
            service.postMessage({ type: "file-action-result", requestId: message.requestId });
          } catch (error) { service.postMessage({ type: "file-action-result", requestId: message.requestId, error: error.message }); }
        })();
        return;
      }
      if (message.type !== "ready" || mainWindow) return;
      const origin = `http://127.0.0.1:${message.port}`;
      mainWindow = new BrowserWindow({
        width: 1380, height: 900, minWidth: 780, minHeight: 620,
        backgroundColor: "#131418", title: "DropSync", autoHideMenuBar: true,
        show: false, icon: path.join(__dirname, "icon.ico"),
        webPreferences: { nodeIntegration: false, contextIsolation: true, sandbox: true, webSecurity: true },
      });
      if (!smokeTest) {
        tray = new Tray(trayIcon()); tray.setToolTip("DropSync · paired device sharing");
        tray.setContextMenu(Menu.buildFromTemplate([{ label: "Open DropSync", click: () => { mainWindow.show(); mainWindow.focus(); } }, { type: "separator" }, { label: "Quit DropSync", click: () => { shuttingDown = true; app.quit(); } }]));
        tray.on("double-click", () => { mainWindow.show(); mainWindow.focus(); });
        mainWindow.on("close", (event) => { if (!shuttingDown && keepRunning) { event.preventDefault(); mainWindow.hide(); } });
      }
      mainWindow.webContents.setUserAgent(mainWindow.webContents.getUserAgent() + " DropSyncDesktop/0.7.0");
      const openExternal = (value) => {
        try {
          const target = new URL(value);
          if (target.protocol === "https:") shell.openExternal(target.href);
        } catch { /* malformed link */ }
      };
      mainWindow.webContents.setWindowOpenHandler(({ url }) => { openExternal(url); return { action: "deny" }; });
      mainWindow.webContents.on("will-navigate", (event, url) => {
        if (new URL(url).origin !== origin) { event.preventDefault(); openExternal(url); }
      });
      mainWindow.webContents.session.setPermissionRequestHandler((contents, permission, callback, details) => {
        let local = false; try { local = details.isMainFrame && new URL(details.requestingUrl).origin === origin; } catch { }
        if (permission !== "clipboard-read" || contents !== mainWindow.webContents || !clipboardEnabled || !local || !mainWindow.isFocused()) return callback(false);
        contents.executeJavaScript("navigator.userActivation.isActive").then((active) => callback(active === true && clipboardEnabled && mainWindow.isFocused()), () => callback(false));
      });
      mainWindow.webContents.session.setPermissionCheckHandler(() => false);
      mainWindow.webContents.on("did-fail-load", (_event, code, description) => smokeLog(`load failed ${code} ${description}`));
      mainWindow.webContents.on("render-process-gone", (_event, details) => smokeLog(`renderer gone ${JSON.stringify(details)}`));
      mainWindow.once("ready-to-show", () => { if (!smokeTest) mainWindow.show(); });
      if (smokeTest) mainWindow.webContents.once("did-finish-load", async () => {
        smokeLog("page loaded");
        try {
          const landing = await mainWindow.webContents.executeJavaScript("document.querySelector('h1')?.textContent.includes('Just DropSync')");
          if (!landing) throw new Error("Desktop must start on the landing page");
          smokeLog("landing verified");
          const accountLoaded = new Promise((resolve) => mainWindow.webContents.once("did-finish-load", resolve));
          await mainWindow.webContents.executeJavaScript("document.querySelector('.hero-actions a').click()");
          await accountLoaded;
          const entry = await mainWindow.webContents.executeJavaScript("({ account: document.querySelector('[data-page=account]')?.classList.contains('is-active'), standalone: document.documentElement.classList.contains('entry-screen'), dashboard: document.querySelector('[data-page=dashboard]')?.classList.contains('is-active') })");
          if (!entry.account || !entry.standalone || entry.dashboard) throw new Error(`Login must precede dashboard: ${JSON.stringify(entry)}`);
          smokeLog("login verified; dashboard hidden");
          // Hidden smoke windows throttle animation frames; settle finite entry
          // animations before capturing so the image is not an intermediate fade.
          await mainWindow.webContents.executeJavaScript("document.getAnimations().forEach(a => { if (Number.isFinite(a.effect.getComputedTiming().endTime)) a.finish(); })");
          if (process.env.DROPSYNC_SMOKE_SCREENSHOT) fs.writeFileSync(process.env.DROPSYNC_SMOKE_SCREENSHOT.replace(/\.png$/, "-login.png"), (await mainWindow.webContents.capturePage()).toPNG());
          await mainWindow.webContents.executeJavaScript("document.querySelector('#continueLocal').click()");
          let state;
          for (let i = 0; i < 50; i++) {
            state = await mainWindow.webContents.executeJavaScript("({ ready: typeof runtimeState !== 'undefined' && !runtimeState.unavailable && document.querySelector('.profile-name')?.textContent === runtimeState.self?.name && document.querySelector('#netChip')?.textContent.includes('Local LAN'), title: document.querySelector('#pageTitle')?.textContent, node: typeof window.require, process: typeof window.process })");
            if (state.ready) break;
            await new Promise((resolve) => setTimeout(resolve, 200));
          }
          const preferences = mainWindow.webContents.getLastWebPreferences();
          if (!state.ready || state.title !== "Dashboard" || state.node !== "undefined" || state.process !== "undefined" || !preferences.sandbox || !preferences.contextIsolation || preferences.nodeIntegration) throw new Error(`Desktop smoke failed: ${JSON.stringify(state)}`);
          if (process.env.DROPSYNC_SMOKE_FILE_ID) {
            const id = process.env.DROPSYNC_SMOKE_FILE_ID;
            await mainWindow.webContents.executeJavaScript(`Promise.all(['open','show'].map(action => apiRequest('/api/received/${id}/' + action, {method:'POST'})))`);
            await mainWindow.webContents.executeJavaScript("apiRequest('/api/downloads/show', {method:'POST'})");
            smokeLog("received file actions verified via service IPC (shell launch suppressed in smoke)");
          }
          if (process.env.DROPSYNC_SMOKE_PEER_FILE) {
            const crypto = require("node:crypto");
            const { createEphemeralExchange, deriveTransferKey, sealFileInfo, signObject } = require("../src/security");
            const peer = JSON.parse(fs.readFileSync(process.env.DROPSYNC_SMOKE_PEER_FILE, "utf8"));
            const bootstrap = await fetch(`${origin}/api/bootstrap`).then((response) => response.json());
            const prepare = async () => {
              const ephemeral = createEphemeralExchange(), salt = crypto.randomBytes(32), id = crypto.randomUUID();
              const receiver = require("../src/utils").readJson(path.join(process.env.DROPSYNC_DATA_DIR, "identity.json"), null);
              const key = deriveTransferKey(ephemeral.privateKey, receiver.exchangePublicKey, salt, id);
              const meta = { version: 2, transferId: id, senderId: peer.deviceId, recipientId: bootstrap.self.deviceId,
                fileInfo: sealFileInfo(key, id, { fileName: "approval-smoke.txt", sha256: "0".repeat(64) }), size: 10, timestamp: Date.now(), chunkSize: 262144,
                ephemeralPublicKey: ephemeral.publicKey, salt: salt.toString("base64url"), noncePrefix: crypto.randomBytes(8).toString("base64url") };
              const response = await fetch(`${origin}/peer/transfers/prepare`, { method: "POST", headers: {
                "X-DropSync-Meta": Buffer.from(JSON.stringify(meta)).toString("base64url"), "X-DropSync-Signature": signObject(meta, peer.signingPrivateKey) } });
              const result = await response.json(); if (result.status !== "pending") throw new Error(`Approval did not wait: ${JSON.stringify(result)}`);
              return meta.transferId;
            };
            const waitModal = async () => {
              for (let i = 0; i < 100; i++) {
                if (await mainWindow.webContents.executeJavaScript("!document.querySelector('#ov-incoming').hidden")) return;
                await new Promise((resolve) => setTimeout(resolve, 100));
              }
              throw new Error("Incoming approval modal did not open");
            };
            await prepare(); await waitModal();
            await mainWindow.webContents.executeJavaScript("document.querySelector('#ov-incoming [data-close-modal]').click(); document.querySelector('#incomingBanner button').click()");
            await waitModal();
            await mainWindow.webContents.executeJavaScript("decideIncoming(false)");
            await prepare(); await waitModal();
            await mainWindow.webContents.executeJavaScript("decideIncoming(true)");
            const pending = await fetch(`${origin}/api/incoming`).then((response) => response.json());
            if (pending.requests.length) throw new Error("Approval did not resolve");
            smokeLog("incoming modal verified: authenticated request -> close -> reopen -> decline / accept");
          }
          await new Promise((resolve) => setTimeout(resolve, 250));
          if (process.env.DROPSYNC_SMOKE_SCREENSHOT) fs.writeFileSync(process.env.DROPSYNC_SMOKE_SCREENSHOT, (await mainWindow.webContents.capturePage()).toPNG());
          console.log("DROPSYNC_SMOKE_OK: landing -> login -> explicit local entry -> dashboard; local service connected; renderer sandboxed; no Node globals");
          smokeLog("DROPSYNC_SMOKE_OK");
          shuttingDown = true; service.kill(); app.exit(0);
        } catch (error) { smokeLog(error.stack); console.error(error); shuttingDown = true; service.kill(); app.exit(1); }
      });
      mainWindow.loadURL(`${origin}/welcome.html`);
    });
    service.on("exit", () => {
      if (!shuttingDown) {
        const error = startupError || "The local transfer service stopped. Restart DropSync to continue. If another service is running, close it first.";
        if (smokeTest) console.error(error);
        else dialog.showErrorBox("DropSync service stopped", error);
        app.quit();
      }
    });
  }).catch((error) => { dialog.showErrorBox("DropSync could not unlock local data", error.message); shuttingDown = true; service?.kill(); app.quit(); });
  app.on("before-quit", () => { shuttingDown = true; if (sleepBlocker !== undefined) powerSaveBlocker.stop(sleepBlocker); service?.kill(); });
  app.on("window-all-closed", () => app.quit());
}
