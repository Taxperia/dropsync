"use strict";
const { test, expect } = require("@playwright/test");

async function nativeSender(page, { coldShare = false, paired = true } = {}) {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.addInitScript(({ coldShare, paired }) => {
    localStorage.setItem("dropsync.onboarded.v1", "true");
    const peer = { deviceId: "a".repeat(32), name: "Office PC", address: "192.168.1.20", port: 47821,
      online: true, trusted: paired, fingerprint: "AAAA-BBBB", capabilities: { transferSend: true, transferReceive: true, pairing: true } };
    const file = { id: "c".repeat(32), name: "holiday.jpg", size: 2048, sha256: "d".repeat(64) };
    const state = window.nativeTestState = {
      version: "0.4.0", csrfToken: "native", self: { deviceId: "b".repeat(32), name: "OPPO CPH2205", addresses: ["192.168.1.21"], port: 47821, fingerprint: "BBBB-AAAA" },
      settings: { deviceName: "OPPO CPH2205", downloadDirectory: "Android app storage", discoveryEnabled: true, ui: {} },
      discovery: { receivedCount: 1, interfaces: [{ name: "wlan0", address: "192.168.1.21" }] },
      devices: [peer], trustedDevices: paired ? [{ deviceId: peer.deviceId, name: peer.name }] : [], transfers: [],
      stagedFiles: coldShare ? [file] : [], importState: { busy: false, pending: coldShare, revision: coldShare ? 1 : 0 },
      capabilities: { discovery: true, pairing: true, transferSend: true, transferReceive: false },
      system: {}, security: { encryption: "AES-256-GCM" },
    };
    window.nativeSendCalls = [];
    window.DropSyncAndroid = {
      isNativeApp: () => true,
      requestAsync(id, path, method, encoded) {
        setTimeout(() => {
          let result;
          if (path === "/api/bootstrap") result = state;
          else if (path === "/api/import/ack") { state.importState.pending = false; result = { ok: true }; }
          else if (path === "/api/transfers/send") {
            const body = JSON.parse(encoded); window.nativeSendCalls.push(body);
            if (!peer.trusted || !peer.online || body.deviceId !== peer.deviceId || !body.fileIds.length) result = { __error: "Pair an online device first" };
            else {
              const transfer = { id: "e".repeat(32), direction: "send", deviceId: peer.deviceId, deviceName: peer.name,
                fileName: state.stagedFiles[0].name, size: state.stagedFiles[0].size, bytesTransferred: 0, status: "connecting", progress: 0,
                encrypted: true, createdAt: new Date().toISOString() };
              state.transfers = [transfer]; state.stagedFiles = []; result = { transfers: [transfer] };
              setTimeout(() => {
                transfer.status = "completed"; transfer.progress = 100; transfer.bytesTransferred = transfer.size;
                window.dispatchEvent(new Event("dropsync-native-devices"));
              }, 350);
            }
          } else result = { __error: "Unexpected request " + path };
          window.completeDropSyncRequest(id, JSON.stringify(result));
        }, 10);
      },
    };
    window.importTestFiles = (names) => {
      state.stagedFiles = names.map((name, i) => ({ ...file, id: String(i).repeat(32), name }));
      state.importState = { busy: false, pending: true, revision: state.importState.revision + 1 };
      window.dispatchEvent(new Event("dropsync-native-devices"));
    };
  }, { coldShare, paired });
}

test("Android sender lists the paired computer and sends only after confirmation", async ({ page }) => {
  const errors = []; page.on("pageerror", (error) => errors.push(error.message));
  await nativeSender(page);
  await page.goto("/index.html#dashboard");
  const card = page.locator("#dashDevices .device-chip", { hasText: "Office PC" });
  await expect(card).toBeEnabled();
  await expect(card).toHaveCSS("opacity", "1");
  await card.click();
  await expect(page.locator("#sendDeviceList")).toContainText("Office PC");
  await page.evaluate(() => window.importTestFiles(["holiday.jpg"]));
  await expect(page.locator("#pickedList")).toContainText("holiday.jpg");
  await page.locator("#sendContinue").click();
  await expect(page.locator("#confirmDevName")).toContainText("Office PC");
  expect(await page.evaluate(() => window.nativeSendCalls.length)).toBe(0);
  await page.locator("#startTransfer").click();
  await expect(page.locator("#ov-send")).toBeHidden();
  await expect.poll(() => page.evaluate(() => runtimeState.transfers[0]?.status)).toBe("completed");
  expect(await page.evaluate(() => window.nativeSendCalls.length)).toBe(1);
  expect(errors).toEqual([]);
});

test("cold and warm Android shares open selected files without automatic sending", async ({ page }) => {
  await nativeSender(page, { coldShare: true });
  await page.goto("/index.html#dashboard");
  await expect(page.locator("#ov-send")).toBeVisible();
  await expect(page.locator("#pickedList")).toContainText("holiday.jpg");
  await expect.poll(() => page.evaluate(() => window.nativeTestState.importState.pending)).toBe(false);
  expect(await page.evaluate(() => window.nativeSendCalls.length)).toBe(0);
  await page.locator("#sendContinue").click();
  await page.evaluate(() => window.importTestFiles(["photo-one.jpg", "document.pdf"]));
  await expect(page.locator("#pickedList li")).toHaveCount(2);
  await expect(page.locator("#ov-send .send-step[data-step='1']")).toHaveClass(/is-active/);
  await expect(page.locator("#pickedList")).toContainText("document.pdf");
  await page.screenshot({ path: "shots/verified-android-share.png", fullPage: true });
  expect(await page.evaluate(() => window.nativeSendCalls.length)).toBe(0);
});

test("shared files remain selected while an unpaired computer is excluded from sending", async ({ page }) => {
  await nativeSender(page, { coldShare: true, paired: false });
  await page.goto("/index.html#dashboard");
  await expect(page.locator("#pickedList")).toContainText("holiday.jpg");
  await expect(page.locator("#sendDeviceList .send-device")).toHaveCount(0);
  await page.locator("#sendContinue").click();
  await expect(page.locator("#ov-send .send-step[data-step='1']")).toHaveClass(/is-active/);
  expect(await page.evaluate(() => window.nativeSendCalls.length)).toBe(0);
});
