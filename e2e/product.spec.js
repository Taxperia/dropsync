"use strict";
const { test, expect } = require("@playwright/test");

test("an upgraded Android install opens the native workspace instead of a fake login or web landing page", async ({ page, context }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await context.addInitScript(() => {
    window.DropSyncAndroid = { isNativeApp: () => true };
    localStorage.setItem("dropsync.onboarded.v1", "true");
  });
  await page.goto("/index.html#dashboard");
  await expect(page.locator("#authForm")).toBeHidden();
  await expect(page.locator(".mobile-nav")).toBeVisible();
  await expect(page.locator(".page[data-page='dashboard']")).toHaveClass(/is-active/);
  await page.evaluate(() => { location.hash = "#history"; });
  await expect(page.locator("#pageTitle")).toHaveText("History");
  // An unconfigured account provider must not masquerade as a required login.
  const reopened = await context.newPage();
  await reopened.goto("/index.html#dashboard");
  await expect(reopened.locator(".page[data-page='dashboard']")).toHaveClass(/is-active/);
  await expect(reopened.locator(".page[data-page='onboarding']")).toBeHidden();
});

test("Android native bridge shows and pairs a real discovered desktop without advertising file transfer", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.addInitScript(() => {
    localStorage.setItem("dropsync.onboarded.v1", "true");
    window.nativeDiscoveryError = "LAN multicast failed on wlan0";
    const peer = {
      deviceId: "a".repeat(32), name: "Office PC", address: "192.168.1.20", port: 47821,
      trusted: false, online: true, lastSeen: Date.now(), fingerprint: "AAAA-BBBB-CCCC-DDDD",
      capabilities: { pairing: true, transferSend: true, transferReceive: true },
    };
    window.DropSyncAndroid = {
      isNativeApp: () => true,
      request: (path, method) => {
        if (path === "/api/bootstrap") return JSON.stringify({
          version: "0.3.0", csrfToken: "native",
          self: { deviceId: "b".repeat(32), name: "My phone", fingerprint: "1111-2222-3333-4444", port: 47821, addresses: ["192.168.1.21"] },
          settings: { deviceName: "My phone", downloadDirectory: "Android app storage", discoveryEnabled: true, autoAcceptTrusted: false, ui: {} },
          discovery: { port: 45555, multicastAddress: "239.255.42.99", receivedCount: 1,
            interfaces: [{ name: "wlan0", address: "192.168.1.21" }], lastError: window.nativeDiscoveryError },
          devices: [peer], trustedDevices: [], transfers: [], stagedFiles: [], system: {},
          security: { protocol: "DropSync/1", encryption: "AES-256-GCM pairing" },
          capabilities: { discovery: true, pairing: true, transferSend: false, transferReceive: false },
        });
        if (path === "/api/pairing/session") return JSON.stringify({ code: "123456", expiresAt: Date.now() + 300000 });
        if (path === "/api/pair" && method === "POST") { peer.trusted = true; return JSON.stringify({ trusted: { deviceId: peer.deviceId, name: peer.name, fingerprint: peer.fingerprint } }); }
        return JSON.stringify({ __error: "Unexpected native request" });
      },
    };
  });
  await page.goto("/index.html#nearby");
  await expect(page.locator("#deviceGrid")).toContainText("Office PC");
  await page.locator("#deviceGrid [data-real-pair]").click();
  await expect(page.locator(".pairing-code .code")).toHaveText("123-456");
  await page.locator("#pairCodeInput").fill("654321");
  await page.locator("#pairConfirm").click();
  await expect(page.locator("#deviceGrid button", { hasText: "Paired" })).toBeDisabled();
  await expect(page.locator("#deviceGrid")).not.toContainText("Send Files");
  await page.evaluate(() => { location.hash = "#network"; });
  const network = page.locator(".page[data-page='network']");
  await expect(network).toContainText("wlan0 (192.168.1.21)");
  await expect(network).toContainText("LAN multicast failed on wlan0");
  await page.evaluate(() => {
    window.nativeDiscoveryError = null;
    window.dispatchEvent(new Event("dropsync-native-devices"));
  });
  await expect(network).not.toContainText("LAN multicast failed on wlan0");
  await expect(network.locator(".spec-list > div").filter({ hasText: "Last discovery error" })).toContainText("None");
});

test("fresh desktop is real, empty, and has durable offline peer cards", async ({ page }) => {
  const errors = []; page.on("pageerror", (e) => errors.push(e.message));
  await page.goto("/index.html");
  await expect(page.locator("#authForm")).toBeHidden();
  await expect(page.locator("#authNotice")).toBeHidden();
  await page.locator("#continueLocal").click();
  await expect(page.locator("#dashDevices")).toContainText("Pair your first device");
  await expect(page.locator("#realDashTransfers")).toContainText("No active transfers");
  await expect(page.locator("#dashDevices")).not.toContainText("Galaxy");
  await page.evaluate(() => {
    runtimeState.devices = [{ deviceId: "a".repeat(32), name: "Paired laptop", trusted: true, online: false }];
    renderDevices();
  });
  const card = page.locator("#dashDevices .is-offline");
  await expect(card).toContainText("Offline");
  await expect(card).toBeDisabled();
  await expect(card.locator(".qbars .on")).toHaveCount(0);
  await page.screenshot({ path: "shots/verified-desktop.png", fullPage: true });
  expect(errors).toEqual([]);
});

for (const width of [320, 390, 768]) {
  test(`Android ${width}px: no demo data, no horizontal scrolling, full-page settings`, async ({ page }) => {
    await page.setViewportSize({ width, height: 844 });
    await page.addInitScript(() => { window.DropSyncAndroid = { isNativeApp: () => true }; });
    const errors = []; page.on("pageerror", (e) => errors.push(e.message));
    await page.goto("/index.html");
    await expect(page.locator(".page[data-page='onboarding']")).toHaveClass(/is-active/);
    await expect(page.locator(".mobile-nav")).toBeHidden();
    if (width === 390) await page.screenshot({ path: "shots/verified-android-introduction.png", fullPage: true });
    await page.locator("#onboardNext").click(); await page.locator("#onboardNext").click(); await page.locator("#onboardNext").click();
    await expect(page.locator(".page[data-page='dashboard']")).toHaveClass(/is-active/);
    await expect(page.locator("#authForm")).toBeHidden();
    await expect(page.locator("#dashDevices")).not.toContainText("Galaxy");
    await expect(page.locator(".page[data-page='dashboard']")).not.toContainText("Project_Backup");
    for (const route of ["dashboard", "shared", "transfers", "storage", "history", "account", "settings-page"]) {
      await page.evaluate((route) => { location.hash = `#${route}`; }, route);
      await expect(page.locator(`.page[data-page='${route}']`)).toHaveClass(/is-active/);
      const overflow = await page.evaluate(() => {
        const page = document.querySelector(".page.is-active");
        return { document: document.documentElement.scrollWidth > innerWidth, page: page.scrollWidth > page.clientWidth + 1 };
      });
      expect(overflow, route).toEqual({ document: false, page: false });
    }
    await expect(page.locator("#ov-settings")).toBeHidden();
    await expect(page.locator("#settingsPane")).toContainText("Device name");
    await expect(page.locator("#settingsPane")).not.toContainText("Windows");
    await page.locator("[data-cat='appearance']").click();
    await page.locator("[aria-label='Theme']").selectOption("Light");
    await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
    await page.screenshot({ path: `shots/verified-mobile-${width}.png`, fullPage: true });
    await page.reload();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
    await expect(page.locator(".page[data-page='onboarding']")).not.toHaveClass(/is-active/);
    expect(errors).toEqual([]);
  });
}

test("history columns and shared files show actual completed records", async ({ page }) => {
  await page.goto("/index.html#history");
  await page.locator("#continueLocal").click();
  await page.waitForFunction(() => !runtimeState.unavailable);
  await page.evaluate(() => {
    runtimeState.transfers = [{ id: "test", fileName: "a".repeat(120) + ".zip", deviceName: "My laptop", size: 1024, direction: "receive", status: "completed", createdAt: new Date().toISOString() }];
    renderTransfers(); renderStaticDataAsLive();
  });
  const cells = page.locator(".history-table tbody tr").first().locator("td");
  await expect(cells).toHaveCount(8);
  await expect(cells.nth(5)).toHaveText("completed");
  await page.setViewportSize({ width: 320, height: 780 });
  await page.evaluate(() => { location.hash = "#shared"; });
  await expect(page.locator(".shared-card")).toHaveCount(1);
  expect(await page.locator(".shared-grid").evaluate((el) => el.scrollWidth <= el.clientWidth)).toBe(true);
});

test("landing page themes, links and mobile layout", async ({ page }) => {
  await page.goto("/");
  await expect(page.locator("h1")).toContainText("Just DropSync");
  await page.screenshot({ path: "shots/verified-landing-dark.png", fullPage: true });
  await page.locator("#themeToggle").click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await page.screenshot({ path: "shots/verified-landing-light.png", fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: "shots/verified-landing-mobile.png", fullPage: true });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.getByRole("link", { name: "Start sharing" }).click();
  await expect(page.locator("#authForm")).toBeHidden();
  await expect(page.locator("#authNotice")).toBeHidden();
  await expect(page.locator(".sidebar")).toBeHidden();
  await page.screenshot({ path: "shots/verified-login-mobile.png", fullPage: true });
  await page.locator("#continueLocal").click();
  await expect(page.locator("#pageTitle")).toHaveText("Dashboard");
});

test("existing root dashboard bookmarks still open their original page", async ({ page }) => {
  await page.goto("/#history");
  await expect(page).toHaveURL(/\/index\.html#account$/);
  await expect(page.locator("#authForm")).toBeHidden();
  await expect(page.locator("#authNotice")).toBeHidden();
  await page.locator("#continueLocal").click();
  await expect(page).toHaveURL(/\/index\.html#history$/);
  await expect(page.locator("#pageTitle")).toHaveText("History");
});
