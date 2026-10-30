"use strict";
const { test, expect } = require("@playwright/test");

test("incoming approval can be closed, reopened, accepted and disabled in settings", async ({ page }) => {
  const errors = []; page.on("pageerror", (error) => errors.push(error.message));
  const id = "11111111-2222-4333-8444-555555555555";
  let pending = [{ id, deviceName: "OPPO CPH2205", fileName: "Holiday photo.jpg", size: 2048, expiresAt: Date.now() + 90_000 }];
  let requireIncomingApproval = true, accepted = false;
  await page.addInitScript(() => {
    window.EventSource = class extends EventTarget { constructor() { super(); setTimeout(() => this.onopen?.(), 10); } close() {} };
  });
  await page.route("**/api/bootstrap", async (route) => {
    const response = await route.fetch(); const data = await response.json();
    await route.fulfill({ json: { ...data, incomingRequests: pending, settings: { ...data.settings, requireIncomingApproval } } });
  });
  await page.route(`**/api/incoming/${id}`, async (route) => {
    accepted = route.request().postDataJSON().accept; pending = [];
    await route.fulfill({ json: { requests: [], transfers: [] } });
  });
  await page.route("**/api/settings", async (route) => {
    const body = route.request().postDataJSON();
    if (body.requireIncomingApproval !== undefined) requireIncomingApproval = body.requireIncomingApproval;
    const response = await route.fetch(); const data = await response.json();
    await route.fulfill({ json: { ...data, settings: { ...data.settings, requireIncomingApproval } } });
  });
  await page.goto("/index.html");
  // Bootstrap may show the incoming prompt before the workspace entry choice.
  await expect(page.locator("#ov-incoming")).toBeVisible();
  await expect(page.locator("#incomingFrom")).toContainText("OPPO CPH2205");
  await expect(page.locator("#incomingRequestList")).toContainText("Holiday photo.jpg");
  await page.locator("#ov-incoming").getByRole("button", { name: "Close", exact: true }).click();
  await expect(page.locator("#ov-incoming")).toBeHidden();
  if (await page.locator("#continueLocal").isVisible()) await page.locator("#continueLocal").click();
  await page.locator("#incomingBanner button").click();
  await expect(page.locator("#ov-incoming")).toBeVisible();
  await page.screenshot({ path: "shots/verified-incoming-approval.png", fullPage: true, animations: "disabled" });
  await page.locator("#acceptTransfer").click();
  await expect(page.locator("#ov-incoming")).toBeHidden();
  expect(accepted).toBe(true);
  await page.evaluate(() => openModal("settings"));
  const toggle = page.getByRole("switch", { name: "Ask before receiving files" });
  await expect(toggle).toHaveAttribute("aria-checked", "true");
  await Promise.all([page.waitForResponse((response) => response.url().endsWith("/api/settings") && response.request().method() === "PUT"), toggle.click()]);
  expect(requireIncomingApproval).toBe(false);
  await page.reload();
  if (await page.locator("#continueLocal").isVisible()) await page.locator("#continueLocal").click();
  await page.evaluate(() => openModal("settings"));
  await expect(toggle).toHaveAttribute("aria-checked", "false");
  await Promise.all([page.waitForResponse((response) => response.url().endsWith("/api/settings") && response.request().method() === "PUT"), toggle.click()]);
  expect(requireIncomingApproval).toBe(true);
  expect(errors).toEqual([]);
});

test("received file location and desktop actions appear in activity, history and shared files", async ({ page }) => {
  const id = "11111111-2222-4333-8444-555555555555";
  let action;
  await page.route(`**/api/received/${id}/show`, async (route) => { action = route.request().method(); await route.fulfill({ json: { ok: true } }); });
  await page.goto("/index.html"); await page.locator("#continueLocal").click();
  await page.waitForFunction(() => !runtimeState.unavailable);
  await page.evaluate((id) => {
    runtimeState.desktop = true;
    runtimeState.transfers = [{ id, direction: "receive", status: "completed", deviceName: "OPPO CPH2205", fileName: "Holiday photo.jpg",
      savedPath: "C:\\Downloads\\DropSync\\Holiday photo.jpg", size: 2048, createdAt: new Date().toISOString() }];
    renderTransfers(); renderStaticDataAsLive();
  }, id);
  await expect(page.locator(".activity-list")).toContainText("Open file");
  await page.locator(".activity-list [data-file-action='show']").click();
  await expect.poll(() => action).toBe("POST");
  await page.evaluate(() => { location.hash = "#shared"; });
  await expect(page.locator(".shared-grid")).toContainText("C:\\Downloads\\DropSync\\Holiday photo.jpg");
  await expect(page.locator(".shared-grid")).toContainText("Show in folder");
  await expect(page.locator("#receivedFolderBar")).toContainText("Open downloads folder");
  await page.screenshot({ path: "shots/verified-received-files.png", fullPage: true });
  await page.evaluate(() => { location.hash = "#history"; });
  await expect(page.locator(".history-table [data-file-action='open']")).toHaveCount(1);
});
