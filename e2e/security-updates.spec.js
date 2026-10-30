"use strict";
const { test, expect } = require("@playwright/test");

test("local entry is prominent and unconfigured updates do not offer an installer", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/index.html");
  const enter = page.getByRole("button", { name: "Start sharing on this device" });
  await expect(enter).toBeVisible(); await expect(enter).toHaveClass(/btn-primary/);
  expect((await enter.boundingBox()).height).toBeGreaterThanOrEqual(48);
  await expect(page.locator("#authNotice")).toBeHidden();
  await enter.click(); await page.waitForFunction(() => Boolean(runtimeState.settings));
  await page.evaluate(() => { openModal("settings"); renderSettings("security"); });
  const control = page.getByRole("switch", { name: "Allow executable files" });
  await expect(control).toHaveAttribute("aria-checked", "false");
  await page.route("**/api/updates/status", (route) => route.fulfill({ json: { configured: false, status: "unconfigured", currentVersion: "0.6.0" } }));
  await page.locator("#settingsNav [data-cat='updates']").click();
  await expect(page.locator("#updateSettings")).toContainText("not activated");
  await expect(page.locator("#updateSettings button")).toHaveCount(0);
});

test("an update cannot be installed before the verified download step", async ({ page }) => {
  let downloaded = false, installed = false;
  const state = (status) => ({ configured: true, currentVersion: "0.6.0", version: "0.7.0", automatic: false, status });
  await page.route("**/api/updates/status", (route) => route.fulfill({ json: state("available") }));
  await page.route("**/api/updates/download", (route) => { downloaded = true; return route.fulfill({ json: state("downloaded") }); });
  await page.route("**/api/updates/install", (route) => { expect(downloaded).toBe(true); installed = true; return route.fulfill({ json: state("installing") }); });
  await page.goto("/index.html"); await page.locator("#continueLocal").click();
  await page.evaluate(() => { openModal("settings"); renderSettings("updates"); });
  await expect(page.getByRole("button", { name: "Install update", exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Download verified update" }).click();
  await page.getByRole("button", { name: "Install update", exact: true }).click();
  await expect(page.locator("#updateSettings")).toContainText("Installation started"); expect(installed).toBe(true);
});
