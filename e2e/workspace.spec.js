"use strict";
// Requires an isolated browser/loopback fixture; these checks were not run locally.
const { test, expect } = require("@playwright/test");
async function enter(page) {
  await page.goto("/index.html"); await page.locator("#continueLocal").click();
  await page.waitForFunction(() => Boolean(runtimeState.settings) && !runtimeState.unavailable);
}
test("profile dropdown opens, saves a local name and survives reload", async ({ page }) => {
  await enter(page); await page.locator("#profileBtn").click();
  await expect(page.locator("#workspaceProfileMenu")).toBeVisible();
  await page.getByRole("menuitem", { name: "Edit profile" }).click();
  await page.locator("#profileName").fill("Fixture owner");
  await page.getByRole("button", { name: "Save profile", exact: true }).click();
  await expect(page.locator("#profileBtn")).toContainText("Fixture owner");
  await page.reload(); await expect(page.locator("#profileBtn")).toContainText("Fixture owner");
});
test("GitHub themes persist and text stages through the regular device chooser", async ({ page }) => {
  await enter(page); await page.evaluate(() => { openModal("settings"); renderSettings("appearance"); });
  await page.getByLabel("Theme", { exact: true }).selectOption("GitHub Dark");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "github-dark");
  await page.reload(); await expect(page.locator("html")).toHaveAttribute("data-theme", "github-dark");
  await page.evaluate(() => openSend({ mode: "text" }));
  await page.locator("#composerText").fill("Only this explicitly composed message.");
  await page.locator("#composerContinue").click();
  await expect(page.locator("#ov-composer")).toBeHidden();
  await expect.poll(() => page.evaluate(() => runtimeState.stagedFiles.some((file) => file.name === "Shared text.txt"))).toBe(true);
  expect(await page.evaluate(() => runtimeState.settings.clipboardEnabled)).toBe(false);
});
