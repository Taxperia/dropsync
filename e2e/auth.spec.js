"use strict";
const { test, expect } = require("@playwright/test");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { createAuthServer } = require("../auth-server/server");

async function configure(page) {
  await page.route("**/auth-config.js", (route) => route.fulfill({ contentType: "application/javascript", body: 'window.DROPSYNC_AUTH = { url: "https://test-project.supabase.co", publishableKey: "test-public-key", providers: ["google", "facebook", "github"] };' }));
}

test("self-hosted account server completes real registration, logout, and sign-in", async ({ page }) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "dropsync-auth-e2e-"));
  const clientKey = "e2e-client-key-that-is-at-least-32-characters";
  const server = createAuthServer({
    DROPSYNC_AUTH_CLIENT_KEY: clientKey,
    DROPSYNC_AUTH_PUBLIC_URL: "http://127.0.0.1:8787",
    DROPSYNC_AUTH_DATA_DIR: directory,
    DROPSYNC_AUTH_ALLOW_LOOPBACK: "true",
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const authUrl = `http://127.0.0.1:${server.address().port}`;
  try {
    await page.route("**/auth-config.js", (route) => route.fulfill({ contentType: "application/javascript", body: `window.DROPSYNC_AUTH = { type: "dropsync", url: ${JSON.stringify(authUrl)}, publishableKey: ${JSON.stringify(clientKey)}, providers: ["google", "facebook", "github"] };` }));
    await page.goto("/index.html#account");
    await page.locator("#authMode").click();
    await page.locator("#authEmail").fill("selfhosted@example.com");
    await page.locator("#authPassword").fill("a-real-password-123");
    await page.locator("#authSubmit").click();
    await expect(page.locator("#authIdentity")).toHaveText("selfhosted@example.com");
    await page.locator(".sidebar [data-nav='account']").click();
    await page.locator("#authSignOut").click();
    await expect(page.locator("#authForm")).toBeVisible();
    await page.locator("#authEmail").fill("selfhosted@example.com");
    await page.locator("#authPassword").fill("a-real-password-123");
    await page.locator("#authSubmit").click();
    await expect(page.locator("#authIdentity")).toHaveText("selfhosted@example.com");
    await expect(page.locator("[data-provider]:visible")).toHaveCount(0);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("email registration, sign-in errors, sign-in and logout use provider responses", async ({ page }) => {
  await configure(page);
  let invalid = true;
  await page.route("https://test-project.supabase.co/auth/v1/**", async (route) => {
    const url = route.request().url();
    if (url.endsWith("/signup")) return route.fulfill({ json: { user: { email: "person@example.com" } } });
    if (url.endsWith("/user")) return route.fulfill({ json: { id: "user-1", email: "person@example.com" } });
    if (url.endsWith("/logout")) return route.fulfill({ json: {} });
    if (invalid) return route.fulfill({ status: 400, json: { error_description: "Invalid credentials" } });
    return route.fulfill({ json: { access_token: "test-access", refresh_token: "test-refresh", expires_in: 3600 } });
  });
  await page.goto("/index.html#account");
  await page.locator("#authEmail").fill("person@example.com");
  await page.locator("#authPassword").fill("a-test-password-123");
  await page.locator("#authSubmit").click();
  await expect(page.locator("#authNotice")).toHaveText("Invalid credentials");
  await page.locator("#authMode").click();
  await page.locator("#authSubmit").click();
  await expect(page.locator("#authNotice")).toContainText("Check your email");
  await page.locator("#authMode").click();
  invalid = false;
  await page.locator("#authSubmit").click();
  await expect(page.locator("#authIdentity")).toHaveText("person@example.com");
  await expect(page.locator(".page[data-page='dashboard']")).toHaveClass(/is-active/);
  const storage = await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }));
  expect(storage).not.toContain("test-access"); expect(storage).not.toContain("test-refresh"); expect(storage).not.toContain("a-test-password");
  await page.locator(".sidebar [data-nav='account']").click();
  await expect(page.locator("#authForm")).toBeHidden();
  await expect(page.locator(".auth-providers")).toBeHidden();
  await page.locator("#authSignOut").click();
  await expect(page.locator("#authForm")).toBeVisible();
  await expect(page.locator(".sidebar")).toBeHidden();
  await page.evaluate(() => { location.hash = "#dashboard"; });
  await expect(page).toHaveURL(/#account$/);
});

for (const provider of ["google", "facebook", "github"]) {
  test(`Android ${provider} OAuth uses PKCE and exchanges a one-time callback`, async ({ page }) => {
    await configure(page);
    await page.addInitScript(() => {
      localStorage.setItem("dropsync.onboarded.v1", "true");
      window.DropSyncAndroid = { openExternal: (url) => { window.oauthUrl = url; } };
    });
    let exchange;
    await page.route("https://test-project.supabase.co/auth/v1/**", async (route) => {
      if (route.request().url().endsWith("/user")) return route.fulfill({ json: { email: "social@example.com" } });
      exchange = route.request().postDataJSON();
      return route.fulfill({ json: { access_token: "test-access", refresh_token: "test-refresh", expires_in: 3600 } });
    });
    await page.goto("/index.html#account");
    await page.locator(`[data-provider='${provider}']`).click();
    const href = await page.evaluate(() => window.oauthUrl);
    const url = new URL(href);
    expect(url.searchParams.get("provider")).toBe(provider);
    expect(url.searchParams.get("redirect_to")).toBe("dropsync://auth/callback");
    expect(url.searchParams.get("code_challenge_method")).toBe("s256");
    const challenge = await page.evaluate(async () => {
      const pending = JSON.parse(localStorage.getItem("dropsync.pkce"));
      const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(pending.verifier)));
      return btoa(String.fromCharCode(...digest)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    });
    expect(url.searchParams.get("code_challenge")).toBe(challenge);
    await page.evaluate(() => window.completeDropSyncAuth("one-time-code", ""));
    await expect(page.locator("#authIdentity")).toHaveText("social@example.com");
    expect(exchange.auth_code).toBe("one-time-code");
    expect(exchange.code_verifier.length).toBeGreaterThanOrEqual(43);
    expect(await page.evaluate(() => localStorage.getItem("dropsync.pkce"))).toBeNull();
  });
}
