"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { createAuthServer } = require("../auth-server/server");

const CLIENT_KEY = "test-client-key-that-is-at-least-32-characters";

async function start(directory, overrides = {}) {
  const server = createAuthServer({
    DROPSYNC_AUTH_CLIENT_KEY: CLIENT_KEY,
    DROPSYNC_AUTH_PUBLIC_URL: "http://127.0.0.1:8787",
    DROPSYNC_AUTH_DATA_DIR: directory,
    DROPSYNC_AUTH_ALLOWED_ORIGINS: "https://appassets.androidplatform.net",
    DROPSYNC_AUTH_ALLOW_LOOPBACK: "true",
    ...overrides,
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { server, base: `http://127.0.0.1:${server.address().port}` };
}

async function request(base, endpoint, options = {}) {
  const response = await fetch(`${base}/auth/v1/${endpoint}`, {
    ...options,
    headers: {
      apikey: CLIENT_KEY,
      Origin: "https://appassets.androidplatform.net",
      "Content-Type": "application/json",
      ...options.headers,
    },
  });
  return { response, body: await response.json() };
}

test("self-hosted auth registers, signs in, rotates sessions, logs out, and persists users", async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "dropsync-auth-test-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  let running = await start(directory);
  t.after(() => running.server.close());

  let result = await request(running.base, "signup", { method: "POST", body: JSON.stringify({ email: "person@example.com", password: "short" }) });
  assert.equal(result.response.status, 400);

  result = await request(running.base, "signup", { method: "POST", body: JSON.stringify({ email: "Person@Example.com", password: "a-long-test-password" }) });
  assert.equal(result.response.status, 201);
  assert.equal(result.body.user.email, "person@example.com");
  const firstAccess = result.body.access_token;
  const firstRefresh = result.body.refresh_token;
  assert.ok(firstAccess); assert.ok(firstRefresh);

  result = await request(running.base, "user", { headers: { Authorization: `Bearer ${firstAccess}` } });
  assert.equal(result.response.status, 200);
  assert.equal(result.body.email, "person@example.com");

  result = await request(running.base, "signup", { method: "POST", body: JSON.stringify({ email: "person@example.com", password: "another-long-password" }) });
  assert.equal(result.response.status, 409);

  result = await request(running.base, "token?grant_type=password", { method: "POST", body: JSON.stringify({ email: "person@example.com", password: "wrong-password" }) });
  assert.equal(result.response.status, 401);

  result = await request(running.base, "token?grant_type=refresh_token", { method: "POST", body: JSON.stringify({ refresh_token: firstRefresh }) });
  assert.equal(result.response.status, 200);
  const rotatedAccess = result.body.access_token;
  assert.notEqual(result.body.refresh_token, firstRefresh);

  result = await request(running.base, "token?grant_type=refresh_token", { method: "POST", body: JSON.stringify({ refresh_token: firstRefresh }) });
  assert.equal(result.response.status, 401);

  result = await request(running.base, "logout", { method: "POST", headers: { Authorization: `Bearer ${rotatedAccess}` }, body: "{}" });
  assert.equal(result.response.status, 200);
  result = await request(running.base, "user", { headers: { Authorization: `Bearer ${rotatedAccess}` } });
  assert.equal(result.response.status, 401);

  await new Promise((resolve) => running.server.close(resolve));
  running = await start(directory);
  result = await request(running.base, "token?grant_type=password", { method: "POST", body: JSON.stringify({ email: "person@example.com", password: "a-long-test-password" }) });
  assert.equal(result.response.status, 200);

  const preflight = await fetch(`${running.base}/auth/v1/signup`, { method: "OPTIONS", headers: { Origin: "https://evil.example" } });
  assert.equal(preflight.status, 403);
});

test("self-hosted Google OAuth uses state and PKCE before issuing a session", async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "dropsync-auth-oauth-test-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const running = await start(directory, { GOOGLE_CLIENT_ID: "google-client", GOOGLE_CLIENT_SECRET: "google-secret" });
  t.after(() => running.server.close());
  const verifier = "v".repeat(48);
  const challenge = require("node:crypto").createHash("sha256").update(verifier).digest("base64url");
  const authorize = new URL(`${running.base}/auth/v1/authorize`);
  authorize.search = new URLSearchParams({ provider: "google", redirect_to: "dropsync://auth/callback", code_challenge: challenge, code_challenge_method: "s256", client_key: CLIENT_KEY }).toString();
  const started = await fetch(authorize, { redirect: "manual", headers: { Origin: "https://appassets.androidplatform.net" } });
  assert.equal(started.status, 302);
  const providerUrl = new URL(started.headers.get("location"));
  assert.equal(providerUrl.hostname, "accounts.google.com");
  const state = providerUrl.searchParams.get("state");
  assert.ok(state);

  const nativeFetch = global.fetch;
  global.fetch = async (url) => {
    const target = String(url);
    if (target === "https://oauth2.googleapis.com/token") return new Response(JSON.stringify({ access_token: "provider-access" }), { status: 200, headers: { "Content-Type": "application/json" } });
    if (target === "https://openidconnect.googleapis.com/v1/userinfo") return new Response(JSON.stringify({ sub: "google-user-1", email: "oauth@example.com", email_verified: true }), { status: 200, headers: { "Content-Type": "application/json" } });
    throw new Error(`Unexpected provider request: ${target}`);
  };
  let callback;
  try {
    callback = await nativeFetch(`${running.base}/auth/v1/callback/google?state=${encodeURIComponent(state)}&code=provider-code`, { redirect: "manual" });
  } finally { global.fetch = nativeFetch; }
  assert.equal(callback.status, 302);
  const applicationReturn = new URL(callback.headers.get("location"));
  assert.equal(applicationReturn.protocol, "dropsync:");
  const authCode = applicationReturn.searchParams.get("code");
  assert.ok(authCode);

  const exchanged = await request(running.base, "token?grant_type=pkce", { method: "POST", body: JSON.stringify({ auth_code: authCode, code_verifier: verifier }) });
  assert.equal(exchanged.response.status, 200);
  assert.equal(exchanged.body.user.email, "oauth@example.com");
  const replay = await request(running.base, "token?grant_type=pkce", { method: "POST", body: JSON.stringify({ auth_code: authCode, code_verifier: verifier }) });
  assert.equal(replay.response.status, 401);
});
