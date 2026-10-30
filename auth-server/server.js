"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { promisify } = require("node:util");
const recordVault = require("./record-vault");
const { OidcClient } = require("./oidc");

const scrypt = promisify(crypto.scrypt);
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]{43,128}$/;
const ACCESS_TTL_MS = 60 * 60 * 1000;
const REFRESH_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const FLOW_TTL_MS = 10 * 60 * 1000;
const BODY_LIMIT = 64 * 1024;

function csv(value) {
  return new Set(String(value || "").split(",").map((item) => item.trim()).filter(Boolean));
}

function base64url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

function token(bytes = 32) {
  return base64url(crypto.randomBytes(bytes));
}

function digest(value) {
  return crypto.createHash("sha256").update(String(value)).digest("base64url");
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function publicUser(user) {
  return { id: user.id, email: user.email, created_at: user.createdAt, providers: Object.keys(user.providers || {}), user_metadata: { display_name: user.profile?.displayName || "", avatar_url: user.profile?.avatar || "" } };
}

async function hashPassword(password, salt = crypto.randomBytes(16)) {
  const hash = await scrypt(password, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  return { salt: base64url(salt), hash: base64url(hash) };
}

async function verifyPassword(password, record) {
  if (!record?.salt || !record?.hash) return false;
  const candidate = await hashPassword(password, Buffer.from(record.salt, "base64url"));
  return safeEqual(candidate.hash, record.hash);
}

class AuthStore {
  constructor(directory, storageKey = "") {
    this.storageKey = storageKey;
    this.directory = path.resolve(directory);
    this.file = path.join(this.directory, "auth.json");
    fs.mkdirSync(this.directory, { recursive: true, mode: 0o700 });
    try { this.state = recordVault.unlock(JSON.parse(fs.readFileSync(this.file, "utf8")), storageKey); }
    catch (error) {
      if (error.code !== "ENOENT") throw error;
      this.state = { version: 1, users: [], sessions: [] };
      this.save();
    }
    if (!Array.isArray(this.state.users) || !Array.isArray(this.state.sessions)) throw new Error("Invalid auth data file");
    this.state.organizations ||= []; this.state.audit ||= [];
    if (storageKey) this.save();
    this.cleanup();
  }

  save() {
    const temporary = `${this.file}.${crypto.randomUUID()}.tmp`;
    fs.writeFileSync(temporary, `${JSON.stringify(recordVault.protect(this.state, this.storageKey), null, 2)}\n`, { mode: 0o600, flag: "wx" });
    fs.renameSync(temporary, this.file);
  }

  cleanup() {
    const now = Date.now();
    const before = this.state.sessions.length;
    this.state.sessions = this.state.sessions.filter((item) => item.refreshExpiresAt > now);
    if (before !== this.state.sessions.length) this.save();
  }

  userByEmail(email) { return this.state.users.find((item) => item.email === email) || null; }
  userById(id) { return this.state.users.find((item) => item.id === id) || null; }

  createUser(email, passwordRecord = null, provider = null) {
    const user = { id: crypto.randomUUID(), email, password: passwordRecord, providers: {}, createdAt: new Date().toISOString() };
    if (provider) user.providers[provider.name] = provider.id;
    this.state.users.push(user); this.save(); return user;
  }

  linkProvider(user, provider, providerId) {
    user.providers ||= {};
    if (user.providers[provider] !== providerId) { user.providers[provider] = providerId; this.save(); }
  }

  userByProvider(provider, providerId) {
    return this.state.users.find((item) => item.providers?.[provider] === providerId) || null;
  }

  createSession(user, authMethod = "password") {
    this.cleanup();
    const accessToken = token(32);
    const refreshToken = token(48);
    const session = {
      id: crypto.randomUUID(), userId: user.id,
      accessHash: digest(accessToken), refreshHash: digest(refreshToken),
      accessExpiresAt: Date.now() + ACCESS_TTL_MS,
      refreshExpiresAt: Date.now() + REFRESH_TTL_MS,
      createdAt: new Date().toISOString(),
      authMethod,
    };
    this.state.sessions.push(session); this.save();
    return { access_token: accessToken, refresh_token: refreshToken, expires_in: ACCESS_TTL_MS / 1000, token_type: "bearer", user: publicUser(user) };
  }

  userForAccess(accessToken) {
    const hash = digest(accessToken);
    const session = this.state.sessions.find((item) => safeEqual(item.accessHash, hash) && item.accessExpiresAt > Date.now());
    return session ? this.userById(session.userId) : null;
  }
  sessionForAccess(accessToken) { const hash = digest(accessToken); return this.state.sessions.find((item) => safeEqual(item.accessHash, hash) && item.accessExpiresAt > Date.now()) || null; }

  rotateRefresh(refreshToken, requiredMethod = null) {
    this.cleanup();
    const hash = digest(refreshToken);
    const index = this.state.sessions.findIndex((item) => safeEqual(item.refreshHash, hash) && item.refreshExpiresAt > Date.now());
    if (index < 0) return null;
    if (requiredMethod && this.state.sessions[index].authMethod !== requiredMethod) { this.state.sessions.splice(index, 1); this.save(); return null; }
    const previous = this.state.sessions[index], user = this.userById(previous.userId);
    this.state.sessions.splice(index, 1); this.save();
    return user ? this.createSession(user, previous.authMethod || "password") : null;
  }

  revokeAccess(accessToken) {
    const hash = digest(accessToken);
    const before = this.state.sessions.length;
    this.state.sessions = this.state.sessions.filter((item) => !safeEqual(item.accessHash, hash));
    if (before !== this.state.sessions.length) this.save();
  }
}

function loadConfig(overrides = {}) {
  const env = { ...process.env, ...overrides };
  const port = Number(env.DROPSYNC_AUTH_PORT || 8787);
  const publicUrl = String(env.DROPSYNC_AUTH_PUBLIC_URL || `http://127.0.0.1:${port}`).replace(/\/$/, "");
  const clientKey = String(env.DROPSYNC_AUTH_CLIENT_KEY || "");
  if (clientKey.length < 32) throw new Error("DROPSYNC_AUTH_CLIENT_KEY must contain at least 32 characters");
  const parsedPublicUrl = new URL(publicUrl);
  if (parsedPublicUrl.protocol !== "https:" && !["127.0.0.1", "localhost"].includes(parsedPublicUrl.hostname)) throw new Error("DROPSYNC_AUTH_PUBLIC_URL must use HTTPS outside localhost");
  const provider = (name) => {
    const prefix = name.toUpperCase();
    const clientId = env[`${prefix}_CLIENT_ID`];
    const clientSecret = env[`${prefix}_CLIENT_SECRET`];
    return clientId && clientSecret ? { clientId, clientSecret } : null;
  };
  const storageKey = String(env.DROPSYNC_AUTH_STORAGE_KEY || "");
  if (storageKey && Buffer.from(storageKey, "base64").length !== 32) throw new Error("DROPSYNC_AUTH_STORAGE_KEY must contain 32 random bytes in base64");
  if (!["localhost", "127.0.0.1"].includes(parsedPublicUrl.hostname) && !storageKey) throw new Error("Public account servers require DROPSYNC_AUTH_STORAGE_KEY to encrypt their records");
  const oidcValues = [env.DROPSYNC_OIDC_ISSUER, env.DROPSYNC_OIDC_CLIENT_ID, env.DROPSYNC_OIDC_CLIENT_SECRET];
  if (oidcValues.some(Boolean) && !oidcValues.every(Boolean)) throw new Error("Configure the OIDC issuer, client ID and client secret together");
  const oidc = oidcValues.every(Boolean) ? { issuer: env.DROPSYNC_OIDC_ISSUER, clientId: env.DROPSYNC_OIDC_CLIENT_ID, clientSecret: env.DROPSYNC_OIDC_CLIENT_SECRET,
    tokenAuthMethod: env.DROPSYNC_OIDC_TOKEN_AUTH_METHOD || "client_secret_basic", allowedOrigins: [...csv(env.DROPSYNC_OIDC_ALLOWED_ORIGINS)] } : null;
  const organization = env.DROPSYNC_ORG_ID ? { id: env.DROPSYNC_ORG_ID, name: String(env.DROPSYNC_ORG_NAME || env.DROPSYNC_ORG_ID).slice(0, 100), admins: csv(String(env.DROPSYNC_ORG_ADMIN_EMAILS || "").toLowerCase()), domains: csv(String(env.DROPSYNC_ORG_ALLOWED_DOMAINS || "").toLowerCase()) } : null;
  if (organization && (!/^[a-zA-Z0-9_-]{1,64}$/.test(organization.id) || !oidc)) throw new Error("Organizations require a valid ID and an OIDC identity provider");
  const requireSso = String(env.DROPSYNC_ORG_REQUIRE_SSO ?? Boolean(organization)).toLowerCase() === "true";
  if (requireSso && !oidc) throw new Error("SSO-only sign-in requires a configured OIDC identity provider");
  return {
    host: env.DROPSYNC_AUTH_HOST || "127.0.0.1", port, publicUrl, clientKey,
    dataDirectory: env.DROPSYNC_AUTH_DATA_DIR || path.join(__dirname, "data"),
    allowedOrigins: csv(env.DROPSYNC_AUTH_ALLOWED_ORIGINS || "https://appassets.androidplatform.net"),
    allowedRedirects: csv(env.DROPSYNC_AUTH_REDIRECTS || "dropsync://auth/callback,http://127.0.0.1:47821/index.html"),
    allowLoopback: String(env.DROPSYNC_AUTH_ALLOW_LOOPBACK || "true").toLowerCase() === "true",
    storageKey, organization, requireSso,
    trustProxy: env.DROPSYNC_AUTH_TRUST_PROXY === "true",
    providers: { google: provider("google"), github: provider("github"), facebook: provider("facebook"), oidc },
  };
}

function createAuthServer(overrides = {}) {
  const config = loadConfig(overrides);
  const store = new AuthStore(config.dataDirectory, config.storageKey);
  const oidc = config.providers.oidc ? new OidcClient(config.providers.oidc) : null;
  let organization = config.organization ? store.state.organizations.find((item) => item.id === config.organization.id) : null;
  if (config.organization && !organization) { organization = { id: config.organization.id, name: config.organization.name, members: [] }; store.state.organizations.push(organization); store.save(); }
  const oauthStates = new Map();
  const authCodes = new Map();
  const attempts = new Map();

  function isAllowedOrigin(origin) {
    if (!origin) return true;
    if (config.allowedOrigins.has(origin)) return true;
    if (!config.allowLoopback) return false;
    try { const value = new URL(origin); return value.protocol === "http:" && ["127.0.0.1", "localhost"].includes(value.hostname); }
    catch { return false; }
  }

  function isAllowedRedirect(value) {
    if (config.allowedRedirects.has(value)) return true;
    let url;
    try { url = new URL(value); } catch { return false; }
    if ([...config.allowedRedirects].some((allowed) => {
      try { const expected = new URL(allowed); return expected.protocol === url.protocol && expected.host === url.host && expected.pathname === url.pathname; }
      catch { return false; }
    })) return true;
    return config.allowLoopback && url.protocol === "http:" && ["127.0.0.1", "localhost"].includes(url.hostname) && ["/index.html", "/auth/callback"].includes(url.pathname);
  }

  function headers(req, extra = {}) {
    const origin = req.headers.origin;
    return {
      "Cache-Control": "no-store", "Content-Type": "application/json; charset=utf-8",
      "Cross-Origin-Resource-Policy": "cross-origin", "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
      ...(origin && isAllowedOrigin(origin) ? { "Access-Control-Allow-Origin": origin, Vary: "Origin" } : {}),
      ...extra,
    };
  }

  function json(req, res, status, payload, extra = {}) {
    const body = Buffer.from(JSON.stringify(payload));
    res.writeHead(status, { ...headers(req, extra), "Content-Length": body.length }); res.end(body);
  }

  function redirect(res, location) {
    res.writeHead(302, { Location: location, "Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff" }); res.end();
  }

  async function readBody(req) {
    const chunks = []; let size = 0;
    for await (const chunk of req) { size += chunk.length; if (size > BODY_LIMIT) throw Object.assign(new Error("Request body is too large"), { status: 413 }); chunks.push(chunk); }
    if (!chunks.length) return {};
    try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); }
    catch { throw Object.assign(new Error("Invalid JSON body"), { status: 400 }); }
  }

  function requireClient(req, url) {
    const supplied = req.headers.apikey || url.searchParams.get("client_key") || "";
    if (!safeEqual(supplied, config.clientKey)) throw Object.assign(new Error("Invalid client key"), { status: 401 });
    if (!isAllowedOrigin(req.headers.origin)) throw Object.assign(new Error("Origin is not allowed"), { status: 403 });
  }

  function bearer(req) {
    const match = String(req.headers.authorization || "").match(/^Bearer\s+(.+)$/i);
    if (!match) throw Object.assign(new Error("Authentication required"), { status: 401 });
    return match[1];
  }

  function rateLimit(req, bucket, limit = 12) {
    const forwarded = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();
    const address = (config.trustProxy && require("node:net").isIP(forwarded) ? forwarded : req.socket.remoteAddress) || "unknown";
    const key = `${bucket}:${address}`; const now = Date.now();
    const recent = (attempts.get(key) || []).filter((value) => now - value < 60_000);
    if (recent.length >= limit) throw Object.assign(new Error("Too many attempts. Try again in a minute."), { status: 429 });
    recent.push(now); attempts.set(key, recent);
  }

  function cleanupFlows() {
    const now = Date.now();
    for (const [key, value] of oauthStates) if (value.expiresAt < now) oauthStates.delete(key);
    for (const [key, value] of authCodes) if (value.expiresAt < now) authCodes.delete(key);
  }

  function organizationMember(user) { return organization?.members.find((member) => member.userId === user.id) || null; }
  function assertSessionPolicy(user, method) {
    if (config.requireSso && method !== "oidc") throw Object.assign(new Error("Use organization SSO"), { status: 403 });
    if (organization && (organizationMember(user)?.role === "suspended" || (config.requireSso && !organizationMember(user)))) throw Object.assign(new Error("An active organization membership is required"), { status: 403 });
  }
  function authenticatedUser(req) {
    const session = store.sessionForAccess(bearer(req)), user = session ? store.userById(session.userId) : null;
    if (!user) throw Object.assign(new Error("Session is invalid or expired"), { status: 401 });
    assertSessionPolicy(user, session.authMethod); return user;
  }
  function requireOrganization(req) {
    const access = bearer(req), session = store.sessionForAccess(access), user = session ? store.userById(session.userId) : null;
    const member = user ? organizationMember(user) : null;
    if (!user || session.authMethod !== "oidc" || !member || member.role === "suspended") throw Object.assign(new Error("An active organization SSO session is required"), { status: 403 });
    return { user, member };
  }
  function provisionOrganization(user, email) {
    if (!organization) return;
    if (config.organization.domains.size && !config.organization.domains.has(email.split("@")[1])) throw new Error("Your email domain is not allowed in this organization");
    let member = organizationMember(user);
    if (!member) { member = { userId: user.id, role: config.organization.admins.has(email) ? "admin" : "member" }; organization.members.push(member); store.save(); }
    if (member.role === "suspended") throw new Error("Organization membership is suspended");
  }

  function oauthError(flow, message) {
    const target = new URL(flow.redirect);
    target.searchParams.set("error_description", message); return target.toString();
  }

  async function providerIdentity(provider, code) {
    const credentials = config.providers[provider];
    const callback = `${config.publicUrl}/auth/v1/callback/${provider}`;
    if (provider === "google") {
      const tokenResponse = await fetch("https://oauth2.googleapis.com/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ code, client_id: credentials.clientId, client_secret: credentials.clientSecret, redirect_uri: callback, grant_type: "authorization_code" }), signal: AbortSignal.timeout(20_000) });
      const tokens = await tokenResponse.json(); if (!tokenResponse.ok) throw new Error("Google token exchange failed");
      const profileResponse = await fetch("https://openidconnect.googleapis.com/v1/userinfo", { headers: { Authorization: `Bearer ${tokens.access_token}` }, signal: AbortSignal.timeout(20_000) });
      const profile = await profileResponse.json();
      if (!profileResponse.ok || !profile.email || profile.email_verified === false) throw new Error("Google did not return a verified email address");
      return { id: String(profile.sub), email: normalizeEmail(profile.email) };
    }
    if (provider === "github") {
      const tokenResponse = await fetch("https://github.com/login/oauth/access_token", { method: "POST", headers: { Accept: "application/json", "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "DropSync-Auth" }, body: new URLSearchParams({ code, client_id: credentials.clientId, client_secret: credentials.clientSecret, redirect_uri: callback }), signal: AbortSignal.timeout(20_000) });
      const tokens = await tokenResponse.json(); if (!tokenResponse.ok || !tokens.access_token) throw new Error("GitHub token exchange failed");
      const common = { Authorization: `Bearer ${tokens.access_token}`, Accept: "application/vnd.github+json", "User-Agent": "DropSync-Auth", "X-GitHub-Api-Version": "2022-11-28" };
      const [profileResponse, emailsResponse] = await Promise.all([fetch("https://api.github.com/user", { headers: common, signal: AbortSignal.timeout(20_000) }), fetch("https://api.github.com/user/emails", { headers: common, signal: AbortSignal.timeout(20_000) })]);
      const profile = await profileResponse.json(); const emails = await emailsResponse.json();
      const email = Array.isArray(emails) ? emails.find((item) => item.primary && item.verified)?.email || emails.find((item) => item.verified)?.email : null;
      if (!profileResponse.ok || !emailsResponse.ok || !profile.id || !email) throw new Error("GitHub did not return a verified email address");
      return { id: String(profile.id), email: normalizeEmail(email) };
    }
    if (provider === "facebook") {
      const tokenUrl = new URL("https://graph.facebook.com/v21.0/oauth/access_token");
      tokenUrl.search = new URLSearchParams({ client_id: credentials.clientId, client_secret: credentials.clientSecret, redirect_uri: callback, code }).toString();
      const tokenResponse = await fetch(tokenUrl, { signal: AbortSignal.timeout(20_000) }); const tokens = await tokenResponse.json();
      if (!tokenResponse.ok || !tokens.access_token) throw new Error("Facebook token exchange failed");
      const profileUrl = new URL("https://graph.facebook.com/me"); profileUrl.search = new URLSearchParams({ fields: "id,email", access_token: tokens.access_token }).toString();
      const profileResponse = await fetch(profileUrl, { signal: AbortSignal.timeout(20_000) }); const profile = await profileResponse.json();
      if (!profileResponse.ok || !profile.id || !profile.email) throw new Error("Facebook did not return an email address");
      return { id: String(profile.id), email: normalizeEmail(profile.email) };
    }
    throw new Error("Unsupported provider");
  }

  async function providerAuthorizeUrl(provider, state) {
    const credentials = config.providers[provider];
    const callback = `${config.publicUrl}/auth/v1/callback/${provider}`;
    if (provider === "oidc") return oidc.authorize(oauthStates.get(state), state, callback);
    if (provider === "google") {
      const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
      url.search = new URLSearchParams({ client_id: credentials.clientId, redirect_uri: callback, response_type: "code", scope: "openid email profile", state, prompt: "select_account" }).toString(); return url.toString();
    }
    if (provider === "github") {
      const url = new URL("https://github.com/login/oauth/authorize");
      url.search = new URLSearchParams({ client_id: credentials.clientId, redirect_uri: callback, scope: "read:user user:email", state }).toString(); return url.toString();
    }
    const url = new URL("https://www.facebook.com/v21.0/dialog/oauth");
    url.search = new URLSearchParams({ client_id: credentials.clientId, redirect_uri: callback, response_type: "code", scope: "email", state }).toString(); return url.toString();
  }

  async function route(req, res) {
    const url = new URL(req.url, config.publicUrl);
    if (req.method === "OPTIONS") {
      if (!isAllowedOrigin(req.headers.origin)) return json(req, res, 403, { error: "Origin is not allowed" });
      res.writeHead(204, headers(req, { "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Allow-Headers": "authorization, content-type, apikey", "Access-Control-Max-Age": "600" })); return res.end();
    }
    if (req.method === "GET" && url.pathname === "/healthz") return json(req, res, 200, { ok: true });
    if (req.method === "GET" && url.pathname === "/auth/v1/config") {
      requireClient(req, url);
      return json(req, res, 200, { providers: Object.entries(config.providers).filter(([name, value]) => value && (!config.requireSso || name === "oidc")).map(([name]) => name), passwordEnabled: !config.requireSso, organization: config.organization ? { id: config.organization.id, name: config.organization.name } : null });
    }
    if (req.method === "POST" && url.pathname === "/auth/v1/signup") {
      if (config.requireSso) throw Object.assign(new Error("Use your organization SSO account"), { status: 403 });
      requireClient(req, url); rateLimit(req, "signup", 6);
      const body = await readBody(req); const email = normalizeEmail(body.email); const password = String(body.password || "");
      if (!EMAIL_PATTERN.test(email) || email.length > 254) throw Object.assign(new Error("Enter a valid email address"), { status: 400 });
      if (password.length < 10 || password.length > 128) throw Object.assign(new Error("Password must contain 10–128 characters"), { status: 400 });
      if (store.userByEmail(email)) throw Object.assign(new Error("An account with this email already exists"), { status: 409 });
      const user = store.createUser(email, await hashPassword(password));
      return json(req, res, 201, store.createSession(user));
    }
    if (req.method === "POST" && url.pathname === "/auth/v1/token" && url.searchParams.get("grant_type") === "password") {
      if (config.requireSso) throw Object.assign(new Error("Use your organization SSO account"), { status: 403 });
      requireClient(req, url); rateLimit(req, "password", 10);
      const body = await readBody(req); const user = store.userByEmail(normalizeEmail(body.email));
      const password = String(body.password || "");
      const valid = user ? await verifyPassword(password, user.password) : (await hashPassword(password, Buffer.alloc(16, 0)), false);
      if (!user || !valid) throw Object.assign(new Error("Invalid email or password"), { status: 401 });
      return json(req, res, 200, store.createSession(user));
    }
    if (req.method === "POST" && url.pathname === "/auth/v1/token" && url.searchParams.get("grant_type") === "refresh_token") {
      requireClient(req, url); rateLimit(req, "refresh", 30);
      const body = await readBody(req); const session = store.rotateRefresh(String(body.refresh_token || ""), config.requireSso ? "oidc" : null);
      if (!session) throw Object.assign(new Error("Refresh token is invalid or expired"), { status: 401 });
      try { authenticatedUser({ headers: { authorization: `Bearer ${session.access_token}` } }); } catch (error) { store.revokeAccess(session.access_token); throw error; }
      return json(req, res, 200, session);
    }
    if (req.method === "POST" && url.pathname === "/auth/v1/token" && url.searchParams.get("grant_type") === "pkce") {
      requireClient(req, url); rateLimit(req, "pkce", 20); cleanupFlows();
      const body = await readBody(req); const flow = authCodes.get(String(body.auth_code || "")); authCodes.delete(String(body.auth_code || ""));
      const verifier = String(body.code_verifier || "");
      if (!flow || flow.expiresAt < Date.now() || !BASE64URL_PATTERN.test(verifier) || !safeEqual(base64url(crypto.createHash("sha256").update(verifier).digest()), flow.challenge)) throw Object.assign(new Error("Authorization code is invalid or expired"), { status: 401 });
      const user = store.userById(flow.userId); if (!user) throw Object.assign(new Error("Account no longer exists"), { status: 401 });
      assertSessionPolicy(user, flow.authMethod);
      return json(req, res, 200, store.createSession(user, flow.authMethod || "password"));
    }
    if (req.method === "GET" && url.pathname === "/auth/v1/user") {
      requireClient(req, url); const user = authenticatedUser(req);
      return json(req, res, 200, publicUser(user));
    }
    if (req.method === "POST" && url.pathname === "/auth/v1/profile") {
      requireClient(req, url); rateLimit(req, "profile", 12); const user = authenticatedUser(req);
      const body = await readBody(req), displayName = String(body.displayName || "").trim(), avatar = String(body.avatar || "");
      if (displayName.length > 80 || (avatar && !/^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+/=]{1,48000}$/.test(avatar))) throw Object.assign(new Error("Invalid account profile"), { status: 400 });
      user.profile = { displayName, avatar }; store.save(); return json(req, res, 200, { user: publicUser(user) });
    }
    if (req.method === "GET" && url.pathname === "/auth/v1/organization") {
      requireClient(req, url); const { member } = requireOrganization(req);
      return json(req, res, 200, { organization: { id: organization.id, name: organization.name }, role: member.role,
        ...(member.role === "admin" ? { members: organization.members.map((item) => ({ userId: item.userId, email: store.userById(item.userId)?.email || "Deleted account", role: item.role })) } : {}) });
    }
    if (req.method === "POST" && url.pathname === "/auth/v1/organization/members") {
      requireClient(req, url); rateLimit(req, "organization", 12); const { user, member } = requireOrganization(req);
      if (member.role !== "admin") throw Object.assign(new Error("Administrator access is required"), { status: 403 });
      const body = await readBody(req), target = organization.members.find((item) => item.userId === body.userId);
      if (!target || !["admin", "member", "suspended"].includes(body.role)) throw Object.assign(new Error("Invalid organization member or role"), { status: 400 });
      if (target.role === "admin" && body.role !== "admin" && organization.members.filter((item) => item.role === "admin").length < 2) throw Object.assign(new Error("Keep at least one organization administrator"), { status: 409 });
      target.role = body.role; if (target.role === "suspended") store.state.sessions = store.state.sessions.filter((session) => session.userId !== target.userId);
      store.state.audit.push({ at: new Date().toISOString(), actor: user.id, event: "organization-role-changed", target: target.userId, role: target.role }); store.state.audit = store.state.audit.slice(-500); store.save(); return json(req, res, 200, { ok: true });
    }
    if (req.method === "POST" && url.pathname === "/auth/v1/logout") {
      requireClient(req, url); store.revokeAccess(bearer(req)); return json(req, res, 200, {});
    }
    if (req.method === "GET" && url.pathname === "/auth/v1/authorize") {
      requireClient(req, url); rateLimit(req, "oauth", 20); cleanupFlows();
      const provider = url.searchParams.get("provider"); const redirectTo = url.searchParams.get("redirect_to"); const challenge = url.searchParams.get("code_challenge");
      if (!config.providers[provider]) throw Object.assign(new Error("OAuth provider is not configured"), { status: 400 });
      if (!isAllowedRedirect(redirectTo) || !BASE64URL_PATTERN.test(challenge || "") || url.searchParams.get("code_challenge_method") !== "s256") throw Object.assign(new Error("Invalid OAuth redirect or PKCE challenge"), { status: 400 });
      if (config.requireSso && provider !== "oidc") throw Object.assign(new Error("Use organization SSO"), { status: 403 });
      if (oauthStates.size >= 500) throw Object.assign(new Error("Too many pending sign-ins"), { status: 429 });
      const state = token(32); oauthStates.set(state, { provider, redirect: redirectTo, challenge, expiresAt: Date.now() + FLOW_TTL_MS });
      return redirect(res, await providerAuthorizeUrl(provider, state));
    }
    const callback = url.pathname.match(/^\/auth\/v1\/callback\/(google|github|facebook|oidc)$/);
    if (req.method === "GET" && callback) {
      cleanupFlows(); const state = url.searchParams.get("state"); const flow = oauthStates.get(state); oauthStates.delete(state);
      if (!flow || flow.provider !== callback[1] || flow.expiresAt < Date.now()) return json(req, res, 400, { error: "OAuth flow is invalid or expired" });
      if (url.searchParams.get("error")) return redirect(res, oauthError(flow, url.searchParams.get("error_description") || "Sign-in was cancelled"));
      try {
        const identity = flow.provider === "oidc" ? await oidc.identity(flow, url.searchParams.get("code"), `${config.publicUrl}/auth/v1/callback/oidc`) : await providerIdentity(flow.provider, url.searchParams.get("code"));
        if (flow.provider === "oidc" && organization && config.organization.domains.size && !config.organization.domains.has(identity.email.split("@")[1])) throw new Error("Your email domain is not allowed in this organization");
        let user = store.userByProvider(flow.provider, identity.id);
        const existingEmail = store.userByEmail(identity.email);
        if (user && user.email !== identity.email) { if (existingEmail && existingEmail.id !== user.id) throw new Error("This email is already assigned to another account"); user.email = identity.email; store.save(); }
        if (!user && existingEmail) {
          if (flow.provider !== "oidc" || !organization) throw new Error("An account already uses this email. Use its existing sign-in method.");
          user = existingEmail; user.password = null; store.state.sessions = store.state.sessions.filter((session) => session.userId !== user.id);
        }
        if (!user) user = store.createUser(identity.email, null, { name: flow.provider, id: identity.id });
        else store.linkProvider(user, flow.provider, identity.id);
        if (flow.provider === "oidc") provisionOrganization(user, identity.email);
        const code = token(32); authCodes.set(code, { userId: user.id, authMethod: flow.provider, challenge: flow.challenge, expiresAt: Date.now() + FLOW_TTL_MS });
        const target = new URL(flow.redirect); target.searchParams.set("code", code); return redirect(res, target.toString());
      } catch (error) { return redirect(res, oauthError(flow, error.message || "Provider sign-in failed")); }
    }
    return json(req, res, 404, { error: "Not found" });
  }

  const server = http.createServer((req, res) => route(req, res).catch((error) => {
    if (error.status >= 500 || !error.status) console.error(error);
    if (!res.headersSent) json(req, res, error.status || 500, { error: error.status ? error.message : "Internal server error" }); else res.destroy();
  }));
  server.authConfig = config;
  return server;
}

if (require.main === module) {
  const server = createAuthServer();
  const { host, port, publicUrl } = server.authConfig;
  server.listen(port, host, () => console.log(`DropSync Auth listening on ${host}:${port} (${publicUrl})`));
  const shutdown = () => server.close(() => process.exit(0));
  process.on("SIGINT", shutdown); process.on("SIGTERM", shutdown);
}

module.exports = { AuthStore, createAuthServer, hashPassword, loadConfig, verifyPassword };
