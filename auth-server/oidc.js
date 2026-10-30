"use strict";
const crypto = require("node:crypto");
const ALGORITHMS = new Set(["RS256", "PS256", "ES256", "EdDSA"]);
function validateIdToken(token, keys, { issuer, clientId, nonce, now = Date.now() / 1000 }) {
  if (typeof token !== "string" || token.length > 32768) throw new Error("Invalid identity token");
  const parts = token.split("."); if (parts.length !== 3 || parts.some((part) => !/^[A-Za-z0-9_-]+$/.test(part))) throw new Error("Invalid identity token");
  const header = JSON.parse(Buffer.from(parts[0], "base64url")), payload = JSON.parse(Buffer.from(parts[1], "base64url"));
  if (!ALGORITHMS.has(header.alg) || typeof header.kid !== "string" || header.kid.length > 200 || header.crit || header.jku || header.x5u) throw new Error("Unsupported identity token header");
  if (!Array.isArray(keys) || keys.length > 64) throw new Error("Invalid identity provider keys");
  const matches = keys.filter((key) => key.kid === header.kid && (!key.use || key.use === "sig") && (!key.alg || key.alg === header.alg) && (!key.key_ops || key.key_ops.includes("verify")));
  if (matches.length !== 1 || matches[0].d) throw new Error("No unique trusted identity key");
  const jwk = matches[0], key = crypto.createPublicKey({ key: jwk, format: "jwk" });
  let options = key, algorithm = "sha256";
  if (["RS256", "PS256"].includes(header.alg)) {
    if (key.asymmetricKeyType !== "rsa" || key.asymmetricKeyDetails.modulusLength < 2048) throw new Error("Weak or mismatched identity key");
    options = { key, padding: header.alg === "PS256" ? crypto.constants.RSA_PKCS1_PSS_PADDING : crypto.constants.RSA_PKCS1_PADDING, ...(header.alg === "PS256" ? { saltLength: 32 } : {}) };
  } else if (header.alg === "ES256") {
    if (jwk.kty !== "EC" || jwk.crv !== "P-256") throw new Error("Mismatched identity key"); options = { key, dsaEncoding: "ieee-p1363" };
  } else { if (key.asymmetricKeyType !== "ed25519") throw new Error("Mismatched identity key"); algorithm = null; }
  if (!crypto.verify(algorithm, Buffer.from(parts[0] + "." + parts[1]), options, Buffer.from(parts[2], "base64url"))) throw new Error("Invalid identity token signature");
  const audience = typeof payload.aud === "string" ? [payload.aud] : payload.aud;
  if (payload.iss !== issuer || !Array.isArray(audience) || audience.length !== 1 || audience[0] !== clientId || (payload.azp !== undefined && payload.azp !== clientId)) throw new Error("Identity issuer or audience mismatch");
  if (!Number.isFinite(payload.exp) || !Number.isFinite(payload.iat) || payload.exp <= now || payload.iat > now + 60 || payload.iat < now - 600 || payload.exp <= payload.iat || (payload.nbf !== undefined && (!Number.isFinite(payload.nbf) || payload.nbf > now + 60))) throw new Error("Expired or invalid identity token time");
  if (typeof nonce !== "string" || !nonce || payload.nonce !== nonce || typeof payload.sub !== "string" || !/^[\x21-\x7e]{1,255}$/.test(payload.sub)) throw new Error("Identity nonce or subject mismatch");
  if (payload.email_verified !== true || typeof payload.email !== "string" || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(payload.email) || payload.email.length > 254) throw new Error("A verified organization email is required");
  return { id: `${issuer}\0${payload.sub}`, email: payload.email.trim().toLowerCase() };
}
class OidcClient {
  constructor(config) {
    this.config = config; const issuer = new URL(config.issuer);
    if (issuer.protocol !== "https:" || issuer.username || issuer.password || issuer.search || issuer.hash) throw new Error("OIDC issuer must be an HTTPS URL");
    this.origins = new Set([issuer.origin, ...(config.allowedOrigins || [])]);
    for (const origin of this.origins) { const url = new URL(origin); if (url.protocol !== "https:" || url.origin !== origin) throw new Error("Invalid OIDC endpoint origin"); }
  }
  checked(value) { const url = new URL(value); if (url.protocol !== "https:" || !this.origins.has(url.origin) || url.username || url.password || url.hash) throw new Error("Untrusted OIDC endpoint"); return url; }
  async json(value, options = {}) {
    const url = this.checked(value), response = await fetch(url, { ...options, redirect: "error", signal: AbortSignal.timeout(20000) });
    if (!response.ok) throw new Error("Identity provider request failed");
    const chunks = []; let size = 0;
    for await (const chunk of response.body) { size += chunk.length; if (size > 262144) { await response.body.cancel().catch(() => {}); throw new Error("Identity response exceeded limits"); } chunks.push(chunk); }
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  }
  async metadata() {
    if (this.discovery && Date.now() - this.discoveryAt < 3600000) return this.discovery;
    const metadata = await this.json(this.config.issuer.replace(/\/$/, "") + "/.well-known/openid-configuration");
    if (metadata.issuer !== this.config.issuer || !metadata.response_types_supported?.includes("code") || !metadata.code_challenge_methods_supported?.includes("S256")) throw new Error("OIDC discovery does not match the configured issuer and PKCE requirements");
    for (const key of ["authorization_endpoint", "token_endpoint", "jwks_uri"]) this.checked(metadata[key]);
    this.discovery = metadata; this.discoveryAt = Date.now(); return metadata;
  }
  async authorize(flow, state, callback) {
    const metadata = await this.metadata(), url = this.checked(metadata.authorization_endpoint);
    flow.idpVerifier = crypto.randomBytes(48).toString("base64url"); flow.nonce = crypto.randomBytes(32).toString("base64url");
    url.search = new URLSearchParams({ client_id: this.config.clientId, redirect_uri: callback, response_type: "code", scope: "openid email profile", state, nonce: flow.nonce,
      code_challenge: crypto.createHash("sha256").update(flow.idpVerifier).digest("base64url"), code_challenge_method: "S256" }).toString(); return url.href;
  }
  async identity(flow, code, callback) {
    if (typeof code !== "string" || !code || code.length > 8192) throw new Error("Invalid authorization code");
    const metadata = await this.metadata();
    const method = this.config.tokenAuthMethod || "client_secret_basic";
    const headers = { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" };
    const body = new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: callback, code_verifier: flow.idpVerifier });
    if (method === "client_secret_basic") headers.Authorization = "Basic " + Buffer.from(`${encodeURIComponent(this.config.clientId)}:${encodeURIComponent(this.config.clientSecret)}`).toString("base64");
    else if (method === "client_secret_post") { body.set("client_id", this.config.clientId); body.set("client_secret", this.config.clientSecret); }
    else throw new Error("Unsupported OIDC token authentication method");
    const tokens = await this.json(metadata.token_endpoint, { method: "POST", headers, body });
    if (!this.jwks || Date.now() - this.jwksAt > 300000) { this.jwks = (await this.json(metadata.jwks_uri)).keys; this.jwksAt = Date.now(); }
    return validateIdToken(tokens.id_token, this.jwks, { issuer: this.config.issuer, clientId: this.config.clientId, nonce: flow.nonce });
  }
}
module.exports = { OidcClient, validateIdToken };
