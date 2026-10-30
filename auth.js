"use strict";

(() => {
  const config = window.DROPSYNC_AUTH || {};
  const validUrl = (() => {
    try {
      const value = new URL(config.url || "");
      return value.protocol === "https:" || (value.protocol === "http:" && ["127.0.0.1", "localhost"].includes(value.hostname));
    } catch { return false; }
  })();
  const enabled = validUrl && Boolean(config.publishableKey);
  const selfHosted = config.type === "dropsync";
  let activeProviders = new Set(selfHosted ? [] : (config.providers || []));
  const notice = $("#authNotice");
  let session = null;
  let registering = false;
  let busy = false;
  let refreshTimer;
  let passwordEnabled = true;
  function message(text) { notice.textContent = text; }
  function setBusy(value) {
    busy = value;
    $$("#authForm button, [data-provider], #authSignOut").forEach((b) => { b.disabled = value || !enabled || Boolean(b.dataset.provider && !activeProviders.has(b.dataset.provider)); });
  }
  async function request(endpoint, body, token) {
    const response = await fetch(`${config.url}/auth/v1/${endpoint}`, {
      method: body === undefined ? "GET" : "POST",
      headers: { apikey: config.publishableKey, "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      signal: AbortSignal.timeout(20000),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.msg || data.error || data.error_description || data.message || "Sign-in request failed. Please try again.");
    return data;
  }
  function showSession(value) {
    session = value;
    window.dropSyncAccount = value?.user || null;
    window.updateDropSyncProfile?.();
    clearTimeout(refreshTimer);
    $("#authSignedIn").hidden = !value;
    $("#authForm").hidden = Boolean(value) || !passwordEnabled;
    $(".auth-providers").hidden = Boolean(value);
    $("#authIdentity").textContent = value?.user?.email || "";
    if (value) {
      message("Signed in. Device pairing and file encryption remain independent of your account.");
      refreshTimer = setTimeout(async () => {
        try { await acceptSession(await request("token?grant_type=refresh_token", { refresh_token: session.refresh_token })); }
        catch { showSession(null); window.leaveDropSyncWorkspace(); message("Session expired. Please sign in again."); }
      }, Math.max(1000, ((value.expires_in || 3600) - 60) * 1000));
    }
  }
  window.getDropSyncOrganization = async () => {
    if (!selfHosted || !session) throw new Error("Organization management requires a configured DropSync account server");
    return request("organization", undefined, session.access_token);
  };
  window.setDropSyncOrganizationRole = async (userId, role) => {
    if (!selfHosted || !session) throw new Error("Organization management requires a configured DropSync account server");
    return request("organization/members", { userId, role }, session.access_token);
  };
  window.updateDropSyncAccount = async (patch) => {
    if (!selfHosted || !session) throw new Error("Account updates require a configured DropSync account server");
    const result = await request("profile", patch, session.access_token); showSession({ ...session, user: result.user }); return result;
  };
  async function acceptSession(data) {
    if (!data.access_token) { message("Check your email to confirm your account, then sign in."); return; }
    const user = await request("user", undefined, data.access_token);
    const signingIn = !session;
    registering = false;
    $("#authSubmit").textContent = "Sign in";
    $("#authMode").textContent = "Create an account";
    $("#authPassword").autocomplete = "current-password";
    showSession({ ...data, user });
    $("#authPassword").value = "";
    if (signingIn) window.enterDropSyncWorkspace("account");
  }
  $("#authMode").onclick = () => {
    registering = !registering;
    $("#authSubmit").textContent = registering ? "Create account" : "Sign in";
    $("#authMode").textContent = registering ? "Already have an account? Sign in" : "Create an account";
    $("#authPassword").autocomplete = registering ? "new-password" : "current-password";
  };
  $("#authForm").onsubmit = async (event) => {
    event.preventDefault();
    if (!enabled || busy) return;
    setBusy(true); message(registering ? "Creating your account…" : "Signing in…");
    try {
      await acceptSession(await request(registering ? "signup" : "token?grant_type=password", {
        email: $("#authEmail").value.trim(), password: $("#authPassword").value,
      }));
    } catch (error) { message(error.message); }
    finally { setBusy(false); }
  };
  $("#authSignOut").onclick = async () => {
    const token = session?.access_token;
    showSession(null); window.leaveDropSyncWorkspace(); setBusy(true);
    try { if (token) await request("logout", {}, token); message("Signed out on this device."); }
    catch { message("Local session cleared. The remote session could not be revoked; it will expire automatically."); }
    finally { setBusy(false); }
  };
  const base64url = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  async function startProvider(provider) {
    if (!enabled || busy || !activeProviders.has(provider)) return;
    setBusy(true);
    try {
      const verifier = base64url(crypto.getRandomValues(new Uint8Array(48)));
      const challenge = base64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
      localStorage.setItem("dropsync.pkce", JSON.stringify({ verifier, expires: Date.now() + 10 * 60 * 1000 }));
      let redirect = isNativeAndroid ? "dropsync://auth/callback" : `${location.origin}/index.html`;
      if (navigator.userAgent.includes("DropSyncDesktop")) {
        const flow = await apiRequest("/api/auth/flow", { method: "POST", body: {} });
        redirect = flow.redirect;
      }
      const url = new URL(`${config.url}/auth/v1/authorize`);
      url.search = new URLSearchParams({ provider, redirect_to: redirect, code_challenge: challenge, code_challenge_method: "s256", ...(selfHosted ? { client_key: config.publishableKey } : {}) }).toString();
      if (isNativeAndroid) window.DropSyncAndroid.openExternal(url.toString());
      else if (navigator.userAgent.includes("DropSyncDesktop")) window.open(url.toString(), "_blank");
      else location.assign(url.toString());
      message("Finish signing in in your browser.");
    } catch (error) { localStorage.removeItem("dropsync.pkce"); message(error.message); }
    finally { setBusy(false); }
  }
  window.completeDropSyncAuth = async (code, error) => {
    location.hash = "#account";
    if (error) { localStorage.removeItem("dropsync.pkce"); message(error); return; }
    if (!enabled || !code) return;
    const raw = localStorage.getItem("dropsync.pkce");
    localStorage.removeItem("dropsync.pkce");
    setBusy(true);
    try {
      const pending = JSON.parse(raw || "null");
      if (!pending || pending.expires < Date.now()) throw new Error("Sign-in expired. Please start again.");
      await acceptSession(await request("token?grant_type=pkce", { auth_code: code, code_verifier: pending.verifier }));
    } catch (failure) { message(failure.message); }
    finally { setBusy(false); }
  };
  document.addEventListener("click", (event) => {
    const provider = event.target.closest("[data-provider]");
    if (provider) startProvider(provider.dataset.provider);
  });
  window.addEventListener("dropsync-auth", (event) => window.completeDropSyncAuth(event.detail.code, event.detail.error));
  setBusy(false);
  $$("[data-provider]").forEach((b) => { b.disabled = !enabled || !activeProviders.has(b.dataset.provider); });
  if (enabled && selfHosted) {
    const company = document.createElement("button"); company.type = "button"; company.className = "btn btn-secondary"; company.dataset.provider = "oidc"; company.textContent = "Company SSO"; $(".auth-providers").appendChild(company);
    $$("[data-provider]").forEach((button) => { button.hidden = true; });
    request("config").then((remote) => {
      passwordEnabled = remote.passwordEnabled !== false;
      if (!session) $("#authForm").hidden = !passwordEnabled;
      activeProviders = new Set(Array.isArray(remote.providers) ? remote.providers : []);
      $$("[data-provider]").forEach((button) => { button.hidden = !activeProviders.has(button.dataset.provider); button.disabled = !activeProviders.has(button.dataset.provider); });
      $(".auth-providers").hidden = Boolean(session) || !activeProviders.size;
    }).catch((error) => message(`Account server could not be reached: ${error.message}`));
  }
  if (!enabled) {
    $("#authForm").hidden = true;
    $(".auth-providers").hidden = true;
    $("#accountTitle").textContent = "Your devices. Your files.";
    $("#accountLede").textContent = "Share directly between your paired devices. Your files stay on your devices.";
    $("#authNotice").hidden = true;
  }
  const params = new URLSearchParams(location.search);
  if (params.has("code") || params.has("error_description")) {
    history.replaceState(null, "", `${location.pathname}#account`);
    window.completeDropSyncAuth(params.get("code"), params.get("error_description"));
  }
})();
