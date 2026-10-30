"use strict";

(() => {
  const project = window.DROPSYNC_PROJECT;
  const television = isNativeAndroid && window.DropSyncAndroid?.isTelevision?.();
  document.documentElement.classList.toggle("tv-mode", Boolean(television));
  if (television) document.addEventListener("keydown", (event) => {
    if (event.defaultPrevented) return;
    if (!["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown"].includes(event.key) || /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName)) return;
    const scope = [...document.querySelectorAll(".overlay:not([hidden])")].at(-1) || document;
    const controls = [...scope.querySelectorAll("button:not(:disabled), a[href], input:not(:disabled), textarea, select, [tabindex='0']")].filter((element) => element.getClientRects().length && !element.closest("[hidden]"));
    const current = document.activeElement, rect = current?.getBoundingClientRect(), x = rect ? rect.left + rect.width / 2 : 0, y = rect ? rect.top + rect.height / 2 : 0;
    const horizontal = event.key === "ArrowLeft" || event.key === "ArrowRight", direction = event.key === "ArrowLeft" || event.key === "ArrowUp" ? -1 : 1;
    const nearest = controls.filter((element) => element !== current).map((element) => { const box = element.getBoundingClientRect(), dx = box.left + box.width / 2 - x, dy = box.top + box.height / 2 - y; return { element, along: (horizontal ? dx : dy) * direction, across: Math.abs(horizontal ? dy : dx) }; }).filter((item) => item.along > 1).sort((a, b) => (a.along + a.across * 3) - (b.along + b.across * 3))[0];
    if (nearest) { event.preventDefault(); nearest.element.focus(); nearest.element.scrollIntoView({ block: "nearest" }); }
  });
  function settingsShell(cat, pane, content) {
    pane.innerHTML = `<div class="set-header"><h4>${escapeHTML(cat.title)}</h4><p>${escapeHTML(cat.desc)}</p></div>${content}`;
  }
  async function saveSettings(patch) {
    const result = await apiRequest("/api/settings", { method: "PUT", body: patch });
    runtimeState.settings = result.settings; window.updateDropSyncProfile(); hydrateSettingsControls(); return result;
  }
  const showError = (error) => toast("Could not complete this action", error.message, "error");
  window.renderDropSyncSettings = async (cat, pane) => {
    if (cat.custom === "project-about") {
      settingsShell(cat, pane, `<article class="project-about"><span class="eyebrow">DROPSYNC ${escapeHTML(runtimeState.version || "0.7.0")}</span><h2>Your devices, connected.</h2><p>${escapeHTML(project.purpose)}</p>
        <dl class="about-facts"><div><dt>Project owner</dt><dd>${escapeHTML(project.owner)}</dd></div><div><dt>Built for</dt><dd>Windows · macOS · Linux · Android</dd></div><div><dt>Connections</dt><dd>Local network and your Tailscale network</dd></div><div><dt>License</dt><dd>${escapeHTML(project.license)}</dd></div></dl>
        <h3>Credits</h3><p>Product direction and ownership: ${escapeHTML(project.owner)}. Built with Node.js, Electron, Android and Bouncy Castle. Third-party components retain their own licenses.</p>
        <p class="muted">Free noncommercial use. Commercial rights are reserved to ${escapeHTML(project.owner)} or require separate written permission.</p><div class="update-actions"><button class="btn btn-secondary" data-feature-action="license">Read license</button><span id="projectRepository"></span></div></article>`);
      const target = pane.querySelector("#projectRepository");
      try { const url = new URL(project.repository); if (url.protocol === "https:" && url.hostname === "github.com" && !url.username && !url.password) { const link = document.createElement("a"); link.className = "btn btn-secondary"; link.textContent = "GitHub project"; link.href = url.href; link.target = "_blank"; link.rel = "noopener noreferrer"; target.appendChild(link); } }
      catch { target.textContent = "GitHub repository will appear here when configured."; target.className = "muted"; }
    } else if (cat.custom === "api") {
      settingsShell(cat, pane, `<div class="integration-card"><div class="integration-title"><h3>VirusTotal</h3><span id="vtConfigured" class="badge badge-neutral">Loading…</span></div>
        <p>Hash checks share the file’s SHA-256 and your IP address with VirusTotal. Files are kept private unless you separately enable content uploads below.</p>
        <form id="vtKeyForm" class="feature-form"><label for="vtKey">Your API key</label><input class="input" id="vtKey" type="password" autocomplete="off" maxlength="64" spellcheck="false" placeholder="Enter a new key; the saved key is never shown"><div class="update-actions"><button class="btn btn-secondary" type="submit">Save API key</button><button class="btn btn-ghost" type="button" id="vtRemove">Remove key</button></div></form></div>
        <div class="set-group"><h5>Checking policy</h5><div class="set-block">${[
          ["toggle", "Enable VirusTotal checks", "Check files before sending and before publishing received files", 0],
          ["toggle", "Block files without a report", "Unknown files and incomplete analyses stay blocked. API errors also stop the transfer.", 1],
          ["toggle", "Upload unknown files for analysis", "Send the full contents of unknown files up to 32 MiB to VirusTotal. Enable only if you accept sharing those contents with the provider.", 0],
        ].map(controlHTML).join("")}</div></div><p class="muted integration-note">Reports may be incomplete or stale. A report with no detections is not a guarantee that a file is safe.</p>`);
      hydrateSettingsControls();
      const badge = pane.querySelector("#vtConfigured"), input = pane.querySelector("#vtKey");
      const status = (value) => { if (badge.isConnected) badge.textContent = value.configured ? value.persisted === false ? "Key set · this session only" : "Key stored securely" : "No API key"; };
      pane.querySelector("#vtKeyForm").onsubmit = async (event) => {
        event.preventDefault(); if (!input.value.trim()) return;
        try { status(await apiRequest("/api/security/virustotal/key", { method: "POST", body: { key: input.value.trim() } })); input.value = ""; toast("API key saved", "The key is not exposed to other devices", "success"); } catch (error) { showError(error); }
      };
      pane.querySelector("#vtRemove").onclick = async () => { try { status(await apiRequest("/api/security/virustotal/key", { method: "POST", body: { key: "" } })); input.value = ""; } catch (error) { showError(error); } };
      try { status(await apiRequest("/api/security/virustotal")); } catch (error) { if (badge.isConnected) badge.textContent = error.message; }
    } else if (cat.custom === "profile") {
      const profile = runtimeState.settings?.profile || {};
      settingsShell(cat, pane, `<form class="feature-form profile-form" id="profileForm"><div class="profile-editor-avatar" id="profileAvatarPreview"></div><label for="profileName">Display name</label><input class="input" id="profileName" maxlength="80" value="${escapeHTML(profile.displayName || "")}" placeholder="Your name"><label for="profileAvatarFile">Avatar image</label><input class="input" id="profileAvatarFile" type="file" accept="image/png,image/jpeg,image/webp"><p class="muted">Your profile stays on this device. Avatar files are resized before saving.</p><div class="update-actions"><button class="btn btn-primary" type="submit">Save profile</button><button class="btn btn-ghost" type="button" id="removeAvatar">Remove avatar</button></div></form><section class="account-summary" id="profileAccount"></section>`);
      let avatar = profile.avatar || "";
      const preview = pane.querySelector("#profileAvatarPreview");
      const paint = () => { preview.replaceChildren(); if (avatar) { const img = document.createElement("img"); img.src = avatar; img.alt = "Your avatar"; preview.appendChild(img); } else preview.textContent = initials(pane.querySelector("#profileName").value || runtimeState.self?.name); };
      pane.querySelector("#profileName").oninput = paint; paint();
      pane.querySelector("#removeAvatar").onclick = () => { avatar = ""; paint(); };
      pane.querySelector("#profileAvatarFile").onchange = async (event) => {
        try {
          const file = event.target.files?.[0]; if (!file) return;
          if (file.size > 2 * 1024 * 1024 || !/^image\/(png|jpeg|webp)$/.test(file.type)) throw new Error("Choose a PNG, JPEG or WebP image up to 2 MiB");
          const bitmap = await createImageBitmap(file, { resizeWidth: 128, resizeHeight: 128, resizeQuality: "high" });
          const canvas = document.createElement("canvas"); canvas.width = 128; canvas.height = 128; canvas.getContext("2d").drawImage(bitmap, 0, 0, 128, 128); bitmap.close(); avatar = canvas.toDataURL("image/png"); paint();
        } catch (error) { showError(error); }
      };
      pane.querySelector("#profileForm").onsubmit = async (event) => { event.preventDefault(); try { await saveSettings({ profile: { displayName: pane.querySelector("#profileName").value.trim(), avatar } }); toast("Profile saved", "Stored on this device", "success"); } catch (error) { showError(error); } };
      const account = pane.querySelector("#profileAccount");
      const title = document.createElement("h3"); title.textContent = "Account";
      const identity = document.createElement("p"); identity.textContent = window.dropSyncAccount?.email || "You are using DropSync without an account.";
      const button = document.createElement("button"); button.type = "button"; button.className = "btn btn-secondary"; button.textContent = "Account settings"; button.onclick = () => { closeModal($("#ov-settings")); location.hash = "#account"; };
      account.append(title, identity, button);
      if (window.dropSyncAccount && window.updateDropSyncAccount) {
        const save = document.createElement("button"); save.type = "button"; save.className = "btn btn-secondary"; save.textContent = "Save this profile to my account";
        save.onclick = async () => { save.disabled = true; try { await window.updateDropSyncAccount({ displayName: pane.querySelector("#profileName").value.trim(), avatar }); toast("Account profile saved", "Your account server received this name and avatar", "success"); } catch (error) { showError(error); } finally { save.disabled = false; } }; account.appendChild(save);
      }
    } else if (cat.custom === "tailscale") {
      settingsShell(cat, pane, `<article class="integration-card"><h3>Your devices, wherever you are</h3><p>Install Tailscale on this device and your home computer, sign in to the same tailnet, and keep DropSync running at home. No public port forwarding or DropSync relay is needed.</p><p>Allow TCP port 47821 between your devices in your tailnet policy and firewall. Pairing and file encryption remain required.</p><form id="tailscaleForm" class="feature-form"><label for="tailscaleAddress">Other device’s Tailscale address</label><input class="input mono" id="tailscaleAddress" placeholder="100.80.1.2:47821 or computer.tailnet.ts.net" required maxlength="280"><button class="btn btn-secondary" type="submit">Find device</button><p id="tailscaleResult" role="status"></p></form><a class="product-link" href="https://tailscale.com/download" target="_blank" rel="noopener noreferrer">Get Tailscale</a></article>`);
      pane.querySelector("#tailscaleForm").onsubmit = async (event) => {
        event.preventDefault(); const resultNode = pane.querySelector("#tailscaleResult"); resultNode.textContent = "Connecting…";
        try {
          const result = await apiRequest("/api/devices/manual", { method: "POST", body: { address: pane.querySelector("#tailscaleAddress").value.trim() } });
          resultNode.textContent = `${result.device.name} found. ${result.device.trusted ? "This device is already paired." : "Compare fingerprints and pair to continue."}`;
          if (!result.device.trusted) {
            const pair = document.createElement("button"); pair.type = "button"; pair.className = "btn btn-primary"; pair.textContent = "Pair this device";
            pair.onclick = () => { closeModal($("#ov-settings")); runtimeState.pendingPairDeviceId = result.device.deviceId; $("#pairTargetName").textContent = result.device.name; $("#pairTargetFingerprint").textContent = result.device.fingerprint; $("#pairTarget").hidden = false; $("#pairConfirm").hidden = false; $("#pairCodeInput").value = ""; openModal("pairing"); };
            resultNode.appendChild(pair);
          }
        } catch (error) { resultNode.textContent = error.message; }
      };
    } else if (cat.custom === "organization") {
      const managed = runtimeState.managedSettings || [];
      settingsShell(cat, pane, `<article class="integration-card"><h3>Managed device policy</h3><p>${managed.length ? `${managed.length} setting(s) are controlled by your administrator. Locked settings cannot be changed here.` : "This installation has no managed policy. You control its local settings."}</p><p>Company sign-in uses an organization identity provider. OIDC is the standard connection used for company accounts; your administrator supplies its configuration. Organization roles never replace local device pairing.</p><div id="organizationStatus" role="status"></div></article>`);
      const status = pane.querySelector("#organizationStatus");
      if (window.getDropSyncOrganization && window.dropSyncAccount) {
        try { const result = await window.getDropSyncOrganization(); if (status.isConnected) renderOrganization(status, result); } catch (error) { if (status.isConnected) status.textContent = error.message; }
      } else status.textContent = "Sign in to a configured organization account to see membership and roles.";
    }
  };
  function renderOrganization(node, result) {
    const text = document.createElement("p"); text.textContent = result.organization ? `${result.organization.name} · your role: ${result.role}` : "Your account is not assigned to an organization."; node.replaceChildren(text);
    if (Array.isArray(result.members)) for (const member of result.members) {
      const row = document.createElement("div"); row.className = "organization-member"; const label = document.createElement("span"); label.textContent = member.email;
      const role = document.createElement("select"); role.className = "input"; role.setAttribute("aria-label", "Role for " + member.email);
      for (const value of ["member", "admin", "suspended"]) { const option = document.createElement("option"); option.value = value; option.textContent = value; role.appendChild(option); } role.value = member.role;
      role.onchange = async () => { role.disabled = true; try { await window.setDropSyncOrganizationRole(member.userId, role.value); member.role = role.value; toast("Organization role updated", "Enforced by the account server", "success"); } catch (error) { role.value = member.role; showError(error); } finally { role.disabled = false; } };
      row.append(label, role); node.appendChild(row);
    }
  }
  function initials(name) { return String(name || "DropSync").trim().split(/\s+/).map((part) => part[0]).slice(0, 2).join("").toUpperCase(); }
  const previews = new Map(), previewTargets = new WeakMap(), previewQueue = [];
  let previewing = 0;
  const previewObserver = new IntersectionObserver((entries) => {
    for (const entry of entries) if (entry.isIntersecting) { previewObserver.unobserve(entry.target); previewQueue.push(entry.target); }
    pumpPreviews();
  }, { rootMargin: "200px" });
  window.resetDropSyncPreviews = () => { previewObserver.disconnect(); previewQueue.length = 0; };
  window.loadDropSyncPreview = (image, transfer) => { previewTargets.set(image, transfer); previewObserver.observe(image); };
  async function pumpPreviews() {
    while (previewing < 2 && previewQueue.length) {
      const image = previewQueue.shift(); if (!image.isConnected) continue;
      const transfer = previewTargets.get(image); if (!transfer) continue;
      if (previews.has(transfer.id)) { image.src = previews.get(transfer.id); image.parentElement.classList.add("has-preview"); continue; }
      previewing++;
      (async () => {
        try {
          let dataUrl;
          if (isNativeAndroid) dataUrl = (await apiRequest(`/api/received/${encodeURIComponent(transfer.id)}/thumbnail`)).dataUrl;
          else {
            const response = await fetch(`/api/received/${encodeURIComponent(transfer.id)}/preview`);
            if (!response.ok) return;
            const width = Number(response.headers.get("X-Image-Width")), height = Number(response.headers.get("X-Image-Height"));
            if (!width || !height || width * height > 16000000 || Number(response.headers.get("Content-Length")) > 20 * 1024 ** 2) return;
            const blob = await response.blob(); if (blob.size > 20 * 1024 ** 2) return;
            const scale = Math.min(1, 320 / width, 200 / height);
            const bitmap = await createImageBitmap(blob, { resizeWidth: Math.max(1, Math.round(width * scale)), resizeHeight: Math.max(1, Math.round(height * scale)), resizeQuality: "low" });
            const canvas = document.createElement("canvas"); canvas.width = bitmap.width; canvas.height = bitmap.height; canvas.getContext("2d").drawImage(bitmap, 0, 0); bitmap.close(); dataUrl = canvas.toDataURL("image/jpeg", 0.75);
          }
          if (typeof dataUrl !== "string" || !dataUrl.startsWith("data:image/jpeg;base64,")) return;
          if (previews.size >= 128) previews.delete(previews.keys().next().value); previews.set(transfer.id, dataUrl);
          if (image.isConnected) { image.src = dataUrl; image.parentElement.classList.add("has-preview"); }
        } catch { /* Non-image or oversized files retain their file icon. */ }
        finally { previewing--; pumpPreviews(); }
      })();
    }
  }
  function notifications() {
    if (!isNativeAndroid) return runtimeState.notifications || [];
    const readAt = Number(runtimeState.settings?.ui?.["notifications-read-at"] || 0), clearAt = Number(runtimeState.settings?.ui?.["notifications-clear-at"] || 0);
    const events = runtimeState.transfers.filter((item) => ["completed", "failed", "retrying"].includes(item.status)).map((item) => ({
      id: item.id, transferId: item.id, kind: item.status, title: item.status === "completed" ? "Transfer completed" : item.status === "retrying" ? "Reconnecting" : "Transfer interrupted",
      message: item.fileName + (item.error ? ": " + item.error : ""), createdAt: item.updatedAt || item.createdAt, canRetry: item.status === "failed" && item.direction === "send",
    }));
    for (const request of runtimeState.incomingRequests || []) events.push({ id: request.id, transferId: request.id, kind: "incoming", title: "Incoming file", message: `${request.fileName} from ${request.deviceName}`, createdAt: new Date(request.expiresAt - 90000).toISOString() });
    return events.filter((item) => Date.parse(item.createdAt) > clearAt).map((item) => ({ ...item, read: Date.parse(item.createdAt) <= readAt })).sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt)).slice(0, 100);
  }
  window.renderDropSyncNotifications = () => {
    const list = $("#notifList"), items = notifications(); if (!list) return; list.replaceChildren();
    const unread = items.filter((item) => !item.read).length; $("#bellBadge").textContent = unread > 99 ? "99+" : String(unread); $("#bellBadge").style.display = unread ? "" : "none";
    if (!items.length) { const empty = document.createElement("li"); empty.className = "notif-empty"; empty.textContent = "No transfer notifications yet."; list.appendChild(empty); return; }
    for (const item of items.slice(0, 30)) {
      const row = document.createElement("li"); row.className = "runtime-notification" + (item.read ? "" : " is-unread");
      const body = document.createElement("div"), title = document.createElement("strong"), text = document.createElement("p"), time = document.createElement("time");
      title.textContent = item.title; text.textContent = item.message; time.textContent = new Date(item.createdAt).toLocaleString(); body.append(title, text, time); row.appendChild(body);
      if (item.kind === "incoming") { const button = document.createElement("button"); button.className = "btn btn-secondary btn-xs"; button.textContent = "Review"; button.onclick = () => { $("#notifPopover").hidden = true; openModal("incoming"); }; row.appendChild(button); }
      else if (item.canRetry) { const button = document.createElement("button"); button.className = "btn btn-secondary btn-xs"; button.textContent = "Retry"; button.onclick = async () => { button.disabled = true; try { await apiRequest(`/api/transfers/${encodeURIComponent(item.transferId)}/retry`, { method: "POST" }); toast("Retry queued", "The original file and device will be verified again", "info"); } catch (error) { showError(error); } finally { button.disabled = false; } }; row.appendChild(button); }
      list.appendChild(row);
    }
  };
  for (const [id, endpoint] of [["markRead", "read"], ["clearNotifs", "clear"]]) $("#" + id).addEventListener("click", async (event) => {
    event.preventDefault(); event.stopImmediatePropagation();
    try { const result = await apiRequest(`/api/notifications/${endpoint}`, { method: "POST" }); if (result.notifications) runtimeState.notifications = result.notifications; if (result.settings) runtimeState.settings = result.settings; window.renderDropSyncNotifications(); } catch (error) { showError(error); }
  }, true);
  window.updateDropSyncProfile = () => {
    if (!runtimeState.settings) return;
    const profile = runtimeState.settings.profile || {}, name = profile.displayName || runtimeState.self?.name || "This device";
    $$(".profile-name").forEach((el) => { el.textContent = name; });
    $$(".profile-status").forEach((el) => { el.textContent = window.dropSyncAccount?.email || "Personal workspace"; });
    const avatar = $("#profileBtn .avatar");
    if (avatar && avatar.dataset.current !== (profile.avatar || name)) { avatar.replaceChildren(); if (profile.avatar) { const image = document.createElement("img"); image.src = profile.avatar; image.alt = ""; avatar.appendChild(image); } else avatar.textContent = initials(name); avatar.dataset.current = profile.avatar || name; }
  };
  const menu = document.createElement("div"); menu.id = "workspaceProfileMenu"; menu.className = "workspace-profile-menu"; menu.hidden = true; menu.setAttribute("role", "menu"); document.body.appendChild(menu);
  function closeProfile() { menu.hidden = true; $("#profileBtn").setAttribute("aria-expanded", "false"); }
  const profileButton = $("#profileBtn");
  profileButton.setAttribute("aria-label", "Open profile menu"); profileButton.setAttribute("aria-expanded", "false");
  const toggleProfile = (event) => {
    event.preventDefault(); event.stopImmediatePropagation(); if (!menu.hidden) return closeProfile();
    menu.replaceChildren();
    for (const [label, action] of [["Edit profile", () => { openModal("settings"); renderSettings("profile"); }], ["Settings", () => openModal("settings")], ["Transfer notifications", () => $("#bellBtn").click()], ["Account", () => { location.hash = "#account"; }]]) {
      const button = document.createElement("button"); button.type = "button"; button.setAttribute("role", "menuitem"); button.textContent = label; button.onclick = () => { closeProfile(); action(); }; menu.appendChild(button);
    }
    const rect = profileButton.getBoundingClientRect(); menu.style.left = `${Math.max(8, rect.left)}px`; menu.style.bottom = `${Math.max(8, innerHeight - rect.top + 8)}px`; menu.hidden = false; profileButton.setAttribute("aria-expanded", "true"); menu.querySelector("button").focus();
  };
  profileButton.addEventListener("click", toggleProfile, true);
  profileButton.addEventListener("keydown", (event) => { if (["Enter", " "].includes(event.key)) toggleProfile(event); });
  document.addEventListener("pointerdown", (event) => { if (!menu.hidden && !menu.contains(event.target) && !profileButton.contains(event.target)) closeProfile(); });
  menu.onkeydown = (event) => { const controls = [...menu.querySelectorAll("button")], index = controls.indexOf(document.activeElement); if (["ArrowDown", "ArrowUp"].includes(event.key)) { event.preventDefault(); controls[(index + (event.key === "ArrowDown" ? 1 : -1) + controls.length) % controls.length].focus(); } if (event.key === "Escape") { closeProfile(); profileButton.focus(); } };
  $$("[data-nav='contacts'], [data-nav='ai'], [data-nav='assistant'], [data-open-modal='assistant']").forEach((el) => { el.hidden = true; });

  const composer = document.createElement("div"); composer.className = "overlay"; composer.id = "ov-composer"; composer.hidden = true;
  composer.innerHTML = '<div class="modal modal-sm" role="dialog" aria-modal="true" aria-labelledby="composerTitle"><header class="modal-head"><h3 id="composerTitle">Send text</h3><button class="icon-btn" data-close-modal aria-label="Close">×</button></header><div class="message-composer"><label for="composerText">Your message</label><textarea class="input" id="composerText" rows="8" maxlength="1000000" placeholder="Type or paste the text you want to share"></textarea><p class="muted">Sent as an encrypted text file to the device you choose. The receiver decides whether to accept.</p><button class="btn btn-secondary" id="composerPaste" type="button">Paste current clipboard</button></div><footer class="modal-foot"><button class="btn btn-ghost" data-close-modal>Cancel</button><button class="btn btn-primary" id="composerContinue">Choose device</button></footer></div>';
  document.body.appendChild(composer); let composerKind = "text";
  async function pasteClipboard() {
    if (!runtimeState.settings?.clipboardEnabled) throw new Error("Enable clipboard sharing in Settings → Security first");
    const text = isNativeAndroid ? (await apiRequest("/api/clipboard/read", { method: "POST" })).text : await navigator.clipboard.readText();
    if (new Blob([text]).size > 1024 * 1024) throw new Error("Clipboard text exceeds 1 MiB");
    $("#composerText").value = text; composerKind = "clipboard";
  }
  window.openDropSyncComposer = (kind = "text") => {
    if (runtimeState.unavailable) return toast("Connect to DropSync first", "The local sharing service is unavailable", "error");
    composerKind = kind; $("#composerText").value = ""; $("#composerTitle").textContent = kind === "clipboard" ? "Share clipboard text" : "Send text"; openModal("composer");
    if (kind === "clipboard") pasteClipboard().catch(showError);
  };
  $("#composerPaste").onclick = () => pasteClipboard().catch(showError);
  $("#composerContinue").onclick = async () => {
    const button = $("#composerContinue"); button.disabled = true;
    try { const text = $("#composerText").value; if (!text.trim()) throw new Error("Enter some text first"); const result = await apiRequest("/api/stage/text", { method: "POST", body: { text, kind: composerKind } }); runtimeState.stagedFiles = result.stagedFiles; renderStagedFiles(); $("#composerText").value = ""; closeModal(composer); openSend({ mode: "files" }); }
    catch (error) { showError(error); } finally { button.disabled = false; }
  };
  const fileSend = openSend;
  openSend = (options = {}) => { if (options.mode === "text") return window.openDropSyncComposer(); if (options.mode === "link") return toast("Send link", "Link sharing remains planned. You can paste a link into Send text.", "info"); return fileSend(options); };
  document.addEventListener("click", async (event) => {
    const action = event.target.closest("[data-feature-action]")?.dataset.featureAction;
    if (action === "choose-folder") { try { await apiRequest("/api/storage/choose", { method: "POST" }); } catch (error) { showError(error); } }
    if (action === "background-settings") { try { await apiRequest("/api/system/background-settings", { method: "POST" }); } catch (error) { showError(error); } }
    if (action === "license") {
      try { const result = await apiRequest("/api/project/license"); let overlay = $("#ov-license-text"); if (!overlay) { overlay = document.createElement("div"); overlay.id = "ov-license-text"; overlay.className = "overlay"; overlay.hidden = true; overlay.innerHTML = '<div class="modal modal-sm" role="dialog" aria-modal="true" aria-label="License"><header class="modal-head"><h3>License</h3><button class="icon-btn" data-close-modal aria-label="Close">×</button></header><pre class="license-text"></pre></div>'; document.body.appendChild(overlay); } overlay.querySelector("pre").textContent = result.text; openModal("license-text"); } catch (error) { showError(error); }
    }
  });
  window.updateDropSyncProfile();
  window.renderDropSyncNotifications();
  if (runtimeState.settings) renderStaticDataAsLive();
})();
