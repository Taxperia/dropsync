"use strict";

// Features shared by the browser, desktop shell, and Android package.
(() => {
  const settingsModal = $("#ov-settings .modal");
  const settingsBody = $("#ov-settings .settings-body") || $("#settingsNav").parentElement;
  const settingsPage = $(".page[data-page='settings-page']");
  const mobileSettings = isNativeAndroid;
  const productVersion = "0.7.0";
  const authConfig = window.DROPSYNC_AUTH || {};
  const authConfigured = (() => {
    try {
      const value = new URL(authConfig.url || "");
      return Boolean(authConfig.publishableKey) && (value.protocol === "https:" || (value.protocol === "http:" && ["127.0.0.1", "localhost"].includes(value.hostname)));
    } catch { return false; }
  })();
  const preferences = (() => { try { return JSON.parse(localStorage.getItem("dropsync.preferences") || "{}"); } catch { return {}; } })();

  function setTheme(theme) {
    const light = theme === "Light" || (theme === "System" && matchMedia("(prefers-color-scheme: light)").matches);
    document.documentElement.dataset.theme = { "GitHub Dark": "github-dark", "GitHub Light": "github-light", Midnight: "midnight", Nord: "nord" }[theme] || (light ? "light" : "dark");
    preferences.theme = theme;
    localStorage.setItem("dropsync.preferences", JSON.stringify(preferences));
  }
  setTheme(preferences.theme || "System");
  matchMedia("(prefers-color-scheme: light)").addEventListener("change", () => setTheme(preferences.theme));

  S.splice(0, S.length, ...window.dropSyncSettings(preferences));
  $("#settingsNav").innerHTML = S.map((c) => `<button class="set-cat" data-cat="${c.id}"><svg class="icon"><use href="#${c.icon}"/></svg>${c.title}</button>`).join("");
  renderSettings("general");
  window.mountSettingsPage = () => {
    settingsPage.replaceChildren(settingsBody);
    settingsPage.classList.add("settings-full-page");
    $("#ov-settings").hidden = true;
    $("#app").removeAttribute("inert");
  };
  // Return the shared controls to the dialog when changing to a desktop viewport.
  document.addEventListener("click", (event) => {
    const trigger = event.target.closest("[data-open-modal='settings'], [data-nav='settings-page']");
    if (trigger && !isNativeAndroid && !matchMedia("(max-width: 900px)").matches) {
      settingsModal.appendChild(settingsBody);
    }
  }, true);
  document.addEventListener("change", (event) => {
    const label = event.target.getAttribute("aria-label");
    if (label === "Theme") setTheme(event.target.value);
    if (label === "Phone name") {
      preferences.phoneName = event.target.value.trim().slice(0, 48);
      localStorage.setItem("dropsync.preferences", JSON.stringify(preferences));
      runtimeState.self.name = preferences.phoneName || "My phone";
      renderDevices();
    }
  });
  document.addEventListener("click", (event) => {
    if (event.target.closest("[aria-label='Reduce motion']")) {
      preferences.reduceMotion = event.target.closest("button").getAttribute("aria-checked") === "true";
      document.documentElement.classList.toggle("reduce-motion", preferences.reduceMotion);
      localStorage.setItem("dropsync.preferences", JSON.stringify(preferences));
    }
  });
  document.documentElement.classList.toggle("reduce-motion", Boolean(preferences.reduceMotion));

  const more = $("#mobileMoreBtn");
  more.setAttribute("aria-label", "Account");
  more.removeAttribute("aria-controls"); more.removeAttribute("aria-expanded");
  more.dataset.nav = "account";
  more.innerHTML = '<svg class="icon"><use href="#i-user"/></svg><span>Account</span>';
  const account = document.createElement("section");
  account.className = "page"; account.dataset.page = "account";
  account.innerHTML = `<div class="account-card card"><span class="eyebrow">DROPSYNC ${productVersion}</span><h2 id="accountTitle">Welcome to DropSync</h2><p class="muted" id="accountLede">Sign in to your account. Local sharing remains available without an account.</p>
    <div id="authNotice" class="auth-notice" role="status" aria-live="polite"></div>
    <div id="authSignedIn" hidden><p id="authIdentity"></p><button class="btn btn-secondary" id="authSignOut">Sign out</button></div>
    <form id="authForm"><label>Email<input class="input" id="authEmail" type="email" autocomplete="email" required maxlength="254"></label>
    <label>Password<input class="input" id="authPassword" type="password" autocomplete="current-password" minlength="8" maxlength="128" required></label>
    <button class="btn btn-primary" id="authSubmit" type="submit">Sign in</button><button class="btn btn-ghost" type="button" id="authMode">Create an account</button></form>
    <div class="auth-providers"><button class="btn btn-secondary" data-provider="google">Google</button><button class="btn btn-secondary" data-provider="facebook">Facebook</button><button class="btn btn-secondary" data-provider="github">GitHub</button></div>
    <button class="btn btn-primary local-entry-button" id="continueLocal"><svg class="icon"><use href="#i-shield-check"/></svg>Start sharing on this device</button><p class="local-entry-hint">No account needed. Pair your devices to share securely.</p><a class="product-link" href="welcome.html">Discover DropSync →</a></div>`;
  if (isNativeAndroid || isNativeDesktop) account.querySelector(".product-link").hidden = true;
  $("main.content").appendChild(account);
  const sidebarAccount = document.createElement("button");
  sidebarAccount.className = "nav-item"; sidebarAccount.dataset.nav = "account";
  sidebarAccount.append(svgIcon("i-user"), document.createTextNode("Account"));
  $("[data-nav='settings-page']").after(sidebarAccount);

  const onboarding = document.createElement("section");
  onboarding.className = "page"; onboarding.dataset.page = "onboarding";
  onboarding.innerHTML = `<div class="onboarding"><div class="onboard-art" aria-hidden="true"><span class="orbit orbit-one"></span><span class="orbit orbit-two"></span><span class="orbit-core">↗</span><span class="orbit-device">▣</span></div><span class="eyebrow" id="onboardStep"></span><h1 id="onboardTitle"></h1><p id="onboardText"></p><div class="onboard-dots" aria-hidden="true"></div><button class="btn btn-primary" id="onboardNext">Continue</button><button class="btn btn-ghost" id="onboardSkip">Skip introduction</button></div>`;
  $("main.content").appendChild(onboarding);
  const slides = [
    ["Your devices. Closer together.", "A quiet home for your files, paired devices, and transfer history."],
    ["Private by design.", "On supported devices, files travel directly between paired peers with authenticated encryption."],
    ["Make yourself at home.", "Pair a nearby computer, then send files securely. You can also share photos and documents directly to DropSync from other apps."],
  ];
  let slide = 0;
  function renderSlide() {
    $("#onboardStep").textContent = `MEET DROPSYNC · ${slide + 1} / 3`;
    $("#onboardTitle").textContent = slides[slide][0];
    $("#onboardText").textContent = slides[slide][1];
    $("#onboardNext").textContent = slide === 2 ? "Get started" : "Continue";
    $(".onboard-dots").replaceChildren(...slides.map((_, i) => { const dot = document.createElement("i"); dot.classList.toggle("active", i === slide); return dot; }));
  }
  function finishOnboarding() {
    localStorage.setItem("dropsync.onboarded.v1", "true");
    if (isNativeAndroid && !authConfigured) window.enterDropSyncWorkspace("local");
    else location.hash = "#account";
  }
  $("#onboardNext").onclick = () => { if (slide === 2) finishOnboarding(); else { slide++; renderSlide(); } };
  $("#onboardSkip").onclick = finishOnboarding;
  renderSlide();
  let desktopSetupComplete = !isNativeDesktop;
  let desktopSetupLoaded = false;
  if (isNativeDesktop) {
    const setup = document.createElement("section");
    setup.className = "page"; setup.dataset.page = "setup";
    setup.innerHTML = `<form id="desktopSetupForm" class="desktop-setup card">
      <span class="setup-logo" aria-hidden="true"><svg class="icon"><use href="#i-logo"/></svg></span>
      <span class="eyebrow">WELCOME TO DROPSYNC</span>
      <h1>Set up this computer.</h1><p class="setup-lede">A name, a place for your files, and you're ready to pair your devices.</p>
      <label for="setupDeviceName">Device name<span class="setup-hint">How this computer appears on your other devices.</span></label>
      <input id="setupDeviceName" class="input" required maxlength="48" autocomplete="off" disabled>
      <label for="setupDownloadDirectory">Receiving folder<span class="setup-hint">Verified incoming files will be saved here.</span></label>
      <div class="setup-folder"><input id="setupDownloadDirectory" class="input" required autocomplete="off" disabled><button id="setupChooseFolder" class="btn btn-secondary" type="button" disabled>Choose folder</button></div>
      <p class="setup-privacy"><svg class="icon"><use href="#i-shield-check"/></svg>Pair your devices to share. Incoming files ask for your approval.</p>
      <p id="setupStatus" role="status" aria-live="polite">Connecting to your local service…</p>
      <button id="setupFinish" class="btn btn-primary" type="submit" disabled>Finish setup</button>
      <span class="setup-hint">You can change these settings later. No account needed.</span>
    </form>`;
    $("main.content").appendChild(setup);
    window.syncDropSyncDesktopSetup = () => {
      if (runtimeState.unavailable || !runtimeState.settings) return;
      desktopSetupComplete = runtimeState.settings.ui?.["desktop-setup-complete"] === true;
      if (!desktopSetupLoaded) {
        desktopSetupLoaded = true;
        $("#setupDeviceName").value = runtimeState.settings.deviceName;
        $("#setupDownloadDirectory").value = runtimeState.settings.downloadDirectory;
        $("#setupStatus").textContent = "";
        $$("#desktopSetupForm input, #desktopSetupForm button").forEach((control) => { control.disabled = false; });
        for (const [key, id] of [["deviceName", "setupDeviceName"], ["downloadDirectory", "setupDownloadDirectory"]]) {
          if (runtimeState.managedSettings?.includes(key)) $("#" + id).disabled = true;
        }
        if (runtimeState.managedSettings?.includes("downloadDirectory")) $("#setupChooseFolder").disabled = true;
      }
      applyRoute();
    };
    $("#setupChooseFolder").onclick = async () => {
      const button = $("#setupChooseFolder"); button.disabled = true;
      try {
        const result = await apiRequest("/api/storage/choose", { method: "POST" });
        if (result.directory) $("#setupDownloadDirectory").value = result.directory;
        $("#setupStatus").textContent = "";
      } catch (error) { $("#setupStatus").textContent = error.message; }
      finally { button.disabled = false; }
    };
    $("#desktopSetupForm").onsubmit = async (event) => {
      event.preventDefault();
      const name = $("#setupDeviceName").value.trim(), directory = $("#setupDownloadDirectory").value.trim();
      if (!name || !directory) { $("#setupStatus").textContent = "Enter a device name and receiving folder."; return; }
      const button = $("#setupFinish"); button.disabled = true; button.textContent = "Saving…";
      try {
        const result = await apiRequest("/api/settings", { method: "PUT", body: { deviceName: name, downloadDirectory: directory, ui: { "desktop-setup-complete": true } } });
        runtimeState.settings = result.settings;
        runtimeState.self.name = result.settings.deviceName;
        desktopSetupComplete = true;
        window.updateDropSyncProfile?.(); renderDevices(); hydrateSettingsControls();
        location.hash = "#dashboard"; applyRoute();
      } catch (error) { $("#setupStatus").textContent = error.message; }
      finally { button.disabled = false; button.textContent = "Finish setup"; }
    };
  }
  // This is an entry preference, not authentication or permission to access files.
  // The desktop shell opens the local workspace directly; provider tokens stay in memory.
  let entered = isNativeDesktop || sessionStorage.getItem("dropsync.local-entry") === "true" || (isNativeAndroid && !authConfigured && localStorage.getItem("dropsync.onboarded.v1") === "true");
  let destination = "dashboard";
  window.resolveDropSyncRoute = (requested) => {
    if (["contacts", "ai", "assistant"].includes(requested)) requested = "nearby";
    let target = requested;
    if (isNativeDesktop && !desktopSetupComplete) {
      target = "setup";
      if (location.hash !== "#setup") history.replaceState(null, "", `${location.pathname}${location.search}#setup`);
    } else if (isNativeDesktop && target === "setup") {
      target = "dashboard";
      history.replaceState(null, "", `${location.pathname}${location.search}#dashboard`);
    } else if (!entered) {
      if (!["account", "onboarding"].includes(requested)) destination = requested;
      target = isNativeAndroid && !localStorage.getItem("dropsync.onboarded.v1") ? "onboarding" : "account";
      if (location.hash !== `#${target}`) history.replaceState(null, "", `${location.pathname}${location.search}#${target}`);
    }
    document.documentElement.classList.toggle("entry-screen", !entered || target === "onboarding" || target === "setup");
    return target;
  };
  window.enterDropSyncWorkspace = (mode) => {
    entered = true;
    if (mode === "local") sessionStorage.setItem("dropsync.local-entry", "true");
    else sessionStorage.removeItem("dropsync.local-entry");
    location.hash = `#${destination}`;
    applyRoute();
  };
  window.leaveDropSyncWorkspace = () => {
    entered = isNativeDesktop;
    destination = "dashboard";
    sessionStorage.removeItem("dropsync.local-entry");
    location.hash = "#account";
    applyRoute();
  };
  $("#continueLocal").onclick = () => window.enterDropSyncWorkspace("local");
  window.syncDropSyncDesktopSetup?.();
  applyRoute();
  document.documentElement.classList.add("product-ready");
})();
