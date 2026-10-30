/* ============================================================
   DropSync — UI prototype behaviour
   ============================================================ */
"use strict";

const $  = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const escapeHTML = (value) => String(value ?? "").replace(/[&<>'"]/g, (char) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;",
})[char]);

// Production UI never runs simulated transfers, including while bootstrap is pending.
let realRuntimeActive = true;
const isNativeAndroid = typeof window.DropSyncAndroid !== "undefined";

/* ---------------- Toasts ---------------- */
const toastIcons = {
  success: "i-check-circle", error: "i-alert-circle", warning: "i-alert-triangle",
  info: "i-info", accent: "i-send",
};
function toast(title, sub = "", tone = "accent", ms = 3400) {
  const stack = $("#toasts");
  const el = document.createElement("div");
  el.className = "toast";
  const icon = document.createElement("span");
  icon.className = `toast-ic ${Object.hasOwn(toastIcons, tone) ? tone : "accent"}`;
  icon.innerHTML = `<svg class="icon"><use href="#${toastIcons[tone] || toastIcons.accent}"/></svg>`;
  const body = document.createElement("div");
  body.className = "toast-body";
  const heading = document.createElement("p");
  heading.textContent = String(title);
  body.appendChild(heading);
  if (sub) {
    const detail = document.createElement("span");
    detail.textContent = String(sub);
    body.appendChild(detail);
  }
  const close = document.createElement("button");
  close.className = "icon-btn toast-x";
  close.type = "button";
  close.setAttribute("aria-label", "Dismiss");
  close.innerHTML = `<svg class="icon icon-xs"><use href="#i-x"/></svg>`;
  el.append(icon, body, close);
  const kill = () => { el.classList.add("is-leaving"); setTimeout(() => el.remove(), 220); };
  close.addEventListener("click", kill);
  stack.appendChild(el);
  while (stack.children.length > 4) stack.firstElementChild.remove();
  if (ms) setTimeout(kill, ms);
  return el;
}

/* ---------------- Context menu ---------------- */
const ctxMenu = $("#ctxMenu");
let ctxItems = [];
function openMenu(items, x, y) {
  ctxItems = items;
  ctxMenu.replaceChildren();
  items.forEach((item, index) => {
    if (item === "-") {
      const separator = document.createElement("div");
      separator.className = "menu-sep";
      separator.setAttribute("role", "separator");
      ctxMenu.appendChild(separator);
      return;
    }
    const button = document.createElement("button");
    button.type = "button";
    button.className = `menu-item ${item.danger ? "danger" : ""}`;
    button.dataset.mi = String(index);
    button.setAttribute("role", "menuitem");
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("class", "icon");
    const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
    use.setAttribute("href", `#${item.icon}`);
    svg.appendChild(use);
    button.append(svg, document.createTextNode(String(item.label)));
    if (item.kbd) {
      const shortcut = document.createElement("span");
      shortcut.className = "kbd";
      shortcut.textContent = item.kbd;
      button.appendChild(shortcut);
    }
    ctxMenu.appendChild(button);
  });
  ctxMenu.hidden = false;
  const r = ctxMenu.getBoundingClientRect();
  ctxMenu.style.left = Math.min(x, innerWidth - r.width - 10) + "px";
  ctxMenu.style.top  = Math.min(y, innerHeight - r.height - 10) + "px";
}
function closeMenu() { ctxMenu.hidden = true; }
ctxMenu.addEventListener("click", (e) => {
  const b = e.target.closest("[data-mi]");
  if (!b) return;
  const item = ctxItems[+b.dataset.mi];
  closeMenu();
  item.action?.();
});
window.addEventListener("click", (e) => { if (!ctxMenu.hidden && !ctxMenu.contains(e.target)) closeMenu(); });

function deviceMenu(card) {
  const name = card.dataset.name;
  const offline = card.classList.contains("is-offline");
  const fav = card.querySelector(".fav")?.classList.contains("is-on");
  return [
    { label: "Send to device", icon: "i-send", kbd: "Ctrl ⇧ F", action: () => openSend({ device: name }) },
    { label: offline ? "Wake & connect" : "Connect", icon: "i-link", action: () => toast("Device connected", `${name} · encrypted session established`, "success") },
    { label: card.dataset.trust === "Trusted device" ? "Remove trust" : "Trust device", icon: "i-shield-check", action: () => toast("Trust updated", name) },
    { label: "Rename", icon: "i-pencil" },
    { label: fav ? "Remove from favorites" : "Add to favorites", icon: "i-star", action: () => toggleFav(card.querySelector(".fav")) },
    "-",
    { label: "Disconnect", icon: "i-unplug", danger: true, action: () => toast("Device disconnected", name, "warning") },
  ];
}
function fileMenu(label) {
  return [
    { label: "Send to device…", icon: "i-send", kbd: "Ctrl ⇧ F", action: () => openSend({}) },
    { label: "Open", icon: "i-external" },
    { label: "Save as…", icon: "i-download", action: () => toast("Saved", label, "success") },
    { label: "Favorite", icon: "i-star" },
    "-",
    { label: "Forward", icon: "i-forward" },
    { label: "Rename", icon: "i-pencil" },
    { label: "View details", icon: "i-eye" },
    "-",
    { label: "Delete", icon: "i-trash", danger: true, action: () => toast("Moved to trash", label, "warning") },
  ];
}

/* Context menu triggers: kebab buttons with data-act="menu" + right-click on cards/rows */
document.addEventListener("click", (e) => {
  const btn = e.target.closest('[data-act="menu"]');
  if (!btn) return;
  e.stopPropagation();
  const card = btn.closest(".device-card");
  const row  = btn.closest("tr") || btn.closest(".transfer-row") || btn.closest(".shared-card");
  const r = btn.getBoundingClientRect();
  if (card) openMenu(deviceMenu(card), r.left - 160, r.bottom + 6);
  else if (row) {
    const name = row.querySelector(".transfer-name, .cell-file")?.textContent.trim() || "item";
    openMenu(fileMenu(name), r.left - 160, r.bottom + 6);
  }
});
document.addEventListener("contextmenu", (e) => {
  const card = e.target.closest(".device-card");
  const row  = e.target.closest(".history-table tbody tr, .shared-card, .contacts-table tbody tr");
  if (!card && !row) return;
  e.preventDefault();
  if (card) openMenu(deviceMenu(card), e.clientX, e.clientY);
  else openMenu(fileMenu(row.querySelector(".cell-file")?.textContent.trim() || "item"), e.clientX, e.clientY);
});

/* ---------------- Favorites toggle ---------------- */
function toggleFav(btn) {
  if (!btn) return;
  btn.classList.toggle("is-on");
  const on = btn.classList.contains("is-on");
  btn.title = on ? "Remove from favorites" : "Add to favorites";
  btn.setAttribute("aria-label", btn.title);
  const label = btn.closest(".device-card")?.dataset.name || "Item";
  toast(on ? "Added to favorites" : "Removed from favorites", label, on ? "success" : "info");
}
document.addEventListener("click", (e) => {
  const fav = e.target.closest(".fav[data-act='fav'], .fav.is-on, .shared-actions .fav, .row-list .fav");
  if (fav && !fav.closest("a")) {
    if (fav.tagName === "BUTTON" || fav.classList.contains("icon-btn")) { e.stopPropagation(); toggleFav(fav); }
  }
});

/* ---------------- Modal manager ---------------- */
const modalStack = [];
const modalReturnFocus = new WeakMap();
const focusableSelector = 'button:not([disabled]):not([hidden]), input:not([disabled]):not([hidden]), select:not([disabled]), textarea:not([disabled]), [href], [tabindex]:not([tabindex="-1"])';
function openModal(id) {
  if (id === "clipboard" && window.openDropSyncComposer) return window.openDropSyncComposer("clipboard");
  if (["trust", "clipboard"].includes(id)) {
    toast("Not available", "This feature is not included in this build.", "info");
    return;
  }
  if (id === "incoming" && !runtimeState.incomingRequests?.length) return toast("No incoming files", "Requests from paired devices will appear here", "info");
  if (id === "settings" && (isNativeAndroid || matchMedia("(max-width: 900px)").matches)) {
    location.hash = "#settings-page";
    window.mountSettingsPage?.();
    return;
  }
  const ov = $("#ov-" + id);
  if (!ov) return;
  if (!ov.hidden) return ov;
  modalReturnFocus.set(ov, document.activeElement);
  ov.hidden = false;
  if (!modalStack.includes(ov)) modalStack.push(ov);
  $("#app")?.setAttribute("inert", "");
  if (id === "pairing") startPairing();
  if (id === "send") sendStep(1);
  requestAnimationFrame(() => {
    const target = ov.querySelector("[autofocus], input:not([hidden]), button:not([hidden])");
    target?.focus();
  });
  return ov;
}
function closeModal(ov) {
  ov = ov || modalStack[modalStack.length - 1];
  if (!ov) return;
  ov.hidden = true;
  const i = modalStack.indexOf(ov);
  if (i > -1) modalStack.splice(i, 1);
  if (ov.id === "ov-pairing") {
    stopPairing();
    if (realRuntimeActive) {
      runtimeState.pendingPairDeviceId = null;
      $("#pairTarget").hidden = true;
      $("#pairConfirm").hidden = true;
      $("#pairCodeInput").value = "";
    }
  }
  const route = parseHash();
  if (route.params.modal === ov.id.replace(/^ov-/, "")) {
    delete route.params.modal;
    const query = new URLSearchParams(route.params).toString();
    history.replaceState(null, "", `#${route.page || "dashboard"}${query ? `?${query}` : ""}`);
  }
  if (!modalStack.length) {
    if (drawer.hidden) $("#app")?.removeAttribute("inert");
    const returnTarget = modalReturnFocus.get(ov);
    if (returnTarget?.isConnected) returnTarget.focus();
  } else {
    const top = modalStack[modalStack.length - 1];
    top.querySelector(focusableSelector)?.focus();
  }
}
document.addEventListener("click", (e) => {
  const t = e.target.closest("[data-open-modal]");
  if (t) {
    const mode = t.dataset.mode;
    const devName = t.closest(".drawer") ? $("#dName").textContent
                  : t.closest(".device-card")?.dataset.name;
    if (t.dataset.openModal === "send") openSend({ device: devName, mode });
    else openModal(t.dataset.openModal);
    return;
  }
  const c = e.target.closest("[data-close-modal]");
  if (c) { closeModal(c.closest(".overlay")); return; }
  if (e.target.classList?.contains("overlay")) closeModal(e.target);
});

/* ---------------- Drawer ---------------- */
const drawer = $("#deviceDrawer");
const drawerBackdrop = $("#drawerBackdrop");
let drawerReturnFocus = null;
function openDrawer(id) {
  const card = $(`.device-card[data-device="${id}"]`);
  if (!card) return;
  const d = card.dataset;
  $("#dName").textContent = d.name;
  $("#dType").textContent = d.type;
  const safeDeviceIcon = /^i-[a-z0-9-]+$/.test(d.icon || "") ? d.icon : "i-laptop";
  $("#dIcon").innerHTML = `<svg class="icon"><use href="#${safeDeviceIcon}"/></svg>`;
  const online = d.status === "online";
  $("#dStatus").innerHTML = online
    ? `<span class="dot success"></span>Connected`
    : `<span class="dot muted"></span>Offline`;
  $("#dTrust").innerHTML = d.trust === "Trusted device"
    ? `<svg class="icon icon-xs"><use href="#i-shield-check"/></svg>Trusted device`
    : `<svg class="icon icon-xs"><use href="#i-shield"/></svg>${escapeHTML(d.trust)}`;
  $("#dConn").textContent = online ? "Connected · Wi-Fi" : "Unavailable";
  $("#dQuality").innerHTML =
    `<span class="qbars inline">${Array.from({ length: 4 }, (_, i) => `<i${i < +d.q ? ' class="on"' : ""}></i>`).join("")}</span>${escapeHTML(d.quality)}`;
  $("#dIp").textContent = d.ip;
  $("#dLastXfer").textContent = d.lastxfer;
  $("#dTotal").textContent = d.total;
  $("#dSpeed").textContent = d.speed;
  drawerReturnFocus = document.activeElement;
  drawer.hidden = false; drawerBackdrop.hidden = false;
  $("#app")?.setAttribute("inert", "");
  requestAnimationFrame(() => $("#drawerClose")?.focus());
}
function closeDrawer() {
  drawer.hidden = true;
  drawerBackdrop.hidden = true;
  if (!modalStack.length) $("#app")?.removeAttribute("inert");
  if (drawerReturnFocus?.isConnected) drawerReturnFocus.focus();
  drawerReturnFocus = null;
}
$("#drawerClose").addEventListener("click", closeDrawer);
drawerBackdrop.addEventListener("click", closeDrawer);
document.addEventListener("click", (e) => {
  const t = e.target.closest("[data-drawer]");
  if (t) openDrawer(t.dataset.drawer);
});

/* ---------------- Router ---------------- */
const PAGE_META = {
  dashboard: ["Dashboard", "This device is visible on your local network"],
  nearby:    ["Nearby Devices", "Scanning your local network"],
  transfers: ["Transfers", "4 active · 2 queued · 8 completed today"],
  history:   ["History", "128 transfers recorded"],
  shared:    ["Shared Items", "24 items shared with you"],
  favorites: ["Favorites", "2 devices · 5 items pinned"],
  contacts:  ["Contacts", "6 saved devices"],
  storage:   ["Storage", "148 GB used of 256 GB"],
  network:   ["Network", "Local network status"],
  "settings-page": ["Settings", "Configure DropSync"],
  account: ["Account", "Your DropSync account"],
  onboarding: ["Welcome", "A little closer. A lot simpler."],
};
function parseHash() {
  const h = location.hash.replace(/^#\/?/, "");
  const [page, qs] = h.split("?");
  const params = {};
  if (qs) qs.split("&").forEach((kv) => { const [k, v] = kv.split("="); params[k] = decodeURIComponent(v || ""); });
  return { page: page || "dashboard", params };
}
function applyRoute() {
  // Product startup owns entry into the workspace; never paint the template first.
  if (!window.resolveDropSyncRoute) return;
  const { page, params } = parseHash();
  const requested = PAGE_META[page] ? page : "dashboard";
  const target = window.resolveDropSyncRoute(requested);
  if (target !== requested || document.documentElement.classList.contains("entry-screen")) {
    for (const key of Object.keys(params)) delete params[key];
  }
  if (target === "settings-page") window.mountSettingsPage?.();
  $$(".page").forEach((p) => p.classList.toggle("is-active", p.dataset.page === target));
  $$(".nav-item").forEach((n) => n.classList.toggle("is-active", n.dataset.nav === target));
  $$(".mobile-nav-item[data-nav]").forEach((n) => n.classList.toggle("is-active", n.dataset.nav === target));
  $("#pageTitle").textContent = PAGE_META[target][0];
  $("#pageSubtitle").textContent = PAGE_META[target][1];

  if (!params.modal) [...modalStack].reverse().forEach((modal) => closeModal(modal));
  if (!params.drawer && !drawer.hidden) closeDrawer();

  if (target === "transfers") switchTab(params.tab || "active");
  if (params.drawer) openDrawer(params.drawer);
  if (params.modal) {
    if (params.modal === "send") openSend(params.device ? { device: params.device } : {});
    else openModal(params.modal);
  }
  if (params.modal === "settings" && params.cat) renderSettings(params.cat);
  if (params.search) { openModal("search"); const i = $("#searchInput"); i.value = params.search; filterSearch(params.search); }
  if (params.ctx) {
    const card = $(`.device-card[data-device="${params.ctx}"]`);
    if (card) setTimeout(() => openMenu(deviceMenu(card), 460, 300), 700);
  }
}
document.addEventListener("click", (e) => {
  const n = e.target.closest("[data-nav]");
  if (n) {
    closeMobileMenu();
    if (n.dataset.nav === "settings-page") { openModal("settings"); return; }
    location.hash = "#" + n.dataset.nav;
  }
  const nt = e.target.closest("[data-nav-to]");
  if (nt) { closeDrawer(); location.hash = "#" + nt.dataset.navTo; }
});
window.addEventListener("hashchange", applyRoute);

/* ---------------- Mobile navigation ---------------- */
const appShell = $("#app");
const mobileMenuBtn = $("#mobileMenuBtn");
const mobileMoreBtn = $("#mobileMoreBtn");
const mobileMenuBackdrop = $("#mobileMenuBackdrop");
function setMobileMenu(open) {
  appShell.classList.toggle("mobile-nav-open", open);
  mobileMenuBtn?.setAttribute("aria-expanded", String(open));
  mobileMoreBtn?.setAttribute("aria-expanded", String(open));
  if (open) requestAnimationFrame(() => $(".sidebar .nav-item")?.focus());
}
function closeMobileMenu() {
  if (!appShell?.classList.contains("mobile-nav-open")) return;
  setMobileMenu(false);
}
mobileMenuBtn?.addEventListener("click", () => setMobileMenu(!appShell.classList.contains("mobile-nav-open")));
mobileMoreBtn?.addEventListener("click", () => { closeMobileMenu(); location.hash = "#account"; });
mobileMenuBackdrop?.addEventListener("click", closeMobileMenu);
window.addEventListener("resize", () => { if (window.innerWidth > 760) closeMobileMenu(); });

/* ---------------- Transfers: tabs & simulation ---------------- */
$$(".tab").forEach((t) => t.addEventListener("click", () => {
  switchTab(t.dataset.tab);
  if (parseHash().page === "transfers") history.replaceState(null, "", `#transfers?tab=${encodeURIComponent(t.dataset.tab)}`);
}));
$$(".tabs[role='tablist']").forEach((tabList) => tabList.addEventListener("keydown", (event) => {
  const tabs = $$("[role='tab']", tabList);
  const current = tabs.indexOf(document.activeElement);
  if (current < 0) return;
  let next = current;
  if (event.key === "ArrowRight" || event.key === "ArrowDown") next = (current + 1) % tabs.length;
  else if (event.key === "ArrowLeft" || event.key === "ArrowUp") next = (current - 1 + tabs.length) % tabs.length;
  else if (event.key === "Home") next = 0;
  else if (event.key === "End") next = tabs.length - 1;
  else return;
  event.preventDefault();
  tabs[next].click();
  tabs[next].focus();
}));
function switchTab(name) {
  if (!$(`.tab[data-tab="${CSS.escape(name)}"]`)) name = "active";
  $$(".tab").forEach((t) => {
    const selected = t.dataset.tab === name;
    t.id = `transfer-tab-${t.dataset.tab}`;
    t.setAttribute("aria-controls", `transfer-panel-${t.dataset.tab}`);
    t.classList.toggle("is-active", selected);
    t.setAttribute("aria-selected", String(selected));
    t.tabIndex = selected ? 0 : -1;
  });
  $$(".tab-panel").forEach((p) => {
    const selected = p.dataset.panel === name;
    p.id = `transfer-panel-${p.dataset.panel}`;
    p.setAttribute("aria-labelledby", `transfer-tab-${p.dataset.panel}`);
    p.classList.toggle("is-active", selected);
    p.setAttribute("role", "tabpanel");
    p.setAttribute("aria-hidden", String(!selected));
  });
}

const fmtETA = (pct, ratePerTick) => {
  const ticks = Math.max(1, Math.round((100 - pct) / ratePerTick));
  const s = Math.round(ticks * 0.7);
  return s >= 60 ? `${Math.ceil(s / 60)} min remaining` : `${s} s remaining`;
};

function initTransferRow(row) {
  if (row.dataset.bound) return;
  row.dataset.bound = "1";
  const rate = parseFloat(row.dataset.speedRate || "0.5") * 8; // % per 700 ms tick
  let pct = parseFloat((row.querySelector("[data-pct]")?.textContent || "0")) || 0;
  let paused = false, timer = null;

  const bar = row.querySelector(".progress-fill");
  const pctEl = row.querySelector("[data-pct]");
  const etaEl = row.querySelector("[data-eta]");

  const stop = () => { clearInterval(timer); timer = null; };
  const finish = () => {
    stop();
    row.classList.add("is-done");
    if (bar) bar.style.width = "100%";
    if (pctEl) pctEl.innerHTML = `<svg class="icon icon-xs"><use href="#i-check"/></svg>Completed`;
    pctEl?.classList.add("success");
    if (etaEl) etaEl.textContent = "Just now";
    const name = row.querySelector(".transfer-name")?.textContent;
    toast("Transfer completed", `${name} · verified & encrypted`, "success");
    const actions = row.querySelector(".transfer-actions");
    if (actions) actions.innerHTML = `<button class="btn btn-ghost btn-sm" data-act="folder">Open Folder</button>
      <button class="icon-btn" data-act="menu" aria-label="More"><svg class="icon icon-sm"><use href="#i-more-h"/></svg></button>`;
  };
  const tick = () => {
    pct = Math.min(100, pct + rate);
    if (bar) bar.style.width = pct + "%";
    if (pctEl && pctEl.dataset) pctEl.textContent = Math.floor(pct) + "%";
    if (etaEl) etaEl.textContent = fmtETA(pct, rate);
    if (pct >= 100) finish();
  };
  timer = setInterval(() => {
    if (realRuntimeActive && !row.dataset.real) return stop();
    if (!paused) tick();
  }, 700);

  row.addEventListener("click", (e) => {
    const actionButton = e.target.closest("[data-act]");
    const act = actionButton?.dataset.act;
    if (!act) return;
    if (act === "pause") {
      paused = !paused;
      actionButton.innerHTML = paused
        ? `<svg class="icon icon-sm"><use href="#i-play"/></svg>`
        : `<svg class="icon icon-sm"><use href="#i-pause"/></svg>`;
      row.classList.toggle("is-paused", paused);
      if (etaEl) etaEl.textContent = paused ? "Paused" : fmtETA(pct, rate);
      toast(paused ? "Transfer paused" : "Transfer resumed", row.querySelector(".transfer-name")?.textContent || "", paused ? "warning" : "info");
    }
    if (act === "cancel") {
      stop();
      row.classList.add("is-cancelled");
      if (pctEl) { pctEl.textContent = "Cancelled"; pctEl.className = "transfer-pct muted"; }
      if (etaEl) etaEl.textContent = "Cancelled";
      const actions = row.querySelector(".transfer-actions");
      if (actions) actions.innerHTML = `<button class="btn btn-secondary btn-sm" data-act="retry">Retry</button>`;
      toast("Transfer cancelled", row.querySelector(".transfer-name")?.textContent || "", "warning");
    }
    if (act === "retry") {
      row.classList.remove("is-failed", "is-cancelled");
      paused = false;
      pct = 0;
      if (pctEl) { pctEl.textContent = "0%"; pctEl.classList.remove("error", "muted"); }
      if (bar) bar.style.width = "0%";
      if (etaEl) etaEl.textContent = fmtETA(0, rate);
      const actions = row.querySelector(".transfer-actions");
      if (actions) actions.innerHTML = `<button class="icon-btn" data-act="pause" aria-label="Pause"><svg class="icon icon-sm"><use href="#i-pause"/></svg></button>
        <button class="icon-btn" data-act="cancel" aria-label="Cancel"><svg class="icon icon-sm"><use href="#i-x"/></svg></button>`;
      timer = setInterval(() => {
        if (realRuntimeActive && !row.dataset.real) return stop();
        if (!paused) tick();
      }, 700);
      toast("Retrying transfer", row.querySelector(".transfer-name")?.textContent || "", "info");
    }
    if (act === "dismiss") { stop(); row.remove(); }
    if (act === "folder") toast("Opening folder", "C:\\Users\\talba\\Downloads", "info");
  });
}
$$("[data-transfer]").forEach(initTransferRow);

$("#pauseAll")?.addEventListener("click", () => {
  if (realRuntimeActive) return pauseAllRealTransfers();
  $$(".tab-panel[data-panel='active'] [data-act='pause']").forEach((b) => b.click());
  toast("All transfers paused", "Resume individually when ready", "warning");
});
$("#clearCompleted")?.addEventListener("click", () => {
  if (realRuntimeActive) return clearCompletedRealTransfers();
  const rows = $$(".tab-panel[data-panel='completed'] .transfer-row");
  rows.forEach((r) => r.remove());
  toast("Completed transfers cleared", "", "info");
});

function makeTransferRow({ name, dirHTML, total, tone, icon, rate = 7 }) {
  const row = document.createElement("article");
  row.className = "transfer-row lg";
  row.dataset.transfer = "";
  row.dataset.speedRate = rate;
  row.innerHTML = `
    <span class="file-badge ${tone}"><svg class="icon"><use href="#${icon}"/></svg></span>
    <div class="transfer-main">
      <div class="transfer-top">
        <span class="transfer-name">${escapeHTML(name)}</span>
        <span class="transfer-dir">${escapeHTML(String(dirHTML).replace(/<[^>]*>/g, ""))}</span>
        <span class="transfer-pct" data-pct>0%</span>
      </div>
      <div class="progress lg"><div class="progress-fill" style="width:0%"></div></div>
      <div class="transfer-meta">
        <span data-done>0 MB</span> of ${total}
        <i class="sep"></i><span data-speed>94 MB/s</span>
        <i class="sep"></i><span data-eta>connecting…</span>
        <i class="sep"></i><span class="encrypted"><svg class="icon icon-xs"><use href="#i-lock"/></svg>Encrypted</span>
      </div>
    </div>
    <div class="transfer-actions">
      <button class="icon-btn" data-act="pause" aria-label="Pause"><svg class="icon icon-sm"><use href="#i-pause"/></svg></button>
      <button class="icon-btn" data-act="cancel" aria-label="Cancel"><svg class="icon icon-sm"><use href="#i-x"/></svg></button>
    </div>`;
  const list = $(".tab-panel[data-panel='active'] .card.list-card");
  list?.prepend(row);
  initTransferRow(row);
  return row;
}

/* ---------------- Send flow ---------------- */
let sendMode = "files";
function sendStep(n) {
  $$("#ov-send .send-step").forEach((s) => s.classList.toggle("is-active", s.dataset.step === String(n)));
  if (n === 2) {
    const sel = $("#sendDeviceList .send-device.is-selected");
    const name = sel?.dataset.name || sel?.dataset.device || "Device";
    const icon = sel?.dataset.icon || "i-phone";
    $("#confirmDevName").textContent = "Sending to " + name;
    const safeIcon = /^i-[a-z0-9-]+$/.test(icon) ? icon : "i-laptop";
    $("#confirmDevIcon").innerHTML = `<use href="#${safeIcon}"/>`;
    const modeNote = { text: "Text snippet · instant", link: "Link · instant", folder: "Folder · 1 item" }[sendMode];
    if (modeNote && sendMode !== "files") {
      $("#confirmDevName").textContent = "Sending to " + name;
    }
  }
}
function openSend({ device, mode } = {}) {
  sendMode = mode || "files";
  openModal("send");
  const titles = { files: "Send to…", folder: "Send Folder", text: "Send Text", link: "Send Link" };
  $("#sendTitle").textContent = titles[sendMode] || "Send to…";
  const dz = $("#dropzone .dropzone-title");
  if (dz) dz.textContent = { files: "Drop files here", folder: "Drop a folder here", text: "Type or paste text", link: "Paste a link" }[sendMode];
  if (device !== undefined) {
    $$("#sendDeviceList .send-device").forEach((d) => d.classList.toggle("is-selected", d.dataset.device === device));
  }
  if (!$("#sendDeviceList .send-device.is-selected")) {
    $("#sendDeviceList .send-device")?.classList.add("is-selected");
  }
  if (device && !realRuntimeActive) { sendStep(2); $("#ov-send .modal-head h3").textContent = "Confirm transfer"; }
  else sendStep(1);
}
$("#sendDeviceList").addEventListener("click", (e) => {
  const d = e.target.closest(".send-device");
  if (!d) return;
  $$("#sendDeviceList .send-device").forEach((x) => x.classList.remove("is-selected"));
  d.classList.add("is-selected");
});
$("#chooseFiles").addEventListener("click", () => (realRuntimeActive || isNativeAndroid) ? $("#fileInput").click() : toast("File picker", "Start the local DropSync service to choose files", "info", 2400));
$("#chooseFolder").addEventListener("click", () => (realRuntimeActive || isNativeAndroid) ? $("#folderInput").click() : toast("Folder picker", "Start the local DropSync service to choose a folder", "info", 2400));

let nativePickedFiles = [];
function nativeFileSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes, unit = -1;
  do { value /= 1024; unit += 1; } while (value >= 1024 && unit < units.length - 1);
  return `${value >= 10 ? value.toFixed(1) : value.toFixed(2)} ${units[unit]}`;
}
function renderNativePickedFiles() {
  if (!isNativeAndroid) return;
  const pickedList = $("#pickedList");
  const confirmList = $("#ov-send .confirm-files");
  pickedList.replaceChildren();
  confirmList.replaceChildren();
  nativePickedFiles.forEach((file, index) => {
    const picked = document.createElement("li");
    picked.innerHTML = '<span class="file-badge sm tone-accent"><svg class="icon icon-xs"><use href="#i-file"/></svg></span><div class="row-body"><p></p><span></span></div><button class="icon-btn" aria-label="Remove"><svg class="icon icon-sm"><use href="#i-x"/></svg></button>';
    picked.querySelector("p").textContent = file.name;
    picked.querySelector(".row-body > span").textContent = nativeFileSize(file.size);
    picked.querySelector("button").addEventListener("click", () => {
      nativePickedFiles.splice(index, 1);
      renderNativePickedFiles();
    });
    pickedList.appendChild(picked);

    const confirm = document.createElement("li");
    confirm.innerHTML = '<span class="file-badge sm tone-accent"><svg class="icon icon-xs"><use href="#i-file"/></svg></span><div class="row-body"><p></p><span>Selected on Android</span></div><span class="muted mono"></span>';
    confirm.querySelector("p").textContent = file.name;
    confirm.querySelector(".muted").textContent = nativeFileSize(file.size);
    confirmList.appendChild(confirm);
  });
  const total = nativePickedFiles.reduce((sum, file) => sum + file.size, 0);
  $("#ov-send .send-step[data-step='1'] .foot-meta").textContent = `${nativePickedFiles.length} ${nativePickedFiles.length === 1 ? "file" : "files"} · ${nativeFileSize(total)}`;
  const stats = $$("#ov-send .confirm-stats b");
  if (stats[0]) stats[0].textContent = String(nativePickedFiles.length);
  if (stats[1]) stats[1].textContent = nativeFileSize(total);
}
if (isNativeAndroid) {
  [$("#fileInput"), $("#folderInput")].forEach((input) => input.addEventListener("change", (event) => {
    if (realRuntimeActive) return;
    nativePickedFiles = [...event.target.files];
    renderNativePickedFiles();
  }));
  renderNativePickedFiles();
}
$("#sendContinue").addEventListener("click", () => {
  if (realRuntimeActive) return prepareRealSend();
  $("#ov-send .modal-head h3").textContent = "Confirm transfer";
  sendStep(2);
});
$("#sendBack").addEventListener("click", () => { $("#ov-send .modal-head h3").textContent = "Send to…"; sendStep(1); });
$("#startTransfer").addEventListener("click", () => {
  if (realRuntimeActive) {
    startRealTransfers().catch((error) => toast("Transfer could not start", error.message, "error"));
    return;
  }
  if (isNativeAndroid) return toast("Transfer service unavailable", "Reopen DropSync before selecting and sending files", "warning");
  if (isNativeAndroid && !nativePickedFiles.length) {
    sendStep(1);
    toast("Choose files first", "Select at least one file from your device", "warning", 2400);
    return;
  }
  const sel = $("#sendDeviceList .send-device.is-selected");
  const dev = sel?.dataset.device || "Galaxy Phone";
  closeModal($("#ov-send"));
  toast("Transfer started", `3 files · 1.82 GB → ${dev} · encrypted`, "accent");
  makeTransferRow({
    name: sendMode === "folder" ? "holiday-album" : "holiday-photos",
    dirHTML: `Sending to <strong>${dev}</strong>`,
    total: "1.82 GB", tone: "tone-clay", icon: sendMode === "folder" ? "i-folder" : "i-image",
  });
});

/* ---------------- Pairing modal ---------------- */
let pairTimer = null, pairCountdown = 300;
async function startPairing() {
  pairCountdown = 300;
  stopPairing();
  $(".pairing-code .code").textContent = realRuntimeActive ? "------" : "482-917";
  if (realRuntimeActive && !runtimeState.pendingPairDeviceId) {
    $("#pairTarget").hidden = true;
    $("#pairConfirm").hidden = true;
    $("#pairHostSession").hidden = false;
    $("#manualConnect").hidden = false;
    $("#pairLede").textContent = "Use this single-use code on the other DropSync device.";
  } else if (realRuntimeActive) {
    $("#pairHostSession").hidden = false;
    $("#manualConnect").hidden = true;
    $("#pairLede").textContent = "Enter the other device's code below, or use your code on that device.";
  }
  if (realRuntimeActive) {
    try {
      const session = await apiRequest("/api/pairing/session", { method: "POST" });
      runtimeState.pairingSession = session;
      $("#pairSelfFingerprint").textContent = session.self?.fingerprint || "—";
      $(".pairing-code .code").textContent = session.code.replace(/(\d{3})(\d{3})/, "$1-$2");
      pairCountdown = Math.max(0, Math.ceil((session.expiresAt - Date.now()) / 1000));
    } catch (error) {
      toast("Pairing unavailable", error.message, "error");
    }
  }
  pairTimer = setInterval(() => {
    pairCountdown = runtimeState?.pairingSession
      ? Math.max(0, Math.ceil((runtimeState.pairingSession.expiresAt - Date.now()) / 1000))
      : Math.max(0, pairCountdown - 1);
    const m = Math.floor(pairCountdown / 60), s = String(pairCountdown % 60).padStart(2, "0");
    const el = $("#pairCountdown");
    if (el) el.textContent = `${m}:${s}`;
    if (pairCountdown === 0) stopPairing();
  }, 1000);
}
function stopPairing() { clearInterval(pairTimer); }
$("#copyCode").addEventListener("click", () => copyText($(".pairing-code .code").textContent.replace(/\D/g, "")));
$("#pairConfirm").addEventListener("click", async () => {
  if (realRuntimeActive) {
    try { await pairSelectedDevice(); } catch (error) { toast("Pairing failed", error.message, "error"); }
    return;
  }
  closeModal($("#ov-pairing"));
  toast("Device paired", "The device is now trusted", "success");
});
function copyText(t) {
  try { navigator.clipboard?.writeText(t); } catch (e) { /* noop */ }
  toast("Copied to clipboard", t.length > 40 ? "" : t, "success", 2200);
}

/* ---------------- Trust modal ---------------- */
$("#trustAlways").addEventListener("click", () => {
  closeModal($("#ov-trust"));
  toast("Galaxy Tab is now trusted", "It can send files without repeated approval", "success");
  const chip = $("#newDeviceChip");
  if (chip) {
    chip.classList.remove("is-new");
    chip.querySelector(".badge")?.replaceWith(Object.assign(document.createElement("span"), { className: "badge badge-accent-soft", innerHTML: `<svg class="icon icon-xs"><use href="#i-shield-check"/></svg>Trusted` }));
    chip.querySelector(".device-chip-meta").innerHTML = `<span class="dot success"></span>Nearby`;
  }
  const card = $('.device-card.is-pending');
  if (card) {
    card.classList.remove("is-pending");
    const b = card.querySelector(".badge-warning");
    if (b) b.outerHTML = `<span class="badge badge-accent-soft"><svg class="icon icon-xs"><use href="#i-shield-check"/></svg>Trusted</span>`;
    const foot = card.querySelector(".device-card-foot");
    if (foot) foot.innerHTML = `
      <button class="btn btn-primary btn-sm" data-act="send">Send</button>
      <button class="btn btn-secondary btn-sm" data-act="connect">Connect</button>
      <button class="icon-btn" data-act="menu" aria-label="More"><svg class="icon icon-sm"><use href="#i-more-h"/></svg></button>`;
    card.dataset.trust = "Trusted device";
  }
});
$("#trustOnce").addEventListener("click", () => { closeModal($("#ov-trust")); toast("Allowed once", "Galaxy Tab can send files during this session", "info"); });
$("#trustDecline").addEventListener("click", () => { closeModal($("#ov-trust")); toast("Request declined", "Galaxy Tab was not allowed to connect", "info"); });

/* ---------------- Incoming transfer ---------------- */
$("#acceptTransfer").addEventListener("click", () => {
  decideIncoming(true).catch((error) => toast("Could not accept file", error.message, "error"));
});
$("#declineTransfer").addEventListener("click", () => { decideIncoming(false).catch((error) => toast("Could not decline file", error.message, "error")); });

/* ---------------- Clipboard modal ---------------- */
$$("[data-clip]").forEach((b) => b.addEventListener("click", () => {
  const a = b.dataset.clip;
  if (a === "copy") copyText("Clipboard content");
  if (a === "save") toast("Saved to Downloads", "", "success");
  if (a === "send") { closeModal($("#ov-clipboard")); openSend({ device: "Galaxy Phone" }); }
}));

/* ---------------- Nearby page: filters ---------------- */
const deviceCards = $$(".device-card");
function applyDeviceFilters() {
  const q = ($("#deviceSearch")?.value || "").toLowerCase();
  const mode = $(".seg-btn.is-active")?.dataset.seg || "all";
  const favOnly = $("#favFilter")?.classList.contains("is-active");
  let visible = 0;
  deviceCards.forEach((c) => {
    const name = c.dataset.name.toLowerCase();
    const online = c.classList.contains("is-online");
    const fav = c.classList.contains("is-fav");
    const ok = (!q || name.includes(q)) &&
               (mode === "all" || (mode === "online" && online) || (mode === "offline" && !online)) &&
               (!favOnly || fav);
    c.style.display = ok ? "" : "none";
    if (ok) visible++;
  });
  const empty = $("#deviceEmpty");
  if (empty) empty.hidden = visible > 0;
  $("#deviceGrid").style.display = visible ? "" : "none";
}
$("#deviceSearch")?.addEventListener("input", applyDeviceFilters);
$$(".seg-btn").forEach((b) => b.addEventListener("click", () => {
  $$(".seg-btn").forEach((x) => x.classList.remove("is-active"));
  b.classList.add("is-active");
  applyDeviceFilters();
}));
$("#favFilter")?.addEventListener("click", (e) => { e.currentTarget.classList.toggle("is-active"); applyDeviceFilters(); });
$("#typeFilter")?.addEventListener("click", (e) => {
  const r = e.currentTarget.getBoundingClientRect();
  const set = (label, pred) => ({ label, icon: "i-filter", action: () => {
    deviceCards.forEach((c) => {
      const ic = c.dataset.icon;
      const ok = pred(ic);
      c.style.display = ok ? "" : "none";
    });
    $("#deviceEmpty").hidden = deviceCards.some((c) => c.style.display !== "none");
  }});
  openMenu([
    { label: "All device types", icon: "i-grid", action: () => { deviceCards.forEach((c) => (c.style.display = "")); $("#deviceEmpty").hidden = true; } },
    set("Computers", (ic) => ["i-monitor", "i-laptop"].includes(ic)),
    set("Phones", (ic) => ic === "i-phone"),
    set("Tablets", (ic) => ic === "i-tablet"),
    set("Boards", (ic) => ic === "i-pi"),
  ], r.left, r.bottom + 6);
});
$("#refreshDiscovery")?.addEventListener("click", refreshDiscovery);
$("#dashRefresh")?.addEventListener("click", refreshDiscovery);
$("#emptyRefresh")?.addEventListener("click", refreshDiscovery);
function refreshDiscovery(e) {
  const btn = e.currentTarget;
  btn.classList.add("is-loading");
  const note = $("#discoverNote");
  if (note) note.innerHTML = `<span class="spinner"></span>Refreshing discovery…`;
  setTimeout(() => {
    btn.classList.remove("is-loading");
    if (note) note.innerHTML = `<span class="dot accent"></span>Discovering · signed local announcements`;
    const count = realRuntimeActive ? runtimeState.devices.length : 0;
    toast("Discovery refreshed", count ? `${count} nearby device${count === 1 ? "" : "s"} found` : "No nearby devices found yet", "info");
  }, 1100);
}

/* Device card inline actions */
document.addEventListener("click", (e) => {
  const card = e.target.closest(".device-card");
  if (!card) return;
  const act = e.target.closest("[data-act]")?.dataset.act;
  if (act === "send") { e.stopPropagation(); openSend({ device: card.dataset.name }); }
  if (act === "connect") { e.stopPropagation(); toast("Device connected", `${card.dataset.name} · encrypted session established`, "success"); }
  if (act === "dismiss") { e.stopPropagation(); card.style.display = "none"; toast("Dismissed", "You can find this device in Contacts", "info"); }
});

/* ---------------- History search ---------------- */
$("#historySearch")?.addEventListener("input", (e) => {
  const q = e.target.value.toLowerCase();
  $$(".history-table tbody tr").forEach((tr) => {
    tr.style.display = tr.textContent.toLowerCase().includes(q) ? "" : "none";
  });
});

/* ---------------- Storage ---------------- */
$("#clearCache")?.addEventListener("click", (e) => {
  const b = e.currentTarget;
  b.classList.add("is-loading");
  setTimeout(() => {
    b.classList.remove("is-loading");
    toast("Transfer cache cleared", "8.2 GB freed", "success");
  }, 1000);
});

/* ---------------- Network test ---------------- */
$("#runTest")?.addEventListener("click", () => {
  const box = $("#testResult"), bar = $("#testResult .progress-fill"), note = $("#testNote");
  box.hidden = false;
  let p = 0;
  const stages = ["Measuring latency…", "Testing throughput…", "Verifying discovery…", "Complete"];
  const iv = setInterval(() => {
    p += 4;
    bar.style.width = Math.min(100, p) + "%";
    note.textContent = stages[Math.min(stages.length - 1, Math.floor(p / 28))];
    if (p >= 100) {
      clearInterval(iv);
      note.innerHTML = `<span class="badge badge-success"><svg class="icon icon-xs"><use href="#i-check"/></svg>Healthy</span> 2 ms latency · 94 MB/s throughput · discovery active`;
      toast("Connection test passed", "Everything looks healthy", "success");
    }
  }, 60);
});
$("#refreshNet")?.addEventListener("click", (e) => {
  e.currentTarget.classList.add("is-loading");
  setTimeout(() => { e.currentTarget.classList.remove("is-loading"); toast("Network refreshed", "7 devices discovered", "info"); }, 900);
});

/* ---------------- Notifications ---------------- */
const bellBtn = $("#bellBtn"), notifPopover = $("#notifPopover");
bellBtn.addEventListener("click", (e) => {
  e.stopPropagation();
  notifPopover.hidden = !notifPopover.hidden;
});
document.addEventListener("click", (e) => {
  if (!notifPopover.hidden && !notifPopover.contains(e.target) && !bellBtn.contains(e.target)) notifPopover.hidden = true;
});
$("#markRead").addEventListener("click", () => {
  $$("#notifList li").forEach((li) => li.classList.remove("is-unread"));
  $("#bellBadge").style.display = "none";
  toast("All notifications marked as read", "", "info", 2000);
});
$("#clearNotifs").addEventListener("click", () => {
  $("#notifList").innerHTML = `<li class="notif-empty" style="justify-content:center;padding:28px;color:var(--text-3);font-size:12.5px">You're all caught up.</li>`;
  $("#bellBadge").style.display = "none";
});

/* Profile menu */
$("#profileBtn").addEventListener("click", (e) => {
  const r = e.currentTarget.getBoundingClientRect();
  openMenu([
    { label: "Set status", icon: "i-user" },
    { label: "My device details", icon: "i-monitor", action: () => { location.hash = "#nearby"; openDrawer("taxperia-pc"); } },
    { label: "Pause all transfers", icon: "i-pause", action: () => toast("All transfers paused", "", "warning") },
    "-",
    { label: "Security status", icon: "i-shield-check", action: () => toast("Security status", "Local build · run the test suite after updating Node.js", "info") },
    { label: "Quit DropSync", icon: "i-power", danger: true },
  ], r.right - 210, r.top - 190);
});

/* ---------------- Global search ---------------- */
const searchOverlay = $("#ov-search");
function filterSearch(q) {
  q = q.trim().toLowerCase();
  let any = false;
  $$("#searchResults .sr-group").forEach((g) => {
    let gAny = false;
    $$(".sr-item", g).forEach((it) => {
      const ok = !q || it.textContent.toLowerCase().includes(q);
      it.style.display = ok ? "" : "none";
      if (ok) gAny = true;
    });
    g.style.display = gAny ? "" : "none";
    if (gAny) any = true;
  });
  let empty = $("#searchResults .sr-empty");
  if (!any) {
    if (!empty) { empty = document.createElement("p"); empty.className = "sr-empty"; empty.textContent = "No results — try a file, device or setting name."; $("#searchResults").appendChild(empty); }
    empty.style.display = "";
  } else empty && (empty.style.display = "none");
}
$("#searchInput").addEventListener("input", (e) => filterSearch(e.target.value));
$("#searchInput").addEventListener("keydown", (e) => {
  if (e.key === "Enter") $("#searchResults .sr-item:not([style*='display: none'])")?.click();
});
$("#globalSearchInput").addEventListener("click", () => openModal("search"));

/* ---------------- Quick send ---------------- */
const qsOverlay = $("#ov-quicksend");
const qsInput = $("#qsInput");
function filterQS() {
  const q = qsInput.value.toLowerCase();
  $$("#qsList .qs-item").forEach((it) => it.style.display = it.dataset.device.toLowerCase().includes(q) ? "" : "none");
}
qsInput.addEventListener("input", filterQS);
qsInput.addEventListener("keydown", (e) => {
  const items = $$("#qsList .qs-item").filter((i) => i.style.display !== "none");
  const cur = items.indexOf($("#qsList .qs-item.is-selected"));
  if (e.key === "ArrowDown") { e.preventDefault(); items[Math.min(items.length - 1, cur + 1)]?.classList.add("is-selected"); items[cur]?.classList.remove("is-selected"); }
  if (e.key === "ArrowUp") { e.preventDefault(); items[Math.max(0, cur - 1)]?.classList.add("is-selected"); items[cur]?.classList.remove("is-selected"); }
  if (e.key === "Enter") { $("#qsList .qs-item.is-selected")?.click(); }
});
$("#qsList").addEventListener("click", (e) => {
  const it = e.target.closest(".qs-item");
  if (!it) return;
  closeModal(qsOverlay);
  openSend({ device: it.dataset.device });
  toast("Quick send", `Ready to send to ${it.dataset.device}`, "info", 2000);
});

/* ---------------- Drag & drop overlay ---------------- */
const dragOverlay = $("#dragOverlay");
let dragDepth = 0;
window.addEventListener("dragenter", (e) => {
  if (![...(e.dataTransfer?.types || [])].includes("Files")) return;
  dragDepth++;
  dragOverlay.hidden = false;
  $("#dropzone")?.classList.add("is-dragover");
});
window.addEventListener("dragleave", () => {
  dragDepth = Math.max(0, dragDepth - 1);
  if (dragDepth === 0) { dragOverlay.hidden = true; $("#dropzone")?.classList.remove("is-dragover"); }
});
window.addEventListener("dragover", (e) => e.preventDefault());
window.addEventListener("drop", (e) => {
  e.preventDefault();
  dragDepth = 0;
  dragOverlay.hidden = true;
  const dev = e.target.closest(".drag-device")?.dataset.device;
  $("#dropzone")?.classList.remove("is-dragover");
  if (dev) { openSend({ device: dev }); toast("Files ready", `Dropped for ${dev}`, "accent"); }
  else toast("Files received", "Choose a device to start the transfer", "accent");
});
$$(".drag-device").forEach((b) => b.addEventListener("click", () => {
  dragOverlay.hidden = true;
  openSend({ device: b.dataset.device });
}));

/* ---------------- Settings modal ---------------- */
const SWATCHES = [
  ["Teal", "#53B89E"], ["Ocean", "#5B9DD6"], ["Sage", "#8FBF7F"], ["Clay", "#C98A5B"], ["Violet", "#9B8BD8"],
];
const S = [{ id: "general", icon: "i-gear", title: "General", desc: "Local device preferences", groups: [] }];

function controlHTML(item) {
  const [type, label, desc, val, extra, effect] = item;
  const text = `<div class="set-row-text"><p>${label}</p>${desc ? `<span>${desc}</span>` : ""}</div>`;
  switch (type) {
    case "toggle": {
      const fx = effect === "compact" ? ' data-effect="compact"' : effect === "reduced" ? ' data-effect="reduced"' : "";
      return `<div class="set-row">${text}<div class="set-row-control"><button class="toggle ${val ? "is-on" : ""}"${fx} role="switch" aria-checked="${!!val}" aria-label="${label}"><i></i></button></div></div>`;
    }
    case "select":
      return `<div class="set-row">${text}<div class="set-row-control"><div class="select"><select aria-label="${label}">${extra.map((o) => `<option ${o === val ? "selected" : ""}>${o}</option>`).join("")}</select><svg class="icon icon-xs"><use href="#i-chevron-down"/></svg></div></div></div>`;
    case "text":
      return `<div class="set-row">${text}<div class="set-row-control"><input class="input" style="width:200px" value="${escapeHTML(val)}" aria-label="${escapeHTML(label)}"></div></div>`;
    case "number":
      return `<div class="set-row">${text}<div class="set-row-control"><input class="input setting-number" type="number" min="${extra[0]}" max="${extra[1]}" step="1" value="${escapeHTML(val)}" aria-label="${escapeHTML(label)}"></div></div>`;
    case "action":
      return `<div class="set-row">${text}<div class="set-row-control"><button class="btn btn-secondary btn-sm" data-feature-action="${escapeHTML(extra)}">${escapeHTML(val)}</button></div></div>`;
    case "status":
      return `<div class="set-row">${text}<div class="set-row-control setting-status">${escapeHTML(val)}</div></div>`;
    case "path":
      return `<div class="set-row">${text}<div class="set-row-control path-input"><input class="input mono" style="width:220px" value="${escapeHTML(val)}" aria-label="${escapeHTML(label)}"><button class="btn btn-ghost btn-sm" data-apply-path>Apply</button></div></div>`;
    case "stepper":
      return `<div class="set-row">${text}<div class="set-row-control"><div class="stepper" data-min="${extra?.[0] ?? 0}" data-max="${extra?.[1] ?? 999}"><button aria-label="decrease">−</button><span class="${effect === "font" ? "" : "mono"}">${val}${effect === "font" ? " px" : ""}</span><button aria-label="increase">+</button></div></div></div>`;
    case "range":
      return `<div class="set-row">${text}<div class="set-row-control range"><input type="range" min="0" max="100" value="${val}"><span class="mono">${val}%</span></div></div>`;
    case "key":
      return `<div class="set-row">${text}<div class="set-row-control key-capture">${val.map((k) => `<span class="kbd">${escapeHTML(k)}</span>`).join("")}<button class="btn btn-ghost btn-xs" style="margin-left:6px" disabled title="Global shortcut registration requires the future desktop shell">Change</button></div></div>`;
    case "button": {
      const danger = extra ? "" : "";
      return `<div class="set-row">${text}<div class="set-row-control"><button class="btn ${extra ? "btn-danger-ghost" : "btn-secondary"} btn-sm" data-toast="${label}">${val}</button></div></div>`;
    }
    case "swatch":
      return `<div class="set-row">${text}<div class="set-row-control swatches">${SWATCHES.map(([n, c], i) => `<button class="swatch ${i === 0 ? "is-on" : ""}" data-swatch="${c}" title="${n}" aria-label="Accent ${n}" style="background:${c}"></button>`).join("")}</div></div>`;
    case "info":
      return `<p class="set-info"><svg class="icon"><use href="#i-shield-check"/></svg>${label}</p>`;
    default:
      return "";
  }
}

function renderSettings(catId) {
  const cat = S.find((c) => c.id === catId) || S[0];
  catId = cat.id;
  const pane = $("#settingsPane");
  $$("#settingsNav .set-cat").forEach((b) => b.classList.toggle("is-active", b.dataset.cat === catId));
  if (["api", "profile", "tailscale", "organization", "project-about"].includes(cat.custom)) { window.renderDropSyncSettings?.(cat, pane); return; }
  if (cat.custom === "updates") {
    pane.innerHTML = '<div class="set-header"><h4>Updates</h4><p>Packages must pass signature and integrity checks before installation.</p></div><div id="updateSettings" class="set-block" aria-live="polite">Loading update status…</div>';
    window.renderDropSyncUpdates?.();
    return;
  }

  pane.innerHTML = `
    <div class="set-header"><h4>${cat.title}</h4><p>${cat.desc}</p></div>
    ${cat.groups.map((g) => `
      <div class="set-group"><h5>${g.name}</h5><div class="set-block">
        ${g.items.map(controlHTML).join("")}
      </div></div>`).join("")}`;
  if (realRuntimeActive && typeof hydrateSettingsControls === "function") hydrateSettingsControls();
}

/* Build settings nav once */
(function buildSettingsNav() {
  const nav = $("#settingsNav");
  nav.innerHTML = S.map((c) => `<button class="set-cat" data-cat="${c.id}"><svg class="icon"><use href="#${c.icon}"/></svg>${c.title}</button>`).join("");
  nav.addEventListener("click", (e) => { const b = e.target.closest(".set-cat"); if (b) renderSettings(b.dataset.cat); });
  renderSettings("general");
})();

/* Settings interactions */
document.addEventListener("click", (e) => {
  const tg = e.target.closest(".toggle");
  if (tg) {
    tg.classList.toggle("is-on");
    tg.setAttribute("aria-checked", tg.classList.contains("is-on"));
    if (tg.dataset.effect === "compact") $("#app").classList.toggle("compact", tg.classList.contains("is-on"));
    return;
  }
  const sw = e.target.closest("[data-swatch]");
  if (sw) {
    $$(".swatch").forEach((s) => s.classList.remove("is-on"));
    sw.classList.add("is-on");
    const c = sw.dataset.swatch;
    const r = document.documentElement.style;
    r.setProperty("--accent", c);
    r.setProperty("--accent-hover", c + "e6");
    r.setProperty("--accent-press", c + "cc");
    r.setProperty("--accent-text", "#0B1512");
    toast("Accent color updated", sw.title, "success", 2000);
    return;
  }
  const tb = e.target.closest("[data-toast]");
  if (tb) { toast(tb.dataset.toast, "This control is not available in the local build yet", "info", 2200); return; }
});

/* ---------------- Keyboard shortcuts ---------------- */
window.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    if (!ctxMenu.hidden) return closeMenu();
    if (!$("#notifPopover").hidden) return ($("#notifPopover").hidden = true);
    const top = modalStack[modalStack.length - 1];
    if (top) return closeModal(top);
    if (!drawer.hidden) return closeDrawer();
    if (appShell.classList.contains("mobile-nav-open")) return closeMobileMenu();
  }
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); $("#ov-search").hidden ? openModal("search") : closeModal($("#ov-search")); }
  if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key.toLowerCase() === "s") { e.preventDefault(); qsOverlay.hidden ? (openModal("quicksend"), qsInput.focus()) : closeModal(qsOverlay); }
  if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key.toLowerCase() === "f") { e.preventDefault(); openSend({}); }
  if (e.key === "Tab" && modalStack.length) {
    const top = modalStack[modalStack.length - 1];
    const focusable = $$(focusableSelector, top).filter((element) => element.offsetParent !== null);
    if (!focusable.length) return;
    const first = focusable[0], last = focusable[focusable.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  } else if (e.key === "Tab" && !drawer.hidden) {
    const focusable = $$(focusableSelector, drawer).filter((element) => element.offsetParent !== null);
    if (!focusable.length) return;
    const first = focusable[0], last = focusable[focusable.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  }
});

/* Focus the search input whenever the search overlay opens */
new MutationObserver(() => { if (!$("#ov-search").hidden) $("#searchInput").focus(); })
  .observe($("#ov-search"), { attributes: true, attributeFilter: ["hidden"] });
new MutationObserver(() => { if (!qsOverlay.hidden) qsInput.focus(); })
  .observe(qsOverlay, { attributes: true, attributeFilter: ["hidden"] });

/* ---------------- Boot ---------------- */
applyRoute();
setTimeout(() => {
  if (!realRuntimeActive && !isNativeAndroid) toast("DropSync prototype mode", "Start the local service for real discovery and transfers", "warning", 3800);
}, 600);
