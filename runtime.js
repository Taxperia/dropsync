"use strict";

const runtimeState = {
  csrfToken: "",
  self: null,
  settings: null,
  devices: [],
  trustedDevices: [],
  transfers: [],
  stagedFiles: [],
  incomingRequests: [],
  pairingSession: null,
  discovery: null,
  pendingPairDeviceId: null,
  eventSource: null,
  saveTimer: null,
  pendingSettingsPatch: { ui: {} },
  capabilities: { discovery: false, pairing: false, transferSend: false, transferReceive: false },
};

const nativeRequests = new Map();
let nativeRequestSequence = 0;
window.completeDropSyncRequest = (id, encoded) => {
  const pending = nativeRequests.get(id);
  if (!pending) return;
  nativeRequests.delete(id);
  clearTimeout(pending.timer);
  try {
    const payload = JSON.parse(encoded);
    if (payload.__error) pending.reject(new Error(payload.__error));
    else pending.resolve(payload);
  } catch (error) { pending.reject(error); }
};

async function apiRequest(url, options = {}) {
  const method = options.method || "GET";
  if (isNativeAndroid) {
    if (options.body instanceof Blob) throw new Error("Choose files using the Android file picker or share them to DropSync.");
    const body = options.body == null ? "" : typeof options.body === "string" ? options.body : JSON.stringify(options.body);
    if (typeof window.DropSyncAndroid.requestAsync === "function") {
      return new Promise((resolve, reject) => {
        const id = String(++nativeRequestSequence);
        const timer = setTimeout(() => {
          nativeRequests.delete(id);
          reject(new Error("The Android service did not respond. Reopen DropSync and try again."));
        }, url.startsWith("/api/updates/") ? 11 * 60 * 1000 : 5 * 60 * 1000);
        nativeRequests.set(id, { resolve, reject, timer });
        try { window.DropSyncAndroid.requestAsync(id, url, method, body); }
        catch (error) { nativeRequests.delete(id); clearTimeout(timer); reject(error); }
      });
    }
    const payload = JSON.parse(window.DropSyncAndroid.request(url, method, body));
    if (payload.__error) throw new Error(payload.__error);
    return payload;
  }
  if (location.protocol === "file:") throw new Error("This build has no local transfer service. No files have been sent.");
  const headers = new Headers(options.headers || {});
  headers.set("Accept", "application/json");
  if (!["GET", "HEAD"].includes(method) && runtimeState.csrfToken) headers.set("X-DropSync-CSRF", runtimeState.csrfToken);
  let body = options.body;
  if (body && !(body instanceof Blob) && typeof body !== "string") {
    headers.set("Content-Type", "application/json; charset=utf-8");
    body = JSON.stringify(body);
  }
  const response = await fetch(url, { ...options, method, headers, body });
  let payload = {};
  try { payload = await response.json(); } catch { /* non-JSON response */ }
  if (!response.ok) throw new Error(payload.error || `Request failed (${response.status})`);
  return payload;
}

function svgIcon(id, className = "icon") {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("class", className);
  const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
  use.setAttribute("href", `#${id}`);
  svg.appendChild(use);
  return svg;
}

function formatBytes(bytes) {
  const value = Number(bytes) || 0;
  if (value < 1024) return `${value} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let amount = value;
  let unit = -1;
  do { amount /= 1024; unit += 1; } while (amount >= 1024 && unit < units.length - 1);
  return `${amount >= 10 ? amount.toFixed(1) : amount.toFixed(2)} ${units[unit]}`;
}

function relativeSeen(timestamp) {
  if (!timestamp) return "Offline";
  const seconds = Math.max(0, Math.round((Date.now() - timestamp) / 1000));
  if (seconds < 10) return "Just now";
  if (seconds < 60) return `${seconds}s ago`;
  return `${Math.round(seconds / 60)}m ago`;
}

function deviceIcon(device) {
  if (device.deviceId === runtimeState.self?.deviceId) {
    if (isNativeAndroid) return window.DropSyncAndroid?.isTelevision?.() ? "i-monitor" : "i-phone";
    return navigator.userAgent.includes("DropSyncDesktop/") ? "i-monitor" : "i-browser";
  }
  const type = device.deviceType || (device.capabilities?.transferReceive === false ? "phone" : "desktop");
  return { phone: "i-phone", desktop: "i-monitor", browser: "i-browser", tv: "i-monitor" }[type] || "i-monitor";
}

function createDeviceCard(device) {
  const card = document.createElement("article");
  card.className = `device-card ${device.online ? "is-online" : "is-offline"}`;
  card.dataset.device = device.deviceId;
  card.dataset.name = device.name;
  card.dataset.type = device.deviceId === runtimeState.self?.deviceId ? "This device" : "DropSync peer";
  card.dataset.icon = deviceIcon(device);
  card.dataset.status = device.online ? "online" : "offline";
  card.dataset.quality = device.online ? "Local network" : "Offline";
  card.dataset.q = device.online ? "4" : "0";
  card.dataset.speed = "Measured during transfer";
  card.dataset.lastxfer = "—";
  card.dataset.total = "—";
  card.dataset.ip = device.address || "127.0.0.1";
  card.dataset.trust = device.trusted ? "Trusted device" : "Not paired";

  const head = document.createElement("div");
  head.className = "device-card-head";
  const icon = document.createElement("span");
  icon.className = "device-ic";
  icon.appendChild(svgIcon(deviceIcon(device)));
  const body = document.createElement("div");
  body.className = "device-card-title";
  const name = document.createElement("h4");
  name.textContent = device.name;
  const meta = document.createElement("p");
  meta.textContent = device.deviceId === runtimeState.self?.deviceId ? "This device" : device.address ? `${device.address}:${device.port}` : "Paired device · offline";
  body.append(name, meta);
  const badge = document.createElement("span");
  badge.className = device.trusted ? "badge badge-accent-soft" : "badge badge-warning";
  badge.textContent = device.deviceId === runtimeState.self?.deviceId ? "Local" : device.trusted ? "Trusted" : "Pair required";
  head.append(icon, body, badge);

  const details = document.createElement("div");
  details.className = "device-card-details";
  const rows = [
    ["Status", device.online ? "Online" : "Offline"],
    ["Last seen", relativeSeen(device.lastSeen)],
    ["Fingerprint", device.fingerprint || runtimeState.self?.fingerprint || "—"],
  ];
  rows.forEach(([label, value]) => {
    const row = document.createElement("div");
    row.className = "device-card-row";
    const left = document.createElement("span");
    left.textContent = label;
    const right = document.createElement("span");
    right.textContent = value;
    if (label === "Fingerprint") right.className = "mono";
    row.append(left, right);
    details.appendChild(row);
  });

  const footer = document.createElement("div");
  footer.className = "device-card-foot";
  if (device.deviceId !== runtimeState.self?.deviceId) {
    const action = document.createElement("button");
    action.type = "button";
    const canSend = device.trusted && runtimeState.capabilities?.transferSend !== false && device.capabilities?.transferReceive !== false;
    action.className = canSend ? "btn btn-primary btn-sm" : "btn btn-secondary btn-sm";
    if (!device.trusted) action.dataset.realPair = device.deviceId;
    else if (canSend) action.dataset.realSendDevice = device.deviceId;
    action.textContent = !device.trusted ? "Pair Device" : canSend ? "Send Files" : "Paired";
    action.disabled = !device.online || (device.trusted && !canSend);
    footer.appendChild(action);
  }
  card.append(head, details, footer);
  return card;
}

function renderDevices() {
  const grid = $("#deviceGrid");
  if (grid) {
    grid.replaceChildren();
    runtimeState.devices.forEach((device) => grid.appendChild(createDeviceCard(device)));
    const hasPeers = runtimeState.devices.length > 0;
    $("#deviceEmpty").hidden = hasPeers;
    grid.style.display = hasPeers ? "" : "none";
  }

  const strip = $("#dashDevices");
  if (strip) {
    strip.replaceChildren();
    const list = [{ ...runtimeState.self, online: !runtimeState.unavailable, trusted: true }, ...runtimeState.devices].slice(0, 7);
    strip.hidden = false;
    strip.classList.toggle("is-waiting", !list.length);
    strip.setAttribute("aria-label", list.length ? "Nearby DropSync devices" : "Waiting for nearby DropSync devices");
    list.forEach((device) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = `device-chip ${device.deviceId === runtimeState.self.deviceId ? "is-this" : ""}`;
      button.classList.toggle("is-offline", !device.online);
      if (device.deviceId !== runtimeState.self.deviceId) {
        const canSend = device.trusted && runtimeState.capabilities?.transferSend !== false && device.capabilities?.transferReceive !== false;
        if (!device.trusted) button.dataset.realPair = device.deviceId;
        else if (canSend) button.dataset.realSendDevice = device.deviceId;
        button.disabled = !device.online || (device.trusted && !canSend);
      }
      const icon = document.createElement("span");
      icon.className = "device-ic";
      icon.appendChild(svgIcon(deviceIcon(device)));
      const body = document.createElement("span");
      body.className = "device-chip-body";
      const name = document.createElement("span");
      name.className = "device-chip-name";
      name.textContent = device.name;
      const meta = document.createElement("span");
      meta.className = "device-chip-meta";
      const dot = document.createElement("span");
      dot.className = `dot ${device.online ? "success" : "muted"}`;
      meta.append(dot, document.createTextNode(device.deviceId === runtimeState.self.deviceId ? "This device" : !device.online ? "Offline" : device.trusted ? "Connected" : "Pair required"));
      body.append(name, meta);
      button.append(icon, body);
      const signal = document.createElement("span");
      signal.className = "qbars";
      signal.setAttribute("aria-label", device.online ? "Connected" : "Offline");
      for (let i = 0; i < 4; i++) {
        const bar = document.createElement("i");
        if (device.online) bar.className = "on";
        signal.appendChild(bar);
      }
      button.appendChild(signal);
      strip.appendChild(button);
    });
    if (!runtimeState.devices.length) {
      const note = document.createElement("button");
      note.className = "device-chip device-placeholder";
      note.dataset.openModal = "pairing";
      note.append(svgIcon("i-plus"), document.createTextNode("Pair your first device"));
      strip.appendChild(note);
    }
  }

  const dashboardSubtitle = $("#nearbySubtitle");
  if (dashboardSubtitle) {
    const count = runtimeState.devices.filter((d) => d.online).length;
    dashboardSubtitle.textContent = runtimeState.unavailable ? "Transfer service is offline"
      : runtimeState.devices.length ? `${count} connected · ${runtimeState.devices.length - count} offline`
      : "Scanning your local network for DropSync devices";
  }

  const sendList = $("#sendDeviceList");
  if (sendList) {
    const selectedId = sendList.querySelector(".is-selected")?.dataset.device;
    sendList.replaceChildren();
    runtimeState.devices.filter((device) => device.trusted && device.online && runtimeState.capabilities?.transferSend !== false && device.capabilities?.transferReceive !== false).forEach((device, index) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = `send-device ${(selectedId ? selectedId === device.deviceId : index === 0) ? "is-selected" : ""}`;
      button.dataset.device = device.deviceId;
      button.dataset.name = device.name;
      button.dataset.icon = deviceIcon(device);
      const icon = document.createElement("span");
      icon.className = "device-ic sm";
      icon.appendChild(svgIcon(deviceIcon(device), "icon icon-xs"));
      const body = document.createElement("span");
      body.className = "row-body";
      const name = document.createElement("p");
      name.textContent = device.name;
      const meta = document.createElement("span");
      meta.textContent = `${device.address}:${device.port} · encrypted`;
      body.append(name, meta);
      button.append(icon, body, svgIcon("i-check", "icon icon-sm check"));
      sendList.appendChild(button);
    });
    if (!sendList.children.length) {
      const empty = document.createElement("p");
      empty.className = "runtime-empty";
      empty.textContent = "No paired online devices. Pair a nearby device first.";
      sendList.appendChild(empty);
    }
  }

  const quickList = $("#qsList");
  if (quickList) {
    quickList.replaceChildren();
    runtimeState.devices.filter((device) => device.trusted && device.online && runtimeState.capabilities?.transferSend !== false && device.capabilities?.transferReceive !== false).forEach((device, index) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = `qs-item ${index === 0 ? "is-selected" : ""}`;
      button.dataset.device = device.deviceId;
      button.dataset.name = device.name;
      const body = document.createElement("span");
      body.className = "row-body";
      const name = document.createElement("p"); name.textContent = device.name;
      const detail = document.createElement("span"); detail.textContent = `${device.address}:${device.port} · trusted`;
      body.append(name, detail);
      button.append(svgIcon(deviceIcon(device), "icon icon-sm"), body);
      quickList.appendChild(button);
    });
    if (!quickList.children.length) quickList.appendChild(createEmpty("No paired online devices."));
  }

  const dragList = $("#dragOverlay .drag-devices");
  if (dragList) {
    dragList.replaceChildren();
    runtimeState.devices.filter((device) => device.trusted && device.online && runtimeState.capabilities?.transferSend !== false && device.capabilities?.transferReceive !== false).forEach((device) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "drag-device";
      button.dataset.realSendDevice = device.deviceId;
      button.append(svgIcon(deviceIcon(device), "icon icon-sm"), document.createTextNode(device.name));
      dragList.appendChild(button);
    });
  }

  const count = runtimeState.devices.length;
  const subtitle = PAGE_META.nearby;
  subtitle[1] = `${count} real device${count === 1 ? "" : "s"} discovered on the local network`;
  if (parseHash().page === "nearby") $("#pageSubtitle").textContent = subtitle[1];
  renderTrustedContacts();
}

function bytesToBase64Url(text) {
  const bytes = new TextEncoder().encode(text);
  let binary = "";
  bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function uploadSelectedFiles(fileList) {
  const files = [...fileList];
  if (!files.length) return;
  for (const file of files) {
    toast("Staging file", `${file.name} · ${formatBytes(file.size)}`, "info", 1800);
    const record = await apiRequest("/api/stage", {
      method: "POST",
      headers: { "X-DropSync-File-Name": bytesToBase64Url(file.name) },
      body: file,
    });
    runtimeState.stagedFiles.push(record);
    renderStagedFiles();
  }
  toast("Files ready", `${files.length} file${files.length === 1 ? "" : "s"} encrypted during transfer`, "success");
}

function renderStagedFiles() {
  const list = $("#pickedList");
  if (!list) return;
  list.replaceChildren();
  runtimeState.stagedFiles.forEach((file) => {
    const item = document.createElement("li");
    const badge = document.createElement("span");
    badge.className = "file-badge sm tone-sand";
    badge.appendChild(svgIcon("i-file", "icon icon-xs"));
    const body = document.createElement("div");
    body.className = "row-body";
    const name = document.createElement("p");
    name.textContent = file.name;
    const size = document.createElement("span");
    size.textContent = formatBytes(file.size);
    body.append(name, size);
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "icon-btn";
    remove.dataset.removeStage = file.id;
    remove.setAttribute("aria-label", `Remove ${file.name}`);
    remove.appendChild(svgIcon("i-x", "icon icon-sm"));
    item.append(badge, body, remove);
    list.appendChild(item);
  });
  const total = runtimeState.stagedFiles.reduce((sum, file) => sum + file.size, 0);
  const meta = $("#ov-send [data-step='1'] .foot-meta");
  if (meta) meta.textContent = `${runtimeState.stagedFiles.length} file${runtimeState.stagedFiles.length === 1 ? "" : "s"} · ${formatBytes(total)}`;
}

function prepareRealSend() {
  if (runtimeState.importState?.busy) return toast("Preparing files", "Wait for the selected files to finish loading", "info");
  if (runtimeState.capabilities?.transferSend === false) return toast("Sending unavailable", "Update the Android app to enable file sending", "warning");
  const selected = $("#sendDeviceList .send-device.is-selected");
  if (!selected) return toast("Choose a device", "Pair an online device before sending", "warning");
  if (!runtimeState.stagedFiles.length) return toast("Choose files", "Add at least one file to continue", "warning");
  $("#ov-send .modal-head h3").textContent = "Confirm encrypted transfer";
  $("#confirmDevName").textContent = `Sending to ${selected.dataset.name}`;
  $("#confirmDevIcon").replaceChildren(svgIcon(selected.dataset.icon || "i-laptop").querySelector("use"));
  const total = runtimeState.stagedFiles.reduce((sum, file) => sum + file.size, 0);
  const stats = $$("#ov-send .confirm-stats b");
  if (stats[0]) stats[0].textContent = String(runtimeState.stagedFiles.length);
  if (stats[1]) stats[1].textContent = formatBytes(total);
  if (stats[2]) stats[2].textContent = "Live";
  const list = $("#ov-send .confirm-files");
  list.replaceChildren();
  runtimeState.stagedFiles.forEach((file) => {
    const item = document.createElement("li");
    const badge = document.createElement("span");
    badge.className = "file-badge sm tone-sand";
    badge.appendChild(svgIcon("i-file", "icon icon-xs"));
    const body = document.createElement("div");
    body.className = "row-body";
    const name = document.createElement("p");
    name.textContent = file.name;
    const detail = document.createElement("span");
    detail.textContent = `SHA-256 verified · ${formatBytes(file.size)}`;
    body.append(name, detail);
    item.append(badge, body);
    list.appendChild(item);
  });
  sendStep(2);
}

async function startRealTransfers() {
  const selected = $("#sendDeviceList .send-device.is-selected");
  if (!selected || !runtimeState.stagedFiles.length) return prepareRealSend();
  const fileIds = runtimeState.stagedFiles.map((file) => file.id);
  const result = await apiRequest("/api/transfers/send", {
    method: "POST",
    body: { deviceId: selected.dataset.device, fileIds },
  });
  result.transfers.forEach(updateTransfer);
  runtimeState.stagedFiles = [];
  renderStagedFiles();
  closeModal($("#ov-send"));
  location.hash = "#transfers";
  toast("Encrypted transfer started", `${fileIds.length} file${fileIds.length === 1 ? "" : "s"} → ${selected.dataset.name}`, "accent");
}

async function pauseAllRealTransfers() {
  const active = runtimeState.transfers.filter((item) => item.direction === "send" && ["connecting", "sending"].includes(item.status));
  const results = await Promise.allSettled(active.map((transfer) => apiRequest(`/api/transfers/${transfer.id}/action`, {
    method: "POST",
    body: { action: "pause" },
  })));
  results.filter((result) => result.status === "fulfilled").forEach((result) => updateTransfer(result.value.transfer));
  toast("Outgoing transfers paused", `${active.length} transfer${active.length === 1 ? "" : "s"}`, "warning");
}

async function clearCompletedRealTransfers() {
  try {
    const result = await apiRequest("/api/transfers?status=completed", { method: "DELETE" });
    runtimeState.transfers = runtimeState.transfers.filter((item) => item.status !== "completed");
    renderTransfers();
    toast("Completed history cleared", `${result.removed} record${result.removed === 1 ? "" : "s"} removed`, "info");
  } catch (error) { toast("History could not be cleared", error.message, "error"); }
}

function updateTransfer(transfer) {
  const previous = runtimeState.transfers.find((item) => item.id === transfer.id);
  runtimeState.transfers = [transfer, ...runtimeState.transfers.filter((item) => item.id !== transfer.id)].slice(0, 500);
  renderTransfers();
  if (transfer.status === "completed" && previous?.status !== "completed") renderStaticDataAsLive();
  if (previous && previous.status !== transfer.status) {
    if (transfer.status === "completed") toast("Transfer completed", `${transfer.fileName} · SHA-256 verified`, "success");
    if (transfer.status === "failed") toast("Transfer failed", transfer.error || transfer.fileName, "error");
  }
}

function createTransferRow(transfer) {
  const row = document.createElement("article");
  row.className = `transfer-row lg ${transfer.status === "failed" ? "is-failed" : ""}`;
  row.dataset.real = "1";
  const badge = document.createElement("span");
  badge.className = "file-badge tone-sand";
  badge.appendChild(svgIcon("i-file"));
  const main = document.createElement("div");
  main.className = "transfer-main";
  const top = document.createElement("div");
  top.className = "transfer-top";
  const name = document.createElement("span");
  name.className = "transfer-name";
  name.textContent = transfer.fileName;
  const direction = document.createElement("span");
  direction.className = "transfer-dir";
  direction.textContent = `${transfer.direction === "receive" ? "Receiving from" : "Sending to"} ${transfer.deviceName}`;
  const pct = document.createElement("span");
  pct.className = `transfer-pct ${transfer.status === "failed" ? "error" : ""}`;
  pct.textContent = ["completed", "failed", "cancelled"].includes(transfer.status)
    ? transfer.status[0].toUpperCase() + transfer.status.slice(1)
    : `${transfer.progress || 0}%`;
  top.append(name, direction, pct);
  const progress = document.createElement("div");
  progress.className = "progress lg";
  const fill = document.createElement("div");
  fill.className = "progress-fill";
  fill.style.width = `${Math.max(0, Math.min(100, transfer.progress || 0))}%`;
  progress.appendChild(fill);
  const meta = document.createElement("div");
  meta.className = "transfer-meta";
  meta.append(document.createTextNode(`${formatBytes(transfer.bytesTransferred)} of ${formatBytes(transfer.size)} · ${transfer.status}`));
  const secure = document.createElement("span");
  secure.className = "encrypted";
  secure.append(svgIcon("i-lock", "icon icon-xs"), document.createTextNode("AES-256-GCM"));
  meta.append(document.createTextNode(" · "), secure);
  main.append(top, progress, meta);
  const actions = document.createElement("div");
  actions.className = "transfer-actions";
  if (transfer.direction === "receive" && transfer.status === "completed") actions.appendChild(receivedFileActions(transfer));
  if (transfer.status === "awaiting-approval") {
    const review = document.createElement("button"); review.className = "btn btn-primary btn-sm";
    review.dataset.openModal = "incoming"; review.textContent = "Review"; actions.appendChild(review);
  }
  if (["sending", "paused", "connecting", "awaiting-acceptance"].includes(transfer.status) && transfer.direction === "send") {
    const pause = document.createElement("button");
    pause.type = "button";
    pause.className = "icon-btn";
    pause.dataset.realTransferAction = transfer.status === "paused" ? "resume" : "pause";
    pause.dataset.transferId = transfer.id;
    pause.setAttribute("aria-label", transfer.status === "paused" ? "Resume" : "Pause");
    pause.appendChild(svgIcon(transfer.status === "paused" ? "i-play" : "i-pause", "icon icon-sm"));
    actions.appendChild(pause);
  }
  if (["sending", "receiving", "paused", "connecting", "awaiting-acceptance", "waiting-for-sender", "scanning", "publishing", "retrying"].includes(transfer.status)) {
    const cancel = document.createElement("button");
    cancel.type = "button";
    cancel.className = "icon-btn";
    cancel.dataset.realTransferAction = "cancel";
    cancel.dataset.transferId = transfer.id;
    cancel.setAttribute("aria-label", "Cancel");
    cancel.appendChild(svgIcon("i-x", "icon icon-sm"));
    actions.appendChild(cancel);
  }
  if (transfer.status === "failed" && transfer.stagedFileId) {
    const retry = document.createElement("button");
    retry.type = "button";
    retry.className = "btn btn-secondary btn-sm";
    retry.dataset.retryTransfer = transfer.id;
    retry.textContent = "Retry";
    actions.appendChild(retry);
  }
  row.append(badge, main, actions);
  return row;
}

function ensureTransferContainer(parent, id) {
  if (!parent) return null;
  let container = parent.querySelector(`#${id}`);
  if (!container) {
    container = document.createElement("div");
    container.id = id;
    parent.appendChild(container);
  }
  container.replaceChildren();
  return container;
}

function renderTransfers() {
  const groups = {
    active: runtimeState.transfers.filter((item) => ["connecting", "sending", "receiving", "paused", "awaiting-approval", "waiting-for-sender", "awaiting-acceptance", "scanning", "publishing", "retrying"].includes(item.status)),
    queued: [],
    completed: runtimeState.transfers.filter((item) => item.status === "completed"),
    failed: runtimeState.transfers.filter((item) => ["failed", "rejected"].includes(item.status)),
    cancelled: runtimeState.transfers.filter((item) => item.status === "cancelled"),
  };
  const dashboardCard = $(".page[data-page='dashboard'] .dash-main .card");
  const dash = ensureTransferContainer(dashboardCard, "realDashTransfers");
  groups.active.slice(0, 4).forEach((transfer) => dash?.appendChild(createTransferRow(transfer)));
  if (dash && !groups.active.length) {
    const empty = document.createElement("p");
    empty.className = "runtime-empty";
    empty.textContent = "No active transfers.";
    dash.appendChild(empty);
  }
  Object.entries(groups).forEach(([status, items]) => {
    const panel = $(`.page[data-page='transfers'] .tab-panel[data-panel='${status}']`);
    let card = panel?.querySelector(".list-card");
    if (panel && !card) {
      panel.replaceChildren();
      card = document.createElement("div");
      card.className = "card list-card";
      panel.appendChild(card);
    }
    const container = ensureTransferContainer(card, `real-${status}-transfers`);
    items.slice(0, 100).forEach((transfer) => container?.appendChild(createTransferRow(transfer)));
    if (container && !items.length) {
      const empty = document.createElement("p");
      empty.className = "runtime-empty";
      empty.textContent = `No ${status} transfers.`;
      container.appendChild(empty);
    }
  });
  $$(".page[data-page='transfers'] .tab").forEach((tab) => {
    const key = tab.dataset.tab;
    const count = key === "queued" ? 0 : groups[key]?.length || 0;
    const badge = tab.querySelector("em");
    if (badge) badge.textContent = String(count);
  });
  const activeCount = groups.active.length;
  const dashBadge = $(".dash-main .card-head-actions .badge");
  if (dashBadge) dashBadge.textContent = `${activeCount} active`;
  $$(".nav-count.accent").forEach((node) => { node.textContent = String(activeCount); });
  renderHistory();
  const mobileCount = $(".mobile-nav-icon em");
  if (mobileCount) { mobileCount.textContent = String(activeCount); mobileCount.hidden = !activeCount; }
  renderDashboardActivity();
  updateStatusBar();
}

function createEmpty(message) {
  const empty = document.createElement("p");
  empty.className = "runtime-empty";
  empty.textContent = message;
  return empty;
}

function receivedFileActions(transfer) {
  const actions = document.createElement("div"); actions.className = "received-actions";
  if (transfer.direction !== "receive" || transfer.status !== "completed") return actions;
  const open = document.createElement(runtimeState.desktop || isNativeAndroid ? "button" : "a");
  open.className = "btn btn-secondary btn-xs";
  open.textContent = runtimeState.desktop || isNativeAndroid ? "Open file" : "Download copy";
  if (runtimeState.desktop || isNativeAndroid) { open.dataset.fileAction = "open"; open.dataset.transferId = transfer.id; }
  else { open.href = `/api/received/${encodeURIComponent(transfer.id)}/download`; open.setAttribute("download", ""); }
  const show = document.createElement("button"); show.type = "button"; show.className = "btn btn-ghost btn-xs";
  show.textContent = "Show in folder"; show.dataset.fileAction = "show"; show.dataset.transferId = transfer.id;
  actions.append(open, show); return actions;
}

function savedLocation(transfer) {
  return transfer.savedPath || `${runtimeState.settings?.downloadDirectory || "Downloads"}${runtimeState.settings?.downloadDirectory?.includes("\\") ? "\\" : "/"}${transfer.fileName}`;
}

const seenIncomingRequests = new Set();
function renderIncoming(requests = runtimeState.incomingRequests || [], autoOpen = false) {
  runtimeState.incomingRequests = requests;
  let banner = $("#incomingBanner");
  if (!banner) {
    banner = document.createElement("div"); banner.id = "incomingBanner"; banner.className = "incoming-banner";
    const text = document.createElement("span");
    const review = document.createElement("button"); review.className = "btn btn-primary btn-sm";
    review.dataset.openModal = "incoming"; review.textContent = "Review incoming files";
    banner.append(text, review); $(".content").prepend(banner);
  }
  banner.hidden = !requests.length;
  banner.querySelector("span").textContent = `${requests.length} incoming file${requests.length === 1 ? "" : "s"} waiting for approval`;
  const list = $("#incomingRequestList"); list.replaceChildren();
  const dialog = $("#ov-incoming");
  if (!requests.length) { if (!dialog.hidden) closeModal(dialog); return; }
  const selected = requests.find((item) => item.id === dialog.dataset.requestId) || requests[0];
  dialog.dataset.requestId = selected.id;
  $("#incomingFrom").textContent = `${selected.deviceName} wants to send a file`;
  $("#ov-incoming .device-ic use").setAttribute("href", `#${deviceIcon(selected)}`);
  $("#incomingSaveTo").textContent = runtimeState.settings.downloadDirectory;
  if (isNativeAndroid) {
    let choose = $("#incomingChooseFolder");
    if (!choose) { choose = document.createElement("button"); choose.id = "incomingChooseFolder"; choose.className = "btn btn-secondary btn-xs"; choose.dataset.featureAction = "choose-folder"; $("#incomingSaveTo").after(choose); }
    choose.textContent = runtimeState.settings.receiveFolderSelected ? "Change folder" : "Choose receiving folder";
    $("#acceptTransfer").disabled = !runtimeState.settings.receiveFolderSelected;
  }
  $("#incomingExpires").textContent = new Date(selected.expiresAt).toLocaleTimeString();
  for (const item of requests) {
    const row = document.createElement("li");
    const choose = document.createElement("button"); choose.className = `incoming-choice ${item.id === selected.id ? "is-selected" : ""}`;
    choose.textContent = `${item.fileName} · ${formatBytes(item.size)} · ${item.deviceName}`;
    choose.addEventListener("click", () => { dialog.dataset.requestId = item.id; renderIncoming(); });
    row.appendChild(choose); list.appendChild(row);
  }
  const fresh = requests.some((item) => !seenIncomingRequests.has(item.id));
  requests.forEach((item) => seenIncomingRequests.add(item.id));
  if (autoOpen && fresh) openModal("incoming");
}

async function decideIncoming(accept) {
  const id = $("#ov-incoming").dataset.requestId;
  if (!id) return;
  $("#acceptTransfer").disabled = true; $("#declineTransfer").disabled = true;
  try {
    const result = await apiRequest(`/api/incoming/${encodeURIComponent(id)}`, { method: "POST", body: { accept } });
    runtimeState.transfers = result.transfers; renderTransfers(); renderIncoming(result.requests);
  } finally { $("#acceptTransfer").disabled = false; $("#declineTransfer").disabled = false; }
}

function renderHistory() {
  const tbody = $(".history-table tbody");
  if (!tbody) return;
  tbody.replaceChildren();
  runtimeState.transfers.forEach((transfer) => {
    const row = document.createElement("tr");
    const values = [
      transfer.fileName,
      transfer.deviceName,
      transfer.direction === "receive" ? "Received" : "Sent",
      formatBytes(transfer.size),
      transfer.speed ? `${formatBytes(transfer.speed)}/s` : "—",
      transfer.status,
      new Date(transfer.updatedAt || transfer.createdAt).toLocaleString(),
      "",
    ];
    values.forEach((value, index) => {
      const cell = document.createElement("td");
      cell.textContent = String(value || "—");
      if ([3, 5].includes(index)) cell.className = "num";
      if (index === 5) {
        cell.textContent = "";
        const badge = document.createElement("span");
        badge.className = transfer.status === "completed" ? "badge badge-success" : transfer.status === "failed" ? "badge badge-error" : "badge badge-neutral";
        badge.textContent = transfer.status;
        cell.appendChild(badge);
      }
      if (index === 7 && transfer.direction === "receive" && transfer.status === "completed") {
        cell.textContent = ""; cell.appendChild(receivedFileActions(transfer)); cell.title = savedLocation(transfer);
      }
      row.appendChild(cell);
    });
    tbody.appendChild(row);
  });
  if (!runtimeState.transfers.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 8;
    cell.appendChild(createEmpty("No real transfers have been recorded yet."));
    row.appendChild(cell);
    tbody.appendChild(row);
  }
  const footer = $(".page[data-page='history'] .table-foot");
  if (footer) footer.textContent = `${runtimeState.transfers.length} real transfer record${runtimeState.transfers.length === 1 ? "" : "s"}`;
}

function renderDashboardActivity() {
  const list = $(".page[data-page='dashboard'] .activity-list");
  if (!list) return;
  list.replaceChildren();
  runtimeState.transfers.slice(0, 5).forEach((transfer) => {
    const item = document.createElement("li");
    const icon = document.createElement("span");
    icon.className = `activity-ic ${transfer.status === "failed" ? "error" : transfer.direction === "receive" ? "recv" : "sent"}`;
    icon.appendChild(svgIcon(transfer.direction === "receive" ? "i-arrow-down-left" : "i-arrow-up-right", "icon icon-sm"));
    const body = document.createElement("div");
    body.className = "activity-body";
    const text = document.createElement("p");
    text.textContent = `${transfer.direction === "receive" ? "Received" : "Sent"} ${transfer.fileName} ${transfer.direction === "receive" ? "from" : "to"} ${transfer.deviceName}`;
    const when = document.createElement("span");
    when.className = "activity-when";
    when.textContent = new Date(transfer.updatedAt || transfer.createdAt).toLocaleString();
    body.append(text, when);
    if (transfer.direction === "receive" && transfer.status === "completed") body.appendChild(receivedFileActions(transfer));
    const badge = document.createElement("span");
    badge.className = transfer.status === "completed" ? "badge badge-success" : transfer.status === "failed" ? "badge badge-error" : "badge badge-neutral";
    badge.textContent = transfer.status;
    item.append(icon, body, badge);
    list.appendChild(item);
  });
  if (!runtimeState.transfers.length) list.appendChild(createEmpty("Transfer activity will appear here."));
  const badge = $(".page[data-page='dashboard'] .dash-main .card-head .badge");
  if (badge) badge.textContent = `${runtimeState.transfers.filter((item) => ["connecting", "sending", "receiving", "paused"].includes(item.status)).length} active`;
}

function updateStatusBar() {
  const items = $$(".statusbar .statusbar-item");
  const active = runtimeState.transfers.filter((item) => ["connecting", "sending", "receiving", "paused"].includes(item.status)).length;
  if (items[0]) {
    const dot = document.createElement("span");
    dot.className = "dot success";
    items[0].replaceChildren(dot, document.createTextNode("Connected · Local network"));
    items[0].title = `${runtimeState.self?.addresses?.[0] || "127.0.0.1"}:${runtimeState.self?.port || ""}`;
  }
  if (items[1]) {
    items[1].replaceChildren(svgIcon("i-shield-check", "icon icon-xs"), document.createTextNode("Encrypted transfers active"));
    items[1].title = "Authenticated end-to-end encrypted transfers";
  }
  if (items[2]) items[2].textContent = `${active} transfer${active === 1 ? "" : "s"} in progress`;
  if (items[3]) items[3].textContent = `v${runtimeState.version || "0.6.0"} · local-first`;
}

function renderTrustedContacts() {
  const tbody = $(".contacts-table tbody");
  if (tbody) {
    tbody.replaceChildren();
    runtimeState.trustedDevices.forEach((device) => {
      const live = runtimeState.devices.find((item) => item.deviceId === device.deviceId);
      const row = document.createElement("tr");
      const values = [device.name, "DropSync peer", live ? relativeSeen(live.lastSeen) : "Offline", "Trusted", live ? "Online" : "Offline"];
      values.forEach((value) => {
        const cell = document.createElement("td");
        cell.textContent = value;
        row.appendChild(cell);
      });
      const actions = document.createElement("td");
      actions.className = "num";
      if (live) {
        const send = document.createElement("button");
        send.type = "button";
        send.className = "btn btn-primary btn-xs";
        send.dataset.realSendDevice = device.deviceId;
        send.textContent = "Send";
        actions.appendChild(send);
      }
      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "btn btn-danger-ghost btn-xs";
      remove.dataset.removeTrusted = device.deviceId;
      remove.textContent = "Remove trust";
      actions.appendChild(remove);
      row.appendChild(actions);
      tbody.appendChild(row);
    });
    if (!runtimeState.trustedDevices.length) {
      const row = document.createElement("tr");
      const cell = document.createElement("td");
      cell.colSpan = 6;
      cell.appendChild(createEmpty("No paired devices yet."));
      row.appendChild(cell);
      tbody.appendChild(row);
    }
  }

  const favorites = $(".page[data-page='favorites'] .fav-device-row");
  if (favorites) {
    favorites.replaceChildren();
    runtimeState.trustedDevices.forEach((device) => {
      const live = runtimeState.devices.find((item) => item.deviceId === device.deviceId);
      const button = document.createElement("button");
      button.type = "button";
      button.className = "fav-device";
      if (live) button.dataset.realSendDevice = device.deviceId;
      const icon = document.createElement("span");
      icon.className = "device-ic lg";
      icon.appendChild(svgIcon(deviceIcon(live || device)));
      const body = document.createElement("span");
      body.className = "fav-device-body";
      const name = document.createElement("strong");
      name.textContent = device.name;
      const state = document.createElement("span");
      state.textContent = live ? "Online · trusted" : "Offline · trusted";
      body.append(name, state);
      button.append(icon, body);
      favorites.appendChild(button);
    });
    if (!runtimeState.trustedDevices.length) favorites.appendChild(createEmpty("Pair a device to add it here."));
  }
  const favoriteLists = $(".page[data-page='favorites'] .fav-cols");
  if (favoriteLists) favoriteLists.replaceChildren(createEmpty("File favorites will appear after real transfers."));
}

function renderSearchData() {
  const root = $("#searchResults");
  if (!root) return;
  root.replaceChildren();
  const addGroup = (title, entries) => {
    if (!entries.length) return;
    const group = document.createElement("div");
    group.className = "sr-group";
    group.dataset.group = title;
    const heading = document.createElement("h6");
    heading.textContent = title;
    group.appendChild(heading);
    entries.forEach(({ title: entryTitle, subtitle, icon, attributes }) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "sr-item";
      Object.entries(attributes || {}).forEach(([key, value]) => { button.dataset[key] = value; });
      const badge = document.createElement("span");
      badge.className = "file-badge sm tone-slate";
      badge.appendChild(svgIcon(icon, "icon icon-xs"));
      const body = document.createElement("div");
      body.className = "row-body";
      const name = document.createElement("p"); name.textContent = entryTitle;
      const detail = document.createElement("span"); detail.textContent = subtitle;
      body.append(name, detail);
      button.append(badge, body);
      group.appendChild(button);
    });
    root.appendChild(group);
  };
  addGroup("Devices", runtimeState.devices.map((device) => ({
    title: device.name,
    subtitle: `${device.trusted ? "Trusted" : "Pair required"} · ${device.address}:${device.port}`,
    icon: deviceIcon(device),
    attributes: { [device.trusted ? "realSendDevice" : "realPair"]: device.deviceId },
  })));
  addGroup("Transfers", runtimeState.transfers.slice(0, 20).map((transfer) => ({
    title: transfer.fileName,
    subtitle: `${transfer.status} · ${transfer.deviceName} · ${formatBytes(transfer.size)}`,
    icon: "i-swap",
    attributes: { navTo: "transfers" },
  })));
  addGroup("Settings", [{
    title: "DropSync settings",
    subtitle: "Identity, storage, discovery, and interface",
    icon: "i-gear",
    attributes: { openModal: "settings" },
  }]);
}

function renderStaticDataAsLive() {
  window.updateDropSyncProfile?.(); window.renderDropSyncNotifications?.();
  PAGE_META.dashboard[1] = runtimeState.unavailable ? "Transfer service not connected" : `${runtimeState.self.name} · local service connected`;
  PAGE_META.nearby[1] = runtimeState.devices.length
    ? `${runtimeState.devices.length} nearby DropSync device${runtimeState.devices.length === 1 ? "" : "s"}`
    : "No nearby DropSync devices found yet";
  PAGE_META.transfers[1] = `${runtimeState.transfers.length} local transfer record${runtimeState.transfers.length === 1 ? "" : "s"}`;
  PAGE_META.history[1] = `${runtimeState.transfers.length} verified transfer record${runtimeState.transfers.length === 1 ? "" : "s"}`;
  PAGE_META.shared[1] = "Files are saved directly after authenticated transfer";
  PAGE_META.favorites[1] = `${runtimeState.trustedDevices.length} paired device${runtimeState.trustedDevices.length === 1 ? "" : "s"}`;
  PAGE_META.contacts[1] = `${runtimeState.trustedDevices.length} trusted device${runtimeState.trustedDevices.length === 1 ? "" : "s"}`;
  PAGE_META.storage[1] = runtimeState.system?.storage ? `${formatBytes(runtimeState.system.storage.free)} free` : runtimeState.settings.downloadDirectory;
  PAGE_META.network[1] = `${runtimeState.devices.length} peer${runtimeState.devices.length === 1 ? "" : "s"} discovered · port ${runtimeState.self.port}`;
  const nearbyCount = $(".nav-item[data-nav='nearby'] .nav-count");
  if (nearbyCount) nearbyCount.textContent = String(runtimeState.devices.length);
  const sharedCount = $(".nav-item[data-nav='shared'] .nav-count");
  if (sharedCount) sharedCount.textContent = "0";
  $(".brand-ver").textContent = runtimeState.version || "0.6.0";
  $("#netChip").lastChild.textContent = "Local LAN";
  if (!window.renderDropSyncNotifications) { $("#bellBadge").style.display = "none"; $("#notifList").replaceChildren(createEmpty("No runtime notifications.")); }
  $$(".qa-tile").forEach((button) => {
    const supported = ["Send Files", "Send Text", "Share Clipboard", "Pair Device"].includes(button.textContent.trim()) || (button.textContent.trim() === "Receive Files" && runtimeState.capabilities?.transferReceive !== false);
    button.disabled = !supported;
    if (!supported) button.title = "Not enabled in the local file-transfer build";
  });

  const storage = runtimeState.system?.storage;
  const dashStorage = $(".page[data-page='dashboard'] .storage-mini");
  if (dashStorage) {
    dashStorage.replaceChildren(createEmpty(storage ? `${formatBytes(storage.used)} used · ${formatBytes(storage.free)} free` : "Storage information unavailable"));
  }
  if (dashStorage && storage) {
    const number = dashStorage.querySelector(".donut-num");
    const caption = dashStorage.querySelector(".donut-cap");
    if (number) number.textContent = formatBytes(storage.used).replace(/\s.*$/, "");
    if (caption) caption.textContent = "used";
    const note = dashStorage.parentElement.querySelector(".mini-note");
    if (note) note.textContent = `${formatBytes(storage.total)} drive · ${formatBytes(storage.free)} free`;
    const legend = dashStorage.querySelector(".legend");
    if (legend) {
      const location = document.createElement("li");
      location.className = "download-location";
      location.title = runtimeState.settings.downloadDirectory;
      const marker = document.createElement("i");
      marker.style.setProperty("--c", "var(--accent)");
      const label = document.createElement("span");
      label.textContent = "Downloads";
      const value = document.createElement("b");
      value.textContent = "Local";
      location.append(marker, label, value);
      legend.replaceChildren(location);
    }
  }
  const dashNetwork = $(".page[data-page='dashboard'] .net-mini");
  if (dashNetwork) {
    const name = dashNetwork.querySelector(".net-name");
    const meta = dashNetwork.querySelector(".net-meta");
    if (name) name.textContent = "Local network service";
    if (meta) meta.textContent = `${runtimeState.devices.length} discovered peer${runtimeState.devices.length === 1 ? "" : "s"} · signed announcements`;
    const specs = $$("dd", dashNetwork.closest(".card"));
    if (specs[0]) specs[0].textContent = runtimeState.self.addresses[0] || "127.0.0.1";
    if (specs[1]) specs[1].textContent = "Measured per transfer";
    if (specs[2]) specs[2].textContent = "Live";
    if (specs[3]) specs[3].textContent = runtimeState.settings.discoveryEnabled ? "Active" : "Disabled";
  }

  const sharedGrid = $(".page[data-page='shared'] .shared-grid");
  if (sharedGrid) {
    window.resetDropSyncPreviews?.();
    let folderBar = $("#receivedFolderBar");
    if (!folderBar) { folderBar = document.createElement("div"); folderBar.id = "receivedFolderBar"; folderBar.className = "received-folder-bar"; sharedGrid.before(folderBar); }
    folderBar.replaceChildren();
    const location = document.createElement("p"); location.className = "saved-location";
    location.textContent = `Received files are saved in ${runtimeState.settings.downloadDirectory}`;
    folderBar.appendChild(location);
    if (!isNativeAndroid) {
      const open = document.createElement("button"); open.className = "btn btn-secondary btn-sm";
      open.dataset.fileAction = "downloads"; open.textContent = "Open downloads folder"; folderBar.appendChild(open);
    }
    const received = runtimeState.transfers.filter((t) => t.direction === "receive" && t.status === "completed");
    const categories = $(".page[data-page='shared'] .chips-row");
    if (categories) {
      const all = document.createElement("button"); all.className = "chip is-active";
      all.textContent = `Received files (${received.length})`; categories.replaceChildren(all);
    }
    sharedGrid.replaceChildren();
    received.forEach((t) => {
      const card = document.createElement("article"); card.className = "shared-card card received-card";
      const name = document.createElement("h3"); name.textContent = t.fileName;
      const meta = document.createElement("p"); meta.className = "muted"; meta.textContent = `${formatBytes(t.size)} · ${t.deviceName}`;
      const status = document.createElement("p"); status.className = "saved-location"; status.textContent = savedLocation(t); status.title = status.textContent;
      card.dataset.receivedName = t.fileName.toLocaleLowerCase();
      const query = $("[aria-label='Filter shared items']")?.value.trim().toLocaleLowerCase() || "";
      card.hidden = Boolean(query && !card.dataset.receivedName.includes(query));
      const preview = document.createElement("div"); preview.className = "received-preview"; preview.appendChild(svgIcon("i-file"));
      if (/\.(png|jpe?g|webp)$/i.test(t.fileName)) { const image = document.createElement("img"); image.alt = ""; image.decoding = "async"; preview.appendChild(image); window.loadDropSyncPreview?.(image, t); }
      card.append(preview, name, meta, status, receivedFileActions(t)); sharedGrid.appendChild(card);
    });
    if (!received.length) sharedGrid.appendChild(createEmpty("No files received yet."));
    if (sharedCount) sharedCount.textContent = String(received.length);
  }

  const storagePage = $(".page[data-page='storage']");
  if (storagePage) {
    storagePage.replaceChildren();
    storagePage.classList.add("volumes-page");
    const transferStorage = document.createElement("article");
    transferStorage.className = "card runtime-system-card";
    const transferTitle = document.createElement("h3"); transferTitle.textContent = "Transfer storage";
    const downloadPath = document.createElement("p"); downloadPath.className = "storage-path muted"; downloadPath.textContent = runtimeState.settings.downloadDirectory;
    const receivedBytes = runtimeState.transfers.filter((t) => t.direction === "receive" && t.status === "completed").reduce((sum, t) => sum + (Number(t.size) || 0), 0);
    const transferNote = document.createElement("p"); transferNote.textContent = `${formatBytes(receivedBytes)} received in saved history`;
    transferStorage.append(transferTitle, downloadPath, transferNote);
    if (!isNativeAndroid) {
      const folder = document.createElement("button"); folder.className = "btn btn-secondary btn-sm";
      folder.dataset.fileAction = "downloads"; folder.textContent = "Open downloads folder"; transferStorage.appendChild(folder);
    }
    const cache = document.createElement("article"); cache.className = "card runtime-system-card";
    const cacheTitle = document.createElement("h3"); cacheTitle.textContent = "Files waiting to send";
    const cacheNote = document.createElement("p"); cacheNote.className = "muted"; cacheNote.textContent = "Temporary copies of files you selected. These are not browser searches or received files.";
    const cacheList = document.createElement("div");
    runtimeState.stagedFiles.forEach((file) => { const item = document.createElement("p"); item.className = "storage-path"; item.textContent = `${file.name} · ${formatBytes(file.size)}`; cacheList.appendChild(item); });
    if (!runtimeState.stagedFiles.length) cacheList.appendChild(createEmpty("No staged files."));
    cache.append(cacheTitle, cacheNote, cacheList);
    storagePage.append(transferStorage, cache);
    const volumes = runtimeState.system?.volumes?.length ? runtimeState.system.volumes : storage ? [storage] : [];
    if (!volumes.length) storagePage.appendChild(createEmpty("No storage information available on this device."));
    for (const volume of volumes) {
    const card = document.createElement("div");
    card.className = "card runtime-system-card volume-card";
    const title = document.createElement("h3");
    title.className = "section-title";
    title.textContent = volume.directory;
    const pathText = document.createElement("p");
    pathText.className = "mono muted storage-path";
    pathText.textContent = volume.downloads ? "Receives your DropSync files" : "Local storage volume";
    const usedPercent = volume.total ? Math.min(100, Math.max(0, volume.used / volume.total * 100)) : 0;
    const bar = document.createElement("div"); bar.className = `volume-meter ${usedPercent >= 90 ? "is-low" : usedPercent >= 80 ? "is-warning" : "is-healthy"}`; bar.setAttribute("role", "meter"); bar.setAttribute("aria-label", `${volume.directory} space used`); bar.setAttribute("aria-valuemin", "0"); bar.setAttribute("aria-valuemax", "100"); bar.setAttribute("aria-valuenow", String(Math.round(usedPercent)));
    const fill = document.createElement("span"); fill.style.width = `${usedPercent}%`; bar.appendChild(fill);
    const capacity = document.createElement("p"); capacity.className = "volume-capacity"; capacity.textContent = `${formatBytes(volume.free)} free of ${formatBytes(volume.total)}`;
    const metrics = document.createElement("dl");
    metrics.className = "spec-list";
    [["Used", formatBytes(volume.used)], ["Free", formatBytes(volume.free)], ["Total", formatBytes(volume.total)]].forEach(([label, value]) => {
      const row = document.createElement("div");
      const dt = document.createElement("dt"); dt.textContent = label;
      const dd = document.createElement("dd"); dd.textContent = value;
      row.append(dt, dd); metrics.appendChild(row);
    });
    card.append(title, pathText, bar, capacity, metrics);
    storagePage.appendChild(card);
    }
  }

  const networkPage = $(".page[data-page='network']");
  if (networkPage) {
    networkPage.replaceChildren();
    const grid = document.createElement("div");
    grid.className = "network-grid";
    const connection = document.createElement("div");
    connection.className = "card";
    const heading = document.createElement("h3");
    heading.className = "section-title";
    heading.textContent = "Live Local Network";
    const specs = document.createElement("dl");
    specs.className = "spec-list";
    const discoveryInterfaces = runtimeState.discovery?.interfaces || [];
    const rows = [
      ["Listen port", String(runtimeState.self.port)],
      ["Local addresses", runtimeState.self.addresses.join(", ") || "127.0.0.1"],
      ["Discovery", runtimeState.settings.discoveryEnabled ? "Signed multicast + LAN broadcast" : "Disabled"],
      ["Discovery interfaces", discoveryInterfaces.length ? discoveryInterfaces.map((item) => typeof item === "string" ? item : `${item.name} (${item.address})`).join(", ") : "No active IPv4 interface"],
      ["Discovery port", String(runtimeState.discovery?.port || 45555)],
      ["Discovered peers", String(runtimeState.devices.length)],
      ["Announcements received", String(runtimeState.discovery?.receivedCount || 0)],
      ["Last discovery error", runtimeState.discovery?.lastError || "None"],
      ["Protocol", "DropSync transfer/2"],
      ["Encryption", "X25519 + HKDF-SHA-256 + AES-256-GCM"],
      ["Tailscale addresses", runtimeState.self.addresses.filter((address) => /^100\./.test(address)).join(", ") || "No Tailscale IPv4 interface detected"],
      ["Remote peers", "Pair Device → enter a Tailscale IP or full *.ts.net name. Both devices need Tailscale access."],
    ];
    rows.forEach(([label, value]) => {
      const row = document.createElement("div");
      const dt = document.createElement("dt"); dt.textContent = label;
      const dd = document.createElement("dd"); dd.textContent = value;
      row.append(dt, dd); specs.appendChild(row);
    });
    connection.append(heading, specs);
    grid.appendChild(connection);
    networkPage.appendChild(grid);
  }
  renderTrustedContacts();
  renderSearchData();
  const current = parseHash().page || "dashboard";
  if (PAGE_META[current]) $("#pageSubtitle").textContent = PAGE_META[current][1];
}

async function pairSelectedDevice() {
  const deviceId = runtimeState.pendingPairDeviceId;
  const code = $("#pairCodeInput").value.replace(/\D/g, "");
  if (!deviceId) throw new Error("Choose a nearby device first");
  if (code.length !== 6) throw new Error("Enter the six-digit code shown on the other device");
  const result = await apiRequest("/api/pair", { method: "POST", body: { deviceId, code } });
  const device = runtimeState.devices.find((item) => item.deviceId === deviceId);
  if (device) device.trusted = true;
  runtimeState.trustedDevices = [result.trusted, ...runtimeState.trustedDevices.filter((item) => item.deviceId !== result.trusted.deviceId)];
  runtimeState.pendingPairDeviceId = null;
  $("#pairCodeInput").value = "";
  closeModal($("#ov-pairing"));
  renderDevices();
  toast("Device paired securely", `${result.trusted.name} · ${result.trusted.fingerprint}`, "success");
}

async function findManualDevice() {
  const input = $("#manualPeerAddress");
  const button = $("#manualPeerConnect");
  const address = input.value.trim();
  if (!address) throw new Error("Enter the other device's local IPv4 address");
  button.disabled = true;
  button.classList.add("is-loading");
  try {
    const result = await apiRequest("/api/devices/manual", { method: "POST", body: { address } });
    const device = result.device;
    runtimeState.devices = [device, ...runtimeState.devices.filter((item) => item.deviceId !== device.deviceId)];
    runtimeState.pendingPairDeviceId = device.deviceId;
    $("#pairTargetName").textContent = device.name;
    $("#pairTargetFingerprint").textContent = device.fingerprint || "—";
    $("#pairTarget").hidden = false;
    $("#pairConfirm").hidden = false;
    $("#pairHostSession").hidden = false;
    $("#manualConnect").hidden = true;
    $("#pairLede").textContent = "Enter the other device's code below, or use your code on that device.";
    renderDevices();
    $("#pairCodeInput").focus();
    toast("Device found", `${device.name} · ${device.address}:${device.port}`, "success");
  } finally {
    button.disabled = false;
    button.classList.remove("is-loading");
  }
}

function settingKey(label) {
  return String(label).toLowerCase().normalize("NFKD").replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 80);
}

const REAL_SETTINGS = {
  "device-name": "deviceName", "phone-name": "deviceName", "automatically-discover-devices": "discoveryEnabled",
  "ask-before-receiving-files": "requireIncomingApproval", "allow-executable-files": "allowExecutableFiles",
  "allow-incoming-files": "receivingEnabled", "enable-clipboard-sharing": "clipboardEnabled",
  "keep-running-in-background": "keepRunningInBackground", "show-transfer-notifications": "notificationsEnabled",
  "keep-computer-available": "keepAwakeWhileSharing",
  "automatic-retry-attempts": "retryAttempts", "upload-limit-kib-s": "uploadLimitKBps", "download-limit-kib-s": "downloadLimitKBps",
  "maximum-file-size-mib": "maxIncomingFileBytes", "simultaneous-incoming-files": "maxConcurrentIncoming",
  "enable-virustotal-checks": "virusTotalEnabled", "block-files-without-a-report": "virusTotalBlockUnknown", "upload-unknown-files-for-analysis": "virusTotalUploadUnknown",
};

function hydrateSettingsControls() {
  if (!runtimeState.settings) return;
  $$("#settingsPane .set-row").forEach((row) => {
    const label = row.querySelector(".set-row-text p")?.textContent || "";
    const key = settingKey(label);
    row.dataset.settingKey = key;
    let value = runtimeState.settings.ui?.[key];
    if (REAL_SETTINGS[key]) value = runtimeState.settings[REAL_SETTINGS[key]];
    if (key === "maximum-file-size-mib") value = (runtimeState.settings.maxIncomingFileBytes || 10 * 1024 ** 3) / 1024 ** 2;
    if (key === "key-storage") row.querySelector(".setting-status").textContent = runtimeState.vault?.provider || runtimeState.settings.keyStorage || "Set a vault passphrase to protect local records";
    if (key === "device-name") value = runtimeState.settings.deviceName;
    if (key === "automatically-discover-devices") value = runtimeState.settings.discoveryEnabled;
    if (key === "ask-before-receiving-files") value = runtimeState.settings.requireIncomingApproval !== false;
    if (key === "allow-executable-files") value = runtimeState.settings.allowExecutableFiles === true;
    if (label.toLowerCase().includes("default download") && !Object.hasOwn(runtimeState.settings.ui || {}, key)) value = runtimeState.settings.downloadDirectory;
    if (value === undefined) return;
    const toggle = row.querySelector(".toggle");
    const input = row.querySelector("input:not([type='range'])");
    const select = row.querySelector("select");
    const step = row.querySelector(".stepper span");
    if (toggle) {
      toggle.classList.toggle("is-on", Boolean(value));
      toggle.setAttribute("aria-checked", String(Boolean(value)));
    } else if (input) {
      input.readOnly = false;
      input.value = String(value);
    } else if (select) select.value = String(value);
    else if (step) step.textContent = String(value).replace(/\s*px$/, "") + (label === "Font size" ? " px" : "");
    if ((runtimeState.managedSettings || []).includes(REAL_SETTINGS[key])) { row.classList.add("is-managed"); row.querySelectorAll("button,input,select").forEach((control) => { control.disabled = true; control.title = "Managed by your organization"; }); }
  });
  const accent = runtimeState.settings.ui?.["accent-color"];
  if (accent) {
    const swatch = $(`#settingsPane [data-swatch="${CSS.escape(accent)}"]`);
    $$("#settingsPane .swatch").forEach((item) => item.classList.toggle("is-on", item === swatch));
    document.documentElement.style.setProperty("--accent", accent);
    document.documentElement.style.setProperty("--accent-hover", `${accent}e6`);
    document.documentElement.style.setProperty("--accent-press", `${accent}cc`);
  }
}

function persistSetting(row, value) {
  if (runtimeState.unavailable) return;
  const key = row.dataset.settingKey;
  if (!key) return;
  const pending = runtimeState.pendingSettingsPatch;
  pending.ui[key] = value;
  if (REAL_SETTINGS[key]) {
    if (row.querySelector("input[type='number']")) {
      value = Number(value);
      if (!Number.isInteger(value)) { toast("Use a whole number", "This setting was not saved", "error"); hydrateSettingsControls(); return; }
    }
    pending[REAL_SETTINGS[key]] = key === "maximum-file-size-mib" ? value * 1024 ** 2 : value;
  }
  if (key === "device-name") pending.deviceName = String(value);
  if (key === "automatically-discover-devices") pending.discoveryEnabled = Boolean(value);
  if (key === "ask-before-receiving-files") pending.requireIncomingApproval = Boolean(value);
  if (key === "allow-executable-files") pending.allowExecutableFiles = Boolean(value);
  if (key.includes("default-download") && typeof value === "string") pending.downloadDirectory = value;
  runtimeState.settings.ui = { ...runtimeState.settings.ui, [key]: value };
  clearTimeout(runtimeState.saveTimer);
  runtimeState.saveTimer = setTimeout(async () => {
    const patch = runtimeState.pendingSettingsPatch;
    runtimeState.pendingSettingsPatch = { ui: {} };
    try {
      const result = await apiRequest("/api/settings", { method: "PUT", body: patch });
      runtimeState.settings = result.settings;
      toast("Settings saved", "Stored locally on this device", "success", 1600);
    } catch (error) {
      try { const current = await apiRequest("/api/bootstrap"); runtimeState.settings = current.settings; } catch { }
      hydrateSettingsControls();
      toast("Settings were not saved", error.message, "error");
    }
  }, 350);
}

function connectEvents() {
  runtimeState.eventSource?.close();
  const source = new EventSource("/api/events");
  runtimeState.eventSource = source;
  source.addEventListener("auth-callback", (event) => window.dispatchEvent(new CustomEvent("dropsync-auth", { detail: JSON.parse(event.data) })));
  source.addEventListener("devices", (event) => {
    runtimeState.devices = JSON.parse(event.data);
    renderDevices();
  });
  source.addEventListener("transfer", (event) => updateTransfer(JSON.parse(event.data)));
  source.addEventListener("incoming", async (event) => {
    renderIncoming(JSON.parse(event.data), true);
    const result = await apiRequest("/api/transfers"); runtimeState.transfers = result.transfers; renderTransfers();
  });
  source.addEventListener("settings", (event) => { runtimeState.settings = JSON.parse(event.data); });
  source.addEventListener("notification", (event) => { runtimeState.notifications = [JSON.parse(event.data), ...(runtimeState.notifications || [])].slice(0, 100); window.renderDropSyncNotifications?.(); });
  source.addEventListener("history-cleared", (event) => {
    const { status } = JSON.parse(event.data);
    runtimeState.transfers = runtimeState.transfers.filter((item) => item.status !== status);
    renderTransfers();
  });
  source.addEventListener("paired", (event) => {
    const peer = JSON.parse(event.data);
    toast("Device paired securely", peer.name, "success");
    if (!$("#ov-pairing").hidden) closeModal($("#ov-pairing"));
    runtimeState.pendingPairDeviceId = null;
    apiRequest("/api/bootstrap").then((result) => {
      runtimeState.devices = result.devices;
      runtimeState.trustedDevices = result.trustedDevices;
      renderDevices();
    });
  });
  source.onerror = () => {
    $("#app")?.classList.add("runtime-disconnected");
  };
  source.onopen = async () => {
    $("#app")?.classList.remove("runtime-disconnected");
    try {
      Object.assign(runtimeState, await apiRequest("/api/bootstrap"));
      renderDevices(); renderTransfers(); renderStaticDataAsLive(); renderIncoming(runtimeState.incomingRequests || [], true);
    } catch { $("#app")?.classList.add("runtime-disconnected"); }
  };
}

document.addEventListener("click", async (event) => {
  const fileAction = event.target.closest("[data-file-action]");
  if (fileAction) {
    event.preventDefault(); fileAction.disabled = true;
    try {
      const target = fileAction.dataset.fileAction === "downloads" ? "/api/downloads/show" : `/api/received/${encodeURIComponent(fileAction.dataset.transferId)}/${fileAction.dataset.fileAction}`;
      await apiRequest(target, { method: "POST" });
    } catch (error) { toast("Could not open saved file", error.message, "error"); }
    finally { fileAction.disabled = false; }
    return;
  }
  const pairButton = event.target.closest("[data-real-pair]");
  if (pairButton) {
    event.preventDefault();
    event.stopPropagation();
    const deviceId = pairButton.dataset.realPair;
    const device = runtimeState.devices.find((item) => item.deviceId === deviceId);
    runtimeState.pendingPairDeviceId = deviceId;
    $("#pairTarget").hidden = false;
    $("#pairConfirm").hidden = false;
    $("#pairTargetName").textContent = device?.name || "device";
    $("#pairTargetFingerprint").textContent = device?.fingerprint || "—";
    openModal("pairing");
    requestAnimationFrame(() => $("#pairCodeInput").focus());
    return;
  }
  const sendButton = event.target.closest("[data-real-send-device]");
  if (sendButton) {
    event.preventDefault();
    event.stopPropagation();
    openSend({ device: sendButton.dataset.realSendDevice });
    return;
  }
  const remove = event.target.closest("[data-remove-stage]");
  if (remove) {
    const id = remove.dataset.removeStage;
    try { await apiRequest(`/api/stage/${id}`, { method: "DELETE" }); } catch { /* local UI still removes it */ }
    runtimeState.stagedFiles = runtimeState.stagedFiles.filter((file) => file.id !== id);
    renderStagedFiles();
    return;
  }
  const transferAction = event.target.closest("[data-real-transfer-action]");
  if (transferAction) {
    try {
      const result = await apiRequest(`/api/transfers/${transferAction.dataset.transferId}/action`, {
        method: "POST",
        body: { action: transferAction.dataset.realTransferAction },
      });
      if (result.transfer) updateTransfer(result.transfer);
      else { const snapshot = await apiRequest("/api/transfers"); runtimeState.transfers = snapshot.transfers; renderTransfers(); }
    } catch (error) { toast("Transfer action failed", error.message, "error"); }
    return;
  }
  const retry = event.target.closest("[data-retry-transfer]");
  if (retry) {
    const transfer = runtimeState.transfers.find((item) => item.id === retry.dataset.retryTransfer);
    if (!transfer?.stagedFileId) return;
    try {
      const result = await apiRequest(`/api/transfers/${encodeURIComponent(transfer.id)}/retry`, { method: "POST" });
      (result.transfers || [result.transfer]).filter(Boolean).forEach(updateTransfer);
    } catch (error) { toast("Retry failed", error.message, "error"); }
    return;
  }
  const removeTrusted = event.target.closest("[data-remove-trusted]");
  if (removeTrusted) {
    try {
      await apiRequest(`/api/trusted/${removeTrusted.dataset.removeTrusted}`, { method: "DELETE" });
      runtimeState.trustedDevices = runtimeState.trustedDevices.filter((item) => item.deviceId !== removeTrusted.dataset.removeTrusted);
      const live = runtimeState.devices.find((item) => item.deviceId === removeTrusted.dataset.removeTrusted);
      if (live) live.trusted = false;
      renderDevices();
      renderTrustedContacts();
      toast("Device trust removed", "Future transfers require pairing again", "warning");
    } catch (error) { toast("Trust could not be removed", error.message, "error"); }
    return;
  }
  const stepButton = event.target.closest("#settingsPane .stepper button");
  if (stepButton) {
    const row = stepButton.closest(".set-row");
    const valueNode = row.querySelector(".stepper span");
    const current = Number.parseInt(valueNode.textContent, 10) || 0;
    const stepper = stepButton.parentElement;
    const min = Number(stepper.dataset.min) || 0;
    const max = Number(stepper.dataset.max) || 999;
    const next = Math.max(min, Math.min(max, current + (stepButton === stepper.firstElementChild ? -1 : 1)));
    valueNode.textContent = `${next}${row.querySelector(".set-row-text p")?.textContent === "Font size" ? " px" : ""}`;
    persistSetting(row, next);
    return;
  }
  const toggle = event.target.closest("#settingsPane .toggle");
  if (toggle) queueMicrotask(() => persistSetting(toggle.closest(".set-row"), toggle.classList.contains("is-on")));
  const swatch = event.target.closest("#settingsPane [data-swatch]");
  if (swatch) queueMicrotask(() => persistSetting(swatch.closest(".set-row"), swatch.dataset.swatch));
  const applyPath = event.target.closest("#settingsPane [data-apply-path]");
  if (applyPath) {
    const row = applyPath.closest(".set-row");
    persistSetting(row, row.querySelector("input").value);
  }
});

document.addEventListener("change", (event) => {
  const row = event.target.closest("#settingsPane .set-row");
  if (!row) return;
  if (event.target.matches("select, input")) persistSetting(row, event.target.type === "checkbox" ? event.target.checked : event.target.value);
});

document.addEventListener("input", (event) => {
  if (!event.target.matches("[aria-label='Filter shared items']")) return;
  const query = event.target.value.trim().toLocaleLowerCase();
  $$("[data-received-name]").forEach((card) => { card.hidden = !card.dataset.receivedName.includes(query); });
});

$("#manualPeerConnect").addEventListener("click", () => {
  findManualDevice().catch((error) => toast("Device not found", error.message, "error"));
});
$("#manualPeerAddress").addEventListener("keydown", (event) => {
  if (event.key !== "Enter") return;
  event.preventDefault();
  findManualDevice().catch((error) => toast("Device not found", error.message, "error"));
});

if (typeof window.DropSyncAndroid === "undefined") {
  $("#fileInput").addEventListener("change", (event) => uploadSelectedFiles(event.target.files).catch((error) => toast("File staging failed", error.message, "error")));
  $("#folderInput").addEventListener("change", (event) => uploadSelectedFiles(event.target.files).catch((error) => toast("Folder staging failed", error.message, "error")));
}
$("#dropzone").addEventListener("dragover", (event) => event.preventDefault());
$("#dropzone").addEventListener("drop", (event) => {
  event.preventDefault();
  event.stopPropagation();
  uploadSelectedFiles(event.dataTransfer.files).catch((error) => toast("File staging failed", error.message, "error"));
});

async function initializeRuntime() {
  initializeEmptyRuntime();
  if (typeof window.DropSyncAndroid !== "undefined") {
    document.documentElement.classList.add("android-app");
    try {
      const data = await apiRequest("/api/bootstrap");
      Object.assign(runtimeState, data);
      runtimeState.unavailable = false;
      realRuntimeActive = true;
      $$(".page[data-page='transfers'] .transfer-row, .page[data-page='dashboard'] [data-transfer]").forEach((row) => row.remove());
      $$(".profile-name").forEach((node) => { node.textContent = data.self.name; });
      $$(".profile-status").forEach((node) => { node.textContent = "Online · LAN discovery active"; });
      $("#pageSubtitle").textContent = `${data.self.name} · ${data.self.fingerprint}`;
      renderDevices(); renderStagedFiles(); renderTransfers(); renderStaticDataAsLive(); hydrateSettingsControls();
      let refreshing = false, refreshAgain = false, handledImport = 0;
      const refreshNative = async () => {
        if (refreshing) { refreshAgain = true; return; }
        refreshing = true;
        try {
          do {
            refreshAgain = false;
            const result = await apiRequest("/api/bootstrap");
            const previous = new Map(runtimeState.transfers.map((item) => [item.id, item.status]));
            Object.assign(runtimeState, result);
            renderDevices(); renderStagedFiles(); renderTransfers();
            renderIncoming(result.incomingRequests || [], true); window.updateDropSyncProfile?.(); window.renderDropSyncNotifications?.();
            $("#sendContinue").disabled = Boolean(result.importState?.busy);
            $("#startTransfer").disabled = Boolean(result.importState?.busy);
            for (const transfer of result.transfers || []) {
              if (!previous.has(transfer.id) || previous.get(transfer.id) === transfer.status) continue;
              if (transfer.status === "completed") { toast("Transfer completed", `${transfer.fileName} · SHA-256 verified`, "success"); renderStaticDataAsLive(); }
              if (transfer.status === "failed") toast("Transfer failed", transfer.error || transfer.fileName, "error");
            }
            if (parseHash().page === "network") renderStaticDataAsLive();
            const imported = result.importState;
            if (imported?.pending && !imported.busy && imported.revision > handledImport && parseHash().page !== "onboarding") {
              handledImport = imported.revision;
              if (imported.error) toast("Some files could not be prepared", imported.error, "error");
              if (result.stagedFiles?.length) openSend({});
              await apiRequest("/api/import/ack", { method: "POST", body: { revision: imported.revision } });
            }
          } while (refreshAgain);
        } catch (error) { console.warn("Android service refresh failed", error); }
        finally { refreshing = false; }
      };
      window.addEventListener("dropsync-native-devices", refreshNative);
      setInterval(refreshNative, 2000);
      await refreshNative();
      toast("Local network discovery active", "Nearby DropSync computers will appear automatically", "success", 3200);
    } catch (error) {
      console.warn("DropSync Android peer service unavailable", error);
      toast("Local network unavailable", error.message, "warning", 0);
    }
    return;
  }
  try {
    const data = await apiRequest("/api/bootstrap");
    Object.assign(runtimeState, data);
    runtimeState.unavailable = false;
    realRuntimeActive = true;
    $$(".page[data-page='transfers'] .transfer-row, .page[data-page='dashboard'] [data-transfer]").forEach((row) => row.remove());
    $$(".profile-name").forEach((node) => { node.textContent = data.self.name; });
    $$(".profile-status").forEach((node) => { node.lastChild.textContent = "Online · Secure local service"; });
    $("#pageSubtitle").textContent = `${data.self.name} · ${data.self.fingerprint}`;
    renderDevices();
    renderStagedFiles();
    renderTransfers();
    renderStaticDataAsLive();
    hydrateSettingsControls();
    connectEvents();
    toast("Secure local service connected", `${data.self.name} · ${data.security.encryption}`, "success", 3200);
  } catch (error) {
    console.warn("DropSync local service unavailable", error);
    toast("Local service unavailable", "Run npm start and open http://127.0.0.1:47821", "warning", 0);
  }
}

function initializeEmptyRuntime() {
  $$(".page[data-page='transfers'] .transfer-row, .page[data-page='dashboard'] [data-transfer]").forEach((row) => row.remove());
  Object.assign(runtimeState, {
    unavailable: true,
    self: { deviceId: "local", name: isNativeAndroid ? "This Android device" : "This device", addresses: [], fingerprint: "—", port: "—" },
    settings: { deviceName: "This device", downloadDirectory: "No transfer service connected", discoveryEnabled: false, ui: {} },
    system: {}, devices: [], trustedDevices: [], transfers: [],
    capabilities: { discovery: false, pairing: false, transferSend: false, transferReceive: false },
  });
  document.documentElement.classList.add("runtime-ready");
  renderDevices(); renderTransfers(); renderStagedFiles(); renderStaticDataAsLive();
  $("#netChip").lastChild.textContent = "Offline";
  $$(".profile-name").forEach((node) => { node.textContent = runtimeState.self.name; });
  $$(".profile-status").forEach((node) => { node.textContent = "Local device"; });
  const storage = $(".page[data-page='dashboard'] .storage-mini");
  if (storage) storage.replaceChildren(createEmpty("Storage information is available when the transfer service is connected."));
  const note = $(".page[data-page='dashboard'] .mini-note");
  if (note) note.textContent = "No storage usage reported";
  const status = $(".statusbar .statusbar-item");
  if (status) status.textContent = "Transfer service offline";
  PAGE_META.dashboard[1] = isNativeAndroid ? "Starting local network discovery…" : "Connecting to local service…";
  $("#pageSubtitle").textContent = PAGE_META[parseHash().page]?.[1] || "";
}

initializeRuntime();
