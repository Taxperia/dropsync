"use strict";
window.renderDropSyncUpdates = async function () {
  const panel = document.getElementById("updateSettings"); if (!panel) return;
  let busy = false;
  function render(state) {
    if (!panel.isConnected) return;
    panel.replaceChildren();
    const p = document.createElement("p"); p.className = "set-info";
    p.textContent = state.status === "error" && state.error ? state.error
      : state.status === "browser" ? "The browser uses your running local service. Install the desktop or Android app to use application updates."
      : !state.configured ? "Updates are not activated in this build. A release repository and a trusted signing key must be configured by the publisher."
      : ({ idle: "Ready to check for signed updates.", checking: "Checking…", current: "You have the latest available version.", available: `Version ${state.version} is available.`, downloading: "Downloading and verifying…", downloaded: "Verified package ready. Install to continue with the system installer.", installing: "Installation started.", error: state.error || "Update operation failed. Try checking again." }[state.status] || state.status);
    panel.appendChild(p);
    if (!state.configured) return;
    const controls = document.createElement("div"); controls.className = "update-actions";
    const action = async (name, body = {}) => {
      if (busy) return; busy = true; controls.querySelectorAll("button,input").forEach((el) => { el.disabled = true; });
      try { render(await apiRequest(`/api/updates/${name}`, { method: "POST", body })); }
      catch (error) { render({ ...state, status: "error", error: error.message }); }
      finally { busy = false; }
    };
    for (const [name, label, show] of [["check", "Check for updates", true], ["download", "Download verified update", state.status === "available"], ["install", "Install update", state.status === "downloaded"]]) {
      if (!show) continue;
      const button = document.createElement("button"); button.type = "button"; button.className = "btn btn-secondary"; button.textContent = label; button.onclick = () => action(name); controls.appendChild(button);
    }
    const label = document.createElement("label"), input = document.createElement("input"); input.type = "checkbox"; input.checked = state.automatic === true;
    input.onchange = () => action("preferences", { automatic: input.checked }); label.append(input, document.createTextNode(" Automatically check for updates")); controls.appendChild(label); panel.appendChild(controls);
  }
  try { render(await apiRequest("/api/updates/status")); } catch (error) { render({ status: "error", configured: false, error: error.message }); }
};

// Automatic checks surface an actionable notice; they never install a package.
(() => {
  if (!isNativeAndroid && !navigator.userAgent.includes("DropSyncDesktop/")) return;
  let lastNotice = "", polling = false;
  async function notice() {
    if (polling || document.hidden || document.documentElement.classList.contains("entry-screen")) return;
    polling = true;
    try {
      const state = await apiRequest("/api/updates/status");
      if (!state.configured || !["available", "downloaded"].includes(state.status) || state.version === lastNotice) return;
      lastNotice = state.version;
      const notification = toast("Update available", `DropSync ${state.version} can be installed from Updates.`, "info", 0);
      const review = document.createElement("button"); review.className = "btn btn-secondary btn-sm"; review.textContent = "Review update";
      review.onclick = () => { openModal("settings"); renderSettings("updates"); notification.remove(); };
      notification.querySelector(".toast-body").appendChild(review);
    } catch { /* Updates are optional; keep transfer UI usable when unavailable. */ }
    finally { polling = false; }
  }
  setTimeout(notice, 45_000); setInterval(notice, 60_000);
})();
