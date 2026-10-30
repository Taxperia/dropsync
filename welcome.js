"use strict";
(() => {
  // Keep bookmarks from the former root-level dashboard working.
  const appRoutes = new Set(["dashboard", "nearby", "transfers", "history", "shared", "favorites", "contacts", "storage", "network", "settings-page", "account", "onboarding"]);
  if (location.pathname === "/" && appRoutes.has(location.hash.slice(1).split("?")[0])) {
    location.replace(`index.html${location.search}${location.hash}`);
    return;
  }
  let preferences;
  try { preferences = JSON.parse(localStorage.getItem("dropsync.preferences") || "{}"); } catch { preferences = {}; }
  function theme(value) {
    document.documentElement.dataset.theme = value === "Light" || (value === "System" && matchMedia("(prefers-color-scheme: light)").matches) ? "light" : "dark";
    document.querySelector("#themeToggle").setAttribute("aria-label", `Switch to ${document.documentElement.dataset.theme === "light" ? "dark" : "light"} theme`);
  }
  theme(preferences.theme || "Dark");
  document.querySelector("#themeToggle").onclick = () => {
    preferences.theme = document.documentElement.dataset.theme === "light" ? "Dark" : "Light";
    theme(preferences.theme);
    localStorage.setItem("dropsync.preferences", JSON.stringify(preferences));
  };
})();
