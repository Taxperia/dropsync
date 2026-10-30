"use strict";
window.dropSyncSettings = (preferences) => [
  { id: "general", icon: "i-gear", title: "General", desc: "Your device, notifications and background sharing.", groups: [
    { name: "Device", items: [
      ["text", "Device name", "Shown to devices on your private networks", ""],
      ...(isNativeAndroid ? [["action", "Receiving folder", "Choose where verified incoming files are saved", "Choose folder", "choose-folder"]] : [["path", "Default download folder", "Verified incoming files are saved here", ""]]),
      ["toggle", "Automatically discover devices", "Find nearby peers. Saved Tailscale addresses remain available.", 1],
    ] },
    { name: "While you are away", items: [
      ["toggle", "Keep running in background", "Continue sharing when the window is closed or your phone screen turns off", 1],
      ...(!isNativeAndroid ? [["toggle", "Keep computer available", "Prevent sleep while ready to receive; the display can still turn off", 0]] : [["action", "Background and battery settings", "Review Android’s background access restrictions", "Open Android settings", "background-settings"]]),
      ["toggle", "Show transfer notifications", "Incoming requests, completed transfers and interruptions", 1],
      ["number", "Automatic retry attempts", "Reconnect interrupted transfers; 0 disables automatic retries", 3, [0, 5]],
    ] },
  ] },
  { id: "transfers", icon: "i-send", title: "Transfers", desc: "Bandwidth and receiving limits. A speed of 0 means unlimited.", groups: [
    { name: "Bandwidth", items: [["number", "Upload limit (KiB/s)", "Maximum combined outgoing speed", 0, [0, 1048576]], ["number", "Download limit (KiB/s)", "Maximum incoming speed", 0, [0, 1048576]]] },
    { name: "Receiving", items: [["number", "Maximum file size (MiB)", "Reject files larger than this before saving", 10240, [1, 102400]], ["number", "Simultaneous incoming files", "Limit concurrent receiving jobs", 3, [1, 8]]] },
  ] },
  { id: "security", icon: "i-shield-check", title: "Security", desc: "Only paired, permitted devices can send. Signing in never pairs a device.", groups: [
    { name: "Incoming files", items: [["toggle", "Allow incoming files", "Pause receiving on this device", 1], ["toggle", "Ask before receiving files", "Show Accept / Decline for each new file", 1], ["toggle", "Allow executable files", "Permit installers, scripts and macro-enabled documents", 0]] },
    { name: "Clipboard", items: [["toggle", "Enable clipboard sharing", "Share only when you click. No clipboard monitoring or history.", 0]] },
    { name: "Local protection", items: [["status", "Key storage", "Device keys and private records are protected using the operating-system vault when available", "Loading…"]] },
  ] },
  { id: "api", icon: "i-key", title: "API integrations", desc: "Optional file reputation checks using your own account.", custom: "api", groups: [] },
  { id: "profile", icon: "i-user", title: "Profile", desc: "Your local display name and avatar.", custom: "profile", groups: [] },
  { id: "network", icon: "i-globe", title: "Tailscale", desc: "Reach your own devices away from home.", custom: "tailscale", groups: [] },
  { id: "organization", icon: "i-users", title: "Organization", desc: "Managed policies and account access.", custom: "organization", groups: [] },
  { id: "appearance", icon: "i-palette", title: "Appearance", desc: "Choose a palette for this device.", groups: [{ name: "Display", items: [
    ["select", "Theme", "Saved locally on this device", preferences.theme || "System", ["System", "Dark", "Light", "GitHub Dark", "GitHub Light", "Midnight", "Nord"]],
    ["toggle", "Reduce motion", "Keep transitions still", preferences.reduceMotion || 0],
  ] }] },
  { id: "updates", icon: "i-info", title: "Updates", desc: "Verified application updates.", custom: "updates", groups: [] },
  { id: "about", icon: "i-info", title: "About", desc: "Purpose, credits, licensing and project links.", custom: "project-about", groups: [] },
];
