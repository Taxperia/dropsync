// Public client configuration only. Never put service-role keys or provider secrets here.
// Android builds can inject a self-hosted or Supabase endpoint through Gradle.
window.DROPSYNC_AUTH = Object.freeze({
  type: "supabase",
  url: "",
  publishableKey: "",
  providers: ["google", "facebook", "github"],
});
