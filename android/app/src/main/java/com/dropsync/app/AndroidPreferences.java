package com.dropsync.app;

import android.content.Context;
import android.net.Uri;
import android.provider.DocumentsContract;
import org.json.JSONObject;
import java.io.IOException;
import java.util.*;

final class AndroidPreferences {
    private final SecretStore store;
    private final Context context;
    private JSONObject value;
    private boolean stopped;
    synchronized void close() { stopped = true; }
    private void assertOpen() throws IOException { if (stopped) throw new IOException("Sharing has stopped"); }
    AndroidPreferences(Context context) {
        this.context = context.getApplicationContext();
        store = new SecretStore(context, "dropsync.settings.v2");
        try { value = new JSONObject(store.get("settings", "{}"));
            if (!value.has("deviceName")) { value.put("deviceName", context.getSharedPreferences("dropsync.native.v1", 0).getString("deviceName", android.os.Build.MODEL)); store.put("settings", value.toString()); context.getSharedPreferences("dropsync.native.v1", 0).edit().remove("deviceName").commit(); }
        } catch (Exception error) { throw new IllegalStateException("Could not unlock settings", error); }
    }
    synchronized JSONObject get() throws Exception {
        JSONObject defaults = new JSONObject().put("deviceName", android.os.Build.MODEL).put("discoveryEnabled", true).put("receivingEnabled", true)
                .put("requireIncomingApproval", true).put("allowExecutableFiles", false).put("clipboardEnabled", false).put("keepRunningInBackground", true)
                .put("notificationsEnabled", true).put("uploadLimitKBps", 0).put("downloadLimitKBps", 0).put("maxIncomingFileBytes", 10L * 1024 * 1024 * 1024)
                .put("maxConcurrentIncoming", 3).put("retryAttempts", 3).put("virusTotalEnabled", false).put("virusTotalBlockUnknown", true).put("virusTotalUploadUnknown", false)
                .put("profile", new JSONObject().put("displayName", "").put("avatar", "")).put("ui", new JSONObject());
        JSONObject snapshot = new JSONObject(value.toString()); Iterator<String> keys = snapshot.keys(); while (keys.hasNext()) { String key = keys.next(); defaults.put(key, snapshot.get(key)); }
        defaults.put("downloadDirectory", value.optString("receiveFolderLabel", "Choose a folder to receive files"));
        defaults.put("receiveFolderSelected", !value.optString("receiveTree").isEmpty()).put("keyStorage", "Android Keystore").put("vaultProtected", true);
        defaults.remove("receiveTree");
        android.os.Bundle restrictions = context.getSystemService(android.content.RestrictionsManager.class).getApplicationRestrictions(); org.json.JSONArray managed = new org.json.JSONArray();
        for (String key : Arrays.asList("requireIncomingApproval", "allowExecutableFiles", "receivingEnabled", "clipboardEnabled", "discoveryEnabled", "virusTotalEnabled", "virusTotalBlockUnknown", "virusTotalUploadUnknown")) if (restrictions.containsKey(key)) {
            Object item = restrictions.get(key); if (!(item instanceof Boolean)) throw new IOException("Invalid managed policy: " + key); defaults.put(key, item); managed.put(key);
        }
        for (String key : Arrays.asList("uploadLimitKBps", "downloadLimitKBps", "maxConcurrentIncoming", "retryAttempts")) if (restrictions.containsKey(key)) {
            Object item = restrictions.get(key); long min = key.equals("maxConcurrentIncoming") ? 1 : 0, max = key.equals("maxConcurrentIncoming") ? 8 : key.equals("retryAttempts") ? 5 : 1048576;
            if (!(item instanceof Number) || !Double.isFinite(((Number) item).doubleValue()) || ((Number) item).doubleValue() != ((Number) item).longValue() || ((Number) item).longValue() < min || ((Number) item).longValue() > max) throw new IOException("Invalid managed policy: " + key); defaults.put(key, ((Number) item).longValue()); managed.put(key);
        }
        if (restrictions.containsKey("maxIncomingFileMiB")) { int size = restrictions.getInt("maxIncomingFileMiB"); if (size < 1 || size > 102400) throw new IOException("Invalid managed receiving limit"); defaults.put("maxIncomingFileBytes", size * 1024L * 1024L); managed.put("maxIncomingFileBytes"); }
        defaults.put("managedSettings", managed); return defaults;
    }
    synchronized JSONObject update(JSONObject patch) throws Exception {
        assertOpen();
        JSONObject original = value; value = new JSONObject(value.toString());
        try {
        JSONObject current = get();
        org.json.JSONArray managed = current.getJSONArray("managedSettings"); for (int i=0;i<managed.length();i++) { String key = managed.getString(i); if (patch.has(key)) { Object incoming = patch.get(key), locked = current.get(key); boolean equal = incoming instanceof Number && locked instanceof Number ? ((Number) incoming).doubleValue() == ((Number) locked).doubleValue() : incoming.equals(locked); if (!equal) throw new IOException("This setting is managed by your organization: " + key); } }
        String[] booleans = {"discoveryEnabled","receivingEnabled","requireIncomingApproval","allowExecutableFiles","clipboardEnabled","keepRunningInBackground","notificationsEnabled","virusTotalEnabled","virusTotalBlockUnknown","virusTotalUploadUnknown"};
        for (String key : booleans) if (patch.has(key)) { if (!(patch.get(key) instanceof Boolean)) throw new IOException("Invalid setting: " + key); value.put(key, patch.getBoolean(key)); }
        for (String key : Arrays.asList("uploadLimitKBps", "downloadLimitKBps", "retryAttempts", "maxConcurrentIncoming", "maxIncomingFileBytes")) if (patch.has(key)) {
            if (!(patch.get(key) instanceof Number)) throw new IOException("Invalid numeric setting: " + key);
            long number = patch.getLong(key), max = key.equals("maxIncomingFileBytes") ? 100L * 1024 * 1024 * 1024 : key.equals("retryAttempts") ? 5 : key.equals("maxConcurrentIncoming") ? 8 : 1_048_576;
            long min = key.equals("maxIncomingFileBytes") ? 1024 : key.equals("maxConcurrentIncoming") ? 1 : 0;
            if (number < min || number > max || patch.getDouble(key) != (double) number) throw new IOException("Invalid setting: " + key); value.put(key, number);
        }
        if (patch.has("deviceName")) { String name = patch.getString("deviceName").trim(); if (name.isEmpty() || name.length() > 48) throw new IOException("Use a device name of 1–48 characters"); value.put("deviceName", name); }
        if (patch.has("profile")) {
            JSONObject profile = patch.getJSONObject("profile"); String name = profile.optString("displayName").trim(), avatar = profile.optString("avatar");
            if (name.length() > 80 || (!avatar.isEmpty() && !avatar.matches("^data:image/(png|jpeg|webp);base64,[A-Za-z0-9+/=]{1,160000}$"))) throw new IOException("Invalid profile");
            value.put("profile", new JSONObject().put("displayName", name).put("avatar", avatar));
        }
        if (patch.has("ui")) {
            JSONObject ui = current.getJSONObject("ui"), incoming = patch.getJSONObject("ui"); Iterator<String> keys = incoming.keys(); int count = 0;
            while (keys.hasNext()) { String key = keys.next(); Object item = incoming.get(key); if (++count > 64 || !key.matches("[a-z0-9-]{1,80}") || !(item instanceof String || item instanceof Number || item instanceof Boolean) || item.toString().length() > 500) throw new IOException("Invalid preference"); ui.put(key, item); }
            value.put("ui", ui);
        }
        store.put("settings", value.toString()); return get();
        } catch (Exception error) { value = original; throw error; }
    }
    synchronized String tree() { return value.optString("receiveTree"); }
    boolean peerAllowed(String id) {
        android.os.Bundle restrictions = context.getSystemService(android.content.RestrictionsManager.class).getApplicationRestrictions();
        if (!restrictions.containsKey("allowedPeerIds")) return true;
        Object entry = restrictions.get("allowedPeerIds"); String[] ids = entry instanceof String[] ? (String[]) entry : entry instanceof String ? ((String) entry).split(",") : new String[0];
        for (String allowed : ids) if (id.equals(allowed.trim())) return true; return false;
    }
    synchronized String folderLabel() { return value.optString("receiveFolderLabel", "Selected folder"); }
    synchronized void selectTree(Uri uri, String label) throws Exception {
        assertOpen();
        if (!"content".equals(uri.getScheme()) || !DocumentsContract.isTreeUri(uri)) throw new IOException("Choose a document folder");
        JSONObject next = new JSONObject(value.toString()).put("receiveTree", uri.toString()).put("receiveFolderLabel", label); store.put("settings", next.toString()); value = next;
    }
    synchronized String apiKey() throws Exception { return store.get("virusTotalApiKey", ""); }
    synchronized org.json.JSONArray manualPeers() throws Exception { return new org.json.JSONArray(value.optJSONArray("manualPeers") == null ? "[]" : value.getJSONArray("manualPeers").toString()); }
    synchronized void rememberPeer(String address) throws Exception {
        assertOpen();
        org.json.JSONArray peers = manualPeers(); for (int i=0;i<peers.length();i++) if (address.equals(peers.getString(i))) return;
        if (peers.length() >= 50) throw new IOException("Remove a saved address before adding more");
        peers.put(address); JSONObject next = new JSONObject(value.toString()).put("manualPeers", peers); store.put("settings", next.toString()); value = next;
    }
    synchronized void apiKey(String key) throws Exception {
        assertOpen();
        if (!key.isEmpty() && !key.matches("[a-fA-F0-9]{64}")) throw new IOException("Enter a valid VirusTotal API key");
        if (key.isEmpty()) store.remove("virusTotalApiKey"); else store.put("virusTotalApiKey", key);
        NativeThreatScanner.reset();
    }
}
