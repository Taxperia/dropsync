package com.dropsync.app;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.net.Uri;
import android.os.Build;
import android.provider.Settings;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.*;
import java.net.URL;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

/** Signed GitHub release updates. Installation always uses Android's installer UI. */
final class AppUpdates {
    private final Activity activity;
    private final SharedPreferences preferences;
    private final JSONObject config;
    private JSONObject state;
    private JSONObject candidate;
    private final String currentVersion;
    private final boolean configured;
    private boolean busy;
    private static final Set<String> HOSTS = new HashSet<>(Arrays.asList("github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"));
    private static final byte[] ED_PREFIX = new byte[]{0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x03,0x21,0x00};

    AppUpdates(Activity activity) throws Exception {
        this.activity = activity;
        preferences = activity.getSharedPreferences("dropsync.updates", 0);
        try (InputStream input = activity.getAssets().open("www/update-config.json")) {
            config = new JSONObject(new String(read(input, 16_384), StandardCharsets.UTF_8));
        }
        currentVersion = activity.getPackageManager().getPackageInfo(activity.getPackageName(), 0).versionName;
        boolean valid;
        try { base("latest"); publicKey(); valid = true; } catch (Exception ignored) { valid = false; }
        configured = valid;
        state = new JSONObject().put("status", configured ? "idle" : "unconfigured").put("currentVersion", currentVersion);
    }

    synchronized JSONObject status() throws Exception {
        return new JSONObject(state.toString()).put("configured", configured).put("automatic", preferences.getBoolean("automatic", false)).put("platform", "android");
    }
    synchronized boolean automatic() { return configured && preferences.getBoolean("automatic", false) && !busy; }
    String request(String path, String method, String body) {
        try {
            String action = path.substring("/api/updates/".length());
            if ("status".equals(action) && "GET".equals(method)) return status().toString();
            if (!"POST".equals(method)) throw new IOException("Unsupported update request");
            if ("preferences".equals(action)) {
                JSONObject value = new JSONObject(body == null || body.isEmpty() ? "{}" : body);
                preferences.edit().putBoolean("automatic", value.optBoolean("automatic", false)).apply();
                return status().toString();
            }
            if (!configured) throw new IOException("Signed updates are not configured in this build");
            synchronized (this) { if (busy) throw new IOException("An update operation is already running"); busy = true; }
            try {
                if ("check".equals(action)) check();
                else if ("download".equals(action)) download();
                else if ("install".equals(action)) install();
                else throw new IOException("Unknown update action");
            } finally { synchronized (this) { busy = false; } }
            return status().toString();
        } catch (Exception error) {
            try { synchronized (this) { state.put("status", "error").put("error", String.valueOf(error.getMessage())); } return new JSONObject().put("__error", error.getMessage()).toString(); }
            catch (Exception ignored) { return "{\"__error\":\"Update operation failed\"}"; }
        }
    }
    private String base(String tag) throws Exception {
        String owner = config.optString("owner"), repo = config.optString("repo");
        if (!owner.matches("^[a-zA-Z0-9][a-zA-Z0-9-]{0,38}$") || !repo.matches("^[a-zA-Z0-9_.-]{1,100}$") || ".".equals(repo) || "..".equals(repo)) throw new IOException("Update repository not configured");
        return "https://github.com/" + owner + "/" + repo + "/releases/" + ("latest".equals(tag) ? "latest/download" : "download/" + tag) + "/";
    }
    private byte[] publicKey() throws Exception {
        String pem = config.getString("publicKey");
        byte[] der = Base64.getMimeDecoder().decode(pem.replaceAll("-----[^-]+-----", "").replaceAll("\\s", ""));
        if (der.length != ED_PREFIX.length + 32) throw new IOException("Invalid release public key");
        for (int i = 0; i < ED_PREFIX.length; i++) if (der[i] != ED_PREFIX[i]) throw new IOException("Invalid release public key");
        return Arrays.copyOfRange(der, ED_PREFIX.length, der.length);
    }
    private void check() throws Exception {
        synchronized (this) { candidate = null; state.remove("error"); state.put("status", "checking"); }
        byte[] bytes = fetch(base("latest") + "dropsync-update.json", 65_536);
        byte[] signature = Base64.getDecoder().decode(new String(fetch(base("latest") + "dropsync-update.sig", 256), StandardCharsets.US_ASCII).trim());
        Ed25519Signer verifier = new Ed25519Signer(); verifier.init(false, new Ed25519PublicKeyParameters(publicKey(), 0)); verifier.update(bytes, 0, bytes.length);
        if (!verifier.verifySignature(signature)) throw new IOException("Update signature is invalid");
        JSONObject manifest = new JSONObject(new String(bytes, StandardCharsets.UTF_8));
        String version = manifest.getString("version"); version(version);
        long now = System.currentTimeMillis(), published = manifest.getLong("publishedAt"), expires = manifest.getLong("expiresAt");
        if (manifest.getInt("schema") != 1 || !("v" + version).equals(manifest.getString("tag")) || published > now + 300_000 || expires <= now || expires <= published || expires - published > 31L * 86_400_000) throw new IOException("Update manifest is invalid or expired");
        if (!newer(version, currentVersion)) { synchronized (this) { state.put("status", "current").put("version", currentVersion); } return; }
        JSONArray artifacts = manifest.getJSONArray("artifacts"); if (artifacts.length() > 32) throw new IOException("Too many artifacts");
        JSONObject match = null;
        for (int i = 0; i < artifacts.length(); i++) {
            JSONObject artifact = artifacts.getJSONObject(i);
            if (!"android".equals(artifact.optString("platform")) || !"universal".equals(artifact.optString("arch"))) continue;
            if (match != null) throw new IOException("Ambiguous Android update package"); match = artifact;
        }
        if (match == null) throw new IOException("This release has no Android package");
        String name = match.getString("name"); long size = match.getLong("size");
        if (!name.matches("^[a-zA-Z0-9][a-zA-Z0-9._-]{0,180}$") || !name.endsWith(".apk") || size < 1 || size > 1_073_741_824L || !match.getString("sha256").matches("^[a-f0-9]{64}$")) throw new IOException("Invalid Android update package");
        match.put("url", base(manifest.getString("tag")) + name).put("expiresAt", expires).put("version", version);
        synchronized (this) { candidate = match; state.put("status", "available").put("version", version); }
    }
    private void download() throws Exception {
        JSONObject value = validCandidate();
        synchronized (this) { state.put("status", "downloading"); }
        File directory = new File(activity.getFilesDir(), "updates");
        if (!directory.isDirectory() && !directory.mkdirs()) throw new IOException("Cannot create update cache");
        File part = new File(directory, UUID.randomUUID() + ".part"), target = new File(directory, "verified.apk");
        HttpURLConnection connection = connection(value.getString("url"), 0); long done = 0, deadline = System.currentTimeMillis() + 600_000;
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try {
            try (InputStream input = connection.getInputStream(); OutputStream output = new FileOutputStream(part)) {
                byte[] buffer = new byte[65_536]; int count;
                while ((count = input.read(buffer)) != -1) {
                    done += count;
                    if (done > value.getLong("size") || System.currentTimeMillis() > deadline || Thread.currentThread().isInterrupted()) throw new IOException("Update download exceeded its limits");
                    digest.update(buffer, 0, count); output.write(buffer, 0, count);
                }
            }
            if (done != value.getLong("size") || !hex(digest.digest()).equals(value.getString("sha256"))) throw new IOException("Update package checksum mismatch");
            verifyApk(part, value);
            if (target.exists() && !target.delete()) throw new IOException("Cannot replace previous update");
            if (!part.renameTo(target)) throw new IOException("Cannot save verified update");
            synchronized (this) { state.put("status", "downloaded"); }
        } finally { connection.disconnect(); part.delete(); }
    }
    private synchronized JSONObject validCandidate() throws Exception {
        if (candidate == null || candidate.getLong("expiresAt") <= System.currentTimeMillis()) throw new IOException("Check for updates first");
        return new JSONObject(candidate.toString());
    }
    private void verifyApk(File file, JSONObject value) throws Exception {
        PackageManager pm = activity.getPackageManager();
        int flags = Build.VERSION.SDK_INT >= 28 ? PackageManager.GET_SIGNING_CERTIFICATES : PackageManager.GET_SIGNATURES;
        PackageInfo installed = pm.getPackageInfo(activity.getPackageName(), flags);
        PackageInfo archive = pm.getPackageArchiveInfo(file.getAbsolutePath(), flags);
        if (archive == null || !activity.getPackageName().equals(archive.packageName) || !value.getString("version").equals(archive.versionName)) throw new IOException("Wrong APK package or version");
        long code = Build.VERSION.SDK_INT >= 28 ? archive.getLongVersionCode() : archive.versionCode;
        long old = Build.VERSION.SDK_INT >= 28 ? installed.getLongVersionCode() : installed.versionCode;
        if (code <= old || !certificates(installed).equals(certificates(archive))) throw new IOException("APK must be newer and signed by the installed application's certificate");
    }
    private static Set<String> certificates(PackageInfo info) throws Exception {
        Signature[] signatures = Build.VERSION.SDK_INT >= 28 ? info.signingInfo == null ? null : info.signingInfo.getApkContentsSigners() : info.signatures;
        if (signatures == null || signatures.length == 0) throw new IOException("Missing APK certificate");
        Set<String> result = new HashSet<>(); for (Signature signature : signatures) result.add(hex(MessageDigest.getInstance("SHA-256").digest(signature.toByteArray()))); return result;
    }
    private void install() throws Exception {
        JSONObject value = validCandidate(); File file = new File(activity.getFilesDir(), "updates/verified.apk");
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream input = new FileInputStream(file)) { byte[] buffer = new byte[65_536]; int count; while ((count = input.read(buffer)) != -1) digest.update(buffer, 0, count); }
        if (!value.getString("sha256").equals(hex(digest.digest()))) throw new IOException("Downloaded APK changed");
        verifyApk(file, value);
        if (!activity.getPackageManager().canRequestPackageInstalls()) {
            launchInstaller(new Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:" + activity.getPackageName())));
            throw new IOException("Allow updates from DropSync in Android settings, then check and download the update again");
        }
        synchronized (this) { state.put("status", "installing"); }
        Intent intent = new Intent(Intent.ACTION_VIEW).setDataAndType(Uri.parse("content://" + activity.getPackageName() + ".updates/verified.apk"), "application/vnd.android.package-archive");
        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION); launchInstaller(intent);
    }
    private void launchInstaller(Intent intent) {
        activity.runOnUiThread(() -> {
            try {
                if (activity.isFinishing() || activity.isDestroyed()) return;
                activity.startActivity(intent);
            } catch (RuntimeException error) {
                try { synchronized (AppUpdates.this) { state.put("status", "error").put("error", "Android did not allow the installer to open"); } } catch (Exception ignored) { }
                android.widget.Toast.makeText(activity, "Android did not allow the installer to open", android.widget.Toast.LENGTH_LONG).show();
            }
        });
    }
    private static HttpURLConnection connection(String address, int redirects) throws Exception {
        URL url = new URL(address);
        if (!"https".equals(url.getProtocol()) || !HOSTS.contains(url.getHost()) || url.getUserInfo() != null || (url.getPort() != -1 && url.getPort() != 443)) throw new IOException("Untrusted update URL");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setInstanceFollowRedirects(false); connection.setConnectTimeout(15_000); connection.setReadTimeout(20_000);
        connection.setRequestProperty("User-Agent", "DropSync-Updater"); connection.setRequestProperty("Accept-Encoding", "identity");
        int code = connection.getResponseCode();
        if (Arrays.asList(301, 302, 303, 307, 308).contains(code)) {
            String location = connection.getHeaderField("Location"); connection.disconnect();
            if (redirects >= 4 || location == null) throw new IOException("Too many update redirects");
            return connection(new URL(url, location).toString(), redirects + 1);
        }
        if (code != 200) { connection.disconnect(); throw new IOException("Update server returned " + code); }
        String encoding = connection.getContentEncoding();
        if (encoding != null && !"identity".equalsIgnoreCase(encoding)) { connection.disconnect(); throw new IOException("Unexpected update encoding"); }
        return connection;
    }
    private static byte[] fetch(String url, int max) throws Exception {
        HttpURLConnection connection = connection(url, 0);
        try (InputStream input = connection.getInputStream()) { return read(input, max); } finally { connection.disconnect(); }
    }
    private static byte[] read(InputStream input, int max) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream(); byte[] buffer = new byte[4096]; int count; long deadline = System.currentTimeMillis() + 30_000;
        while ((count = input.read(buffer)) != -1) { if (bytes.size() + count > max || System.currentTimeMillis() > deadline) throw new IOException("Update response exceeded limits"); bytes.write(buffer, 0, count); } return bytes.toByteArray();
    }
    private static int[] version(String value) throws Exception {
        if (!value.matches("^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$")) throw new IOException("Invalid stable version");
        String[] parts = value.split("\\."); return new int[]{Integer.parseInt(parts[0]), Integer.parseInt(parts[1]), Integer.parseInt(parts[2])};
    }
    private static boolean newer(String left, String right) throws Exception { int[] a = version(left), b = version(right); for (int i = 0; i < 3; i++) if (a[i] != b[i]) return a[i] > b[i]; return false; }
    private static String hex(byte[] bytes) { StringBuilder result = new StringBuilder(); for (byte value : bytes) result.append(String.format(Locale.ROOT, "%02x", value & 255)); return result.toString(); }
}
