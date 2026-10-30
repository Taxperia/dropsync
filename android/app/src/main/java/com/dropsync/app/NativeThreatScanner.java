package com.dropsync.app;

import android.content.Context;
import org.json.JSONObject;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Opt-in VirusTotal lookup. Content upload additionally requires its own setting. */
final class NativeThreatScanner {
    private static final Map<String, Cached> cache = new HashMap<>();
    private static final String BASE = "https://www.virustotal.com/api/v3/";
    private static long nextRequest;
    private static final Set<HttpURLConnection> active = new HashSet<>();
    static void reset() { synchronized (cache) { cache.clear(); } List<HttpURLConnection> connections; synchronized (active) { connections = new ArrayList<>(active); active.clear(); } for (HttpURLConnection connection : connections) connection.disconnect(); }
    static String inspect(Context context, AndroidPreferences configuration, String hash, File file, boolean encrypted) throws Exception {
        JSONObject settings = configuration.get(); if (!settings.optBoolean("virusTotalEnabled")) return "not-scanned";
        if (!hash.matches("[a-f0-9]{64}")) throw new IOException("Invalid file digest");
        String key = configuration.apiKey(); if (key.isEmpty()) throw new IOException("Configure your VirusTotal API key before enabling checks");
        String result;
        synchronized (cache) { Cached cached = cache.get(hash); result = cached != null && System.currentTimeMillis() - cached.created < 600_000 ? cached.status : null; }
        if (result == null) {
            JSONObject report = request("files/" + hash, key, configuration); result = report == null ? "unknown" : verdict(report.getJSONObject("data").getJSONObject("attributes").getJSONObject("last_analysis_stats"));
            synchronized (cache) { if (cache.size() >= 256) cache.clear(); cache.put(hash, new Cached(result)); }
        }
        if ("malicious".equals(result)) throw new IOException("VirusTotal detected this file; transfer blocked");
        if ("unknown".equals(result) && settings.optBoolean("virusTotalUploadUnknown") && file != null) {
            long size = encrypted ? SecretStore.encryptedSize(file) : file.length();
            if (size < 0 || size > 32L * 1024 * 1024) throw new IOException("VirusTotal content upload is limited to 32 MiB");
            String boundary = "DropSync" + UUID.randomUUID().toString().replace("-", "");
            byte[] head = ("--" + boundary + "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"sample.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n").getBytes(StandardCharsets.US_ASCII);
            byte[] tail = ("\r\n--" + boundary + "--\r\n").getBytes(StandardCharsets.US_ASCII);
            HttpURLConnection connection = open("files", key, configuration); connection.setRequestMethod("POST"); connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary); connection.setFixedLengthStreamingMode(head.length + size + tail.length);
            JSONObject analysis;
            try {
                try (OutputStream output = connection.getOutputStream(); InputStream input = encrypted ? SecretStore.encryptedInput(file) : new FileInputStream(file)) {
                    output.write(head); byte[] buffer = new byte[16_384]; long done = 0; int count;
                    while ((count = input.read(buffer)) != -1) { done += count; if (done > size || Thread.currentThread().isInterrupted()) throw new IOException("Scan upload interrupted"); output.write(buffer, 0, count); }
                    if (done != size) throw new IOException("File changed during scan upload"); output.write(tail);
                }
                analysis = response(connection);
            } finally { close(connection); }
            String id = analysis.getJSONObject("data").getString("id"); if (!id.matches("[a-zA-Z0-9_+=:-]{1,300}")) throw new IOException("Invalid analysis reference");
            long deadline = System.currentTimeMillis() + 90_000;
            result = "unknown";
            while (System.currentTimeMillis() < deadline) {
                Thread.sleep(15_000); JSONObject report = request("analyses/" + id, key, configuration); if (report == null) throw new IOException("VirusTotal analysis was not found"); JSONObject data = report.getJSONObject("data").getJSONObject("attributes");
                if ("completed".equals(data.optString("status"))) { result = verdict(data.getJSONObject("stats")); break; }
            }
            synchronized (cache) { cache.put(hash, new Cached(result)); }
            if ("malicious".equals(result)) throw new IOException("VirusTotal detected this file; transfer blocked");
        }
        if ("unknown".equals(result) && settings.optBoolean("virusTotalBlockUnknown", true)) {
            if (file == null && settings.optBoolean("virusTotalUploadUnknown")) return "analysis-required";
            throw new IOException("VirusTotal has no completed report; transfer blocked by your unknown-file policy");
        }
        return "no-detections".equals(result) ? "virustotal-no-detections" : "virustotal-unknown";
    }
    private static String verdict(JSONObject stats) throws Exception {
        for (String name : Arrays.asList("malicious", "suspicious", "undetected", "harmless")) {
            Object value = stats.opt(name);
            if (!(value instanceof Number) || ((Number) value).doubleValue() < 0 || !Double.isFinite(((Number) value).doubleValue()) || ((Number) value).doubleValue() != Math.floor(((Number) value).doubleValue())) throw new IOException("Invalid VirusTotal report");
        }
        if (stats.optInt("malicious") > 0 || stats.optInt("suspicious") > 0) return "malicious";
        return stats.optInt("undetected") + stats.optInt("harmless") > 0 ? "no-detections" : "unknown";
    }
    private static HttpURLConnection open(String resource, String key, AndroidPreferences configuration) throws Exception {
        long slot; synchronized (NativeThreatScanner.class) { slot = Math.max(System.currentTimeMillis(), nextRequest); nextRequest = slot + 16000; }
        long wait = slot - System.currentTimeMillis(); if (wait > 0) Thread.sleep(wait);
        JSONObject current = configuration.get();
        if (!current.optBoolean("virusTotalEnabled") || !configuration.apiKey().equals(key) || ("files".equals(resource) && !current.optBoolean("virusTotalUploadUnknown"))) throw new IOException("VirusTotal permission or API key changed; retry the transfer");
        HttpURLConnection connection = (HttpURLConnection) new URL(BASE + resource).openConnection();
        connection.setInstanceFollowRedirects(false); connection.setConnectTimeout(10_000); connection.setReadTimeout(20_000);
        connection.setRequestProperty("x-apikey", key); connection.setRequestProperty("Accept", "application/json"); synchronized (active) { active.add(connection); } return connection;
    }
    private static void close(HttpURLConnection connection) { synchronized (active) { active.remove(connection); } connection.disconnect(); }
    private static JSONObject request(String resource, String key, AndroidPreferences configuration) throws Exception {
        HttpURLConnection connection = open(resource, key, configuration); try { if (connection.getResponseCode() == 404) return null; return response(connection); } finally { close(connection); }
    }
    private static JSONObject response(HttpURLConnection connection) throws Exception {
        int code = connection.getResponseCode(); if (code != 200) throw new IOException(code == 429 ? "VirusTotal quota exceeded; try again later" : "VirusTotal request failed (" + code + ")");
        try (InputStream input = connection.getInputStream()) { ByteArrayOutputStream bytes = new ByteArrayOutputStream(); byte[] buffer = new byte[4096]; int count; long deadline = System.currentTimeMillis() + 30_000;
            while ((count = input.read(buffer)) != -1) { if (bytes.size() + count > 262_144 || System.currentTimeMillis() > deadline) throw new IOException("Scan response exceeded limits"); bytes.write(buffer, 0, count); } return new JSONObject(new String(bytes.toByteArray(), StandardCharsets.UTF_8)); }
    }
    private static final class Cached { final String status; final long created = System.currentTimeMillis(); Cached(String status) { this.status = status; } }
}
