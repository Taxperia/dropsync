package com.dropsync.app;

import android.content.Context;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.net.Uri;
import android.provider.OpenableColumns;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Native URI staging, outgoing queue and persistent transfer history. */
final class AndroidTransfers {
    private static final long MAX_FILE_BYTES = 10L * 1024 * 1024 * 1024;
    private final Context context;
    private final AndroidPreferences configuration;
    interface Endpoint { JSONObject resolve() throws Exception; }
    private final SecretStore preferences;
    private final File directory;
    private final Runnable changed;
    private volatile boolean stopped;
    private final ExecutorService sender = Executors.newSingleThreadExecutor();
    private final Map<String, Staged> staged = new ConcurrentHashMap<>();
    private final Map<String, Job> active = new ConcurrentHashMap<>();
    private final LinkedHashMap<String, JSONObject> history = new LinkedHashMap<>();

    AndroidTransfers(Context context, Runnable changed, AndroidPreferences configuration) {
        this.context = context.getApplicationContext(); this.changed = changed;
        this.configuration = configuration;
        preferences = new SecretStore(context, "dropsync.transfers.v1");
        directory = new File(context.getFilesDir(), "staging");
        if (!directory.isDirectory() && !directory.mkdirs()) throw new IllegalStateException("Could not create staging directory");
        load();
    }

    void stageUri(Uri uri) throws Exception {
        if (uri == null || !"content".equals(uri.getScheme())) throw new IOException("Choose a file from an Android content provider");
        String name = "Shared file";
        try (Cursor cursor = context.getContentResolver().query(uri, new String[]{OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE}, null, null, null)) {
            if (cursor != null && cursor.moveToFirst()) {
                int nameColumn = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                if (nameColumn >= 0 && !cursor.isNull(nameColumn)) name = cursor.getString(nameColumn);
                int sizeColumn = cursor.getColumnIndex(OpenableColumns.SIZE);
                if (sizeColumn >= 0 && !cursor.isNull(sizeColumn) && cursor.getLong(sizeColumn) > MAX_FILE_BYTES) throw new IOException("File exceeds the 10 GB limit");
            }
        }
        try (InputStream input = context.getContentResolver().openInputStream(uri)) {
            if (input == null) throw new IOException("The shared file could not be opened");
            stage(input, name);
        }
    }

    void stageText(String text) throws Exception {
        if (text == null || text.isEmpty()) throw new IOException("No shared file or text was supplied");
        if (text.length() > 1_000_000) throw new IOException("Shared text is too large");
        if (text.getBytes(StandardCharsets.UTF_8).length > 1024 * 1024) throw new IOException("Shared text exceeds 1 MiB");
        try (InputStream input = new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8))) { stage(input, "Shared text.txt"); }
    }

    private void stage(InputStream input, String name) throws Exception {
        synchronized (this) {
            if (stopped) throw new IOException("Sharing has stopped");
            if (staged.size() >= 100) throw new IOException("Remove some selected files before adding more");
        }
        String id = UUID.randomUUID().toString();
        File target = new File(directory, id + ".bin");
        MessageDigest hash = MessageDigest.getInstance("SHA-256"); long size = 0;
        try {
            try (OutputStream output = new BufferedOutputStream(new FileOutputStream(target))) {
                byte[] buffer = new byte[65_536]; int count;
                while ((count = input.read(buffer)) != -1) {
                    if (stopped || Thread.currentThread().isInterrupted()) throw new InterruptedIOException("File selection interrupted");
                    size += count;
                    if (size > MAX_FILE_BYTES) throw new IOException("File exceeds the 10 GB limit");
                    hash.update(buffer, 0, count); output.write(buffer, 0, count);
                }
            }
            synchronized (this) {
                if (stopped) throw new IOException("Sharing has stopped");
                staged.put(id, new Staged(id, safeName(name), size, hex(hash.digest()), target));
                saveStaged();
            }
        } catch (Exception error) { target.delete(); throw error; }
    }

    synchronized JSONArray stagedFiles() throws Exception {
        JSONArray result = new JSONArray();
        for (Staged file : staged.values()) if (file.uses == 0) result.put(file.json());
        return result;
    }

    synchronized void removeStage(String id) throws Exception {
        if (stopped) throw new IOException("Sharing has stopped");
        Staged file = staged.get(id);
        if (file != null && file.uses > 0) throw new IOException("This file is being sent");
        if (file != null) { staged.remove(id); file.path.delete(); saveStaged(); }
    }

    synchronized JSONArray send(String deviceId, String deviceName, String address, int port, String exchangeKey,
                                String selfId, Ed25519PrivateKeyParameters signingKey, JSONArray fileIds, EncryptedSender.TrustCheck trustCheck, Endpoint endpoint, String operationId) throws Exception {
        if (fileIds.length() < 1 || fileIds.length() > 100) throw new IOException("Choose at least one file");
        if (stopped) throw new IOException("Sharing has stopped");
        if (operationId != null && (fileIds.length() != 1 || !operationId.matches("[a-fA-F0-9-]{36}"))) throw new IOException("Invalid retry operation");
        List<Staged> files = new ArrayList<>(); Set<String> unique = new HashSet<>();
        for (int i = 0; i < fileIds.length(); i++) {
            String id = fileIds.getString(i); Staged file = staged.get(id);
            if (!unique.add(id) || file == null || !file.path.isFile() || file.uses != 0) throw new IOException("A selected file is unavailable or already being sent");
            files.add(file);
        }
        JSONArray result = new JSONArray();
        for (Staged file : files) {
            Job job = new Job(file, deviceId, deviceName, operationId);
            job.control.setTrustCheck(trustCheck);
            file.uses++; active.put(job.id, job); record(job, true); result.put(job.json());
            sender.execute(() -> {
                job.worker = Thread.currentThread();
                try {
                    job.control.checkpoint(); job.status = "scanning"; record(job, true);
                    NativeThreatScanner.inspect(context, configuration, file.sha256, file.path, false);
                    for (int attempt = 0; ; attempt++) {
                      job.control.checkpoint(); job.status = "sending"; job.bytes = 0; record(job, false);
                      try {
                        JSONObject destination = endpoint.resolve();
                        EncryptedSender.send(destination.getString("address"), destination.getInt("port"), file.path, file.name, file.size, file.sha256, attempt == 0 ? job.id : UUID.randomUUID().toString(), job.operationId,
                            selfId, deviceId, exchangeKey, signingKey, job.control, new EncryptedSender.Progress() {
                                private long remoteRate;
                                public void remoteLimit(long value) { remoteRate = value; }
                                public void throttle(long bytes, long started) throws Exception {
                                    long local = configuration.get().optLong("uploadLimitKBps") * 1024L;
                                    long rate = local > 0 && remoteRate > 0 ? Math.min(local, remoteRate) : Math.max(local, remoteRate);
                                    if (rate <= 0) return;
                                    long target = (long) (bytes * 1_000_000_000.0 / rate);
                                    while (System.nanoTime() - started < target) { job.control.checkpoint(); Thread.sleep(Math.min(200, Math.max(1, (target - (System.nanoTime() - started)) / 1_000_000))); }
                                }
                                public void update(long bytes) {
                                    job.bytes = bytes;
                                    long now = System.currentTimeMillis();
                                    if (now - job.lastProgress > 200) { job.lastProgress = now; record(job, false); }
                                }
                                public void awaitingApproval(boolean waiting) {
                                    if (!job.control.isCancelled()) {
                                        job.status = job.control.isPaused() ? "paused" : waiting ? "awaiting-acceptance" : "sending";
                                        record(job, false);
                                    }
                                }
                            });
                        break;
                      } catch (Exception error) {
                        boolean network = error instanceof java.net.SocketException || error instanceof java.net.SocketTimeoutException || (error instanceof EOFException && String.valueOf(error.getMessage()).contains("Peer"));
                        if (job.control.isCancelled() || !network || attempt >= configuration.get().optInt("retryAttempts", 3)) throw error;
                        job.status = "retrying"; job.retryCount = attempt + 1; job.error = "Connection interrupted. Retrying the verified file."; record(job, true);
                        long until = System.currentTimeMillis() + Math.min(30000L, 5000L << attempt);
                        while (System.currentTimeMillis() < until) { job.control.checkpoint(); Thread.sleep(250); }
                      }
                    }
                    job.error = null;
                    job.bytes = file.size; job.status = "completed";
                } catch (Exception error) {
                    job.status = job.control.isCancelled() ? "cancelled" : "failed";
                    job.error = job.control.isCancelled() ? null : error.getMessage();
                } finally {
                    job.worker = null;
                    Thread.interrupted();
                    synchronized (AndroidTransfers.this) {
                        file.uses--;
                        if (!stopped) {
                            if ("completed".equals(job.status)) { staged.remove(file.id); file.path.delete(); }
                            saveStaged(); record(job, true);
                        }
                        active.remove(job.id);
                    }
                    changed.run();
                }
            });
        }
        return result;
    }

    synchronized JSONObject control(String id, String action) throws Exception {
        Job job = active.get(id);
        if (job == null || !Arrays.asList("connecting", "sending", "paused", "awaiting-acceptance", "scanning", "retrying").contains(job.status)) throw new IOException("Active transfer not found");
        switch (action) {
            case "pause": job.control.pause(); job.status = "paused"; break;
            case "resume": job.control.resume(); job.status = "sending"; break;
            case "cancel": job.cancel(); job.status = "cancelled"; break;
            default: throw new IOException("Unsupported transfer action");
        }
        record(job, true); return job.json();
    }

    synchronized void revokeDevice(String deviceId) {
        for (Job job : active.values()) if (deviceId.equals(job.deviceId)) job.cancel();
    }

    synchronized JSONObject find(String id) throws Exception { JSONObject value = history.get(id); if (value == null) throw new IOException("Transfer not found"); return new JSONObject(value.toString()); }

    synchronized JSONArray transfers() {
        JSONArray result = new JSONArray(); List<JSONObject> values = new ArrayList<>(history.values());
        Collections.reverse(values); for (JSONObject value : values) result.put(value);
        return result;
    }

    synchronized void clearCompleted() {
        Iterator<Map.Entry<String, JSONObject>> iterator = history.entrySet().iterator();
        while (iterator.hasNext()) if ("completed".equals(iterator.next().getValue().optString("status"))) iterator.remove();
        saveHistory();
    }

    synchronized void stop() {
        if (stopped) return; stopped = true;
        for (Job job : active.values()) {
            if ("completed".equals(job.status)) continue;
            job.cancel(); job.status = "cancelled"; job.error = "Sharing was stopped";
            try { history.put(job.id, job.json()); } catch (Exception error) { throw new IllegalStateException(error); }
        }
        sender.shutdownNow(); saveHistory(); saveStaged();
    }

    private synchronized void record(Job job, boolean persist) {
        if (stopped) return;
        try {
            history.put(job.id, job.json());
            while (history.size() > 500) {
                String removable = null;
                for (String id : history.keySet()) if (!active.containsKey(id)) { removable = id; break; }
                if (removable == null) break;
                history.remove(removable);
            }
            if (persist) saveHistory();
            changed.run();
        } catch (Exception error) { throw new IllegalStateException(error); }
    }
    private void saveHistory() {
        JSONArray values = new JSONArray(); for (JSONObject value : history.values()) values.put(value);
        try { preferences.put("history", values.toString()); } catch (Exception error) { throw new IllegalStateException(error); }
    }
    private void saveStaged() {
        try {
            JSONArray values = new JSONArray(); for (Staged file : staged.values()) values.put(file.json());
            preferences.put("staged", values.toString());
        } catch (Exception error) { throw new IllegalStateException(error); }
    }
    private void load() {
        try {
            JSONArray values = new JSONArray(preferences.get("staged", "[]"));
            for (int i = 0; i < Math.min(values.length(), 100); i++) {
                JSONObject value = values.getJSONObject(i); String id = value.getString("id");
                if (!id.matches("[a-f0-9-]{36}")) continue;
                File file = new File(directory, id + ".bin");
                if (file.isFile() && file.length() == value.getLong("size")) staged.put(id,
                        new Staged(id, safeName(value.getString("name")), value.getLong("size"), value.getString("sha256"), file));
            }
            JSONArray previous = new JSONArray(preferences.get("history", "[]"));
            for (int i = Math.max(0, previous.length() - 500); i < previous.length(); i++) {
                JSONObject value = previous.getJSONObject(i);
                if (Arrays.asList("connecting", "sending", "paused", "awaiting-acceptance", "scanning", "retrying").contains(value.optString("status"))) value.put("status", "failed").put("error", "Transfer interrupted. Retry the selected file.");
                history.put(value.getString("id"), value);
            }
            Set<String> keep = new HashSet<>(); for (Staged file : staged.values()) keep.add(file.path.getName());
            File[] old = directory.listFiles();
            if (old != null) for (File file : old) if (!keep.contains(file.getName()) && file.getName().matches("[a-f0-9-]{36}\\.bin")) file.delete();
            saveHistory();
        } catch (Exception error) { throw new IllegalStateException("Could not load Android transfer history", error); }
    }
    private static String safeName(String value) {
        String name = value.replaceAll("[\\x00-\\x1f<>:\"/\\\\|?*]", "_").replaceAll("[. ]+$", "");
        return name.isEmpty() ? "Shared file" : name.substring(0, Math.min(180, name.length()));
    }
    private static String hex(byte[] bytes) { StringBuilder result = new StringBuilder(); for (byte b : bytes) result.append(String.format(Locale.ROOT, "%02x", b & 255)); return result.toString(); }
    private static String now() { SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.ROOT); format.setTimeZone(TimeZone.getTimeZone("UTC")); return format.format(new Date()); }
    private static final class Staged {
        final String id, name, sha256; final long size; final File path; int uses;
        Staged(String id, String name, long size, String sha256, File path) { this.id=id; this.name=name; this.size=size; this.sha256=sha256; this.path=path; }
        JSONObject json() throws Exception { return new JSONObject().put("id",id).put("name",name).put("size",size).put("sha256",sha256); }
    }
    private static final class Job {
        final String id = UUID.randomUUID().toString(), operationId, deviceId, deviceName, createdAt = now(); final Staged file;
        final EncryptedSender.Control control = new EncryptedSender.Control();
        volatile String status = "connecting", error; volatile long bytes, lastProgress; volatile int retryCount;
        volatile Thread worker;
        Job(Staged file, String deviceId, String deviceName, String operationId) { this.file=file; this.deviceId=deviceId; this.deviceName=deviceName; this.operationId=operationId == null ? id : operationId; }
        void cancel() { control.cancel(); Thread thread = worker; if (thread != null) thread.interrupt(); }
        JSONObject json() throws Exception { return new JSONObject().put("id",id).put("direction","send").put("deviceId",deviceId).put("deviceName",deviceName)
                .put("fileName",file.name).put("size",file.size).put("sha256",file.sha256).put("operationId", operationId).put("stagedFileId",file.id).put("bytesTransferred",bytes)
                .put("progress", "completed".equals(status) ? 100 : file.size == 0 ? 0 : Math.min(100, Math.round(bytes * 1000.0 / file.size) / 10.0))
                .put("status",status).put("retryCount", retryCount).put("error",error == null ? JSONObject.NULL : error).put("encrypted",true).put("createdAt",createdAt).put("updatedAt",now()); }
    }
}
