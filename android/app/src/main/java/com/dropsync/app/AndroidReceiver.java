package com.dropsync.app;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.Uri;
import android.provider.DocumentsContract;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Authenticated v2 receiver. Decrypts into private encrypted quarantine, then SAF. */
final class AndroidReceiver {
    private final Context context;
    private final AndroidPeerService owner;
    private final Runnable changed;
    private final SecretStore records;
    private final File quarantine;
    private volatile boolean stopped;
    private final Map<String, Pending> pending = new LinkedHashMap<>();
    private final Map<String, Job> active = new ConcurrentHashMap<>();
    private final Map<String, Long> seen = new ConcurrentHashMap<>();
    private final Map<String, Lease> authorized = new LinkedHashMap<>();
    private final Map<String, Long> denied = new LinkedHashMap<>();
    private final LinkedHashMap<String, JSONObject> history = new LinkedHashMap<>();
    private static final Set<String> EXECUTABLE = new HashSet<>(Arrays.asList("exe","com","scr","msi","msp","bat","cmd","ps1","vbs","vbe","js","jse","wsf","wsh","hta","lnk","url","reg","pif","gadget","cpl","chm","scf","sct","sh","bash","zsh","py","pyw","pl","rb","desktop","appimage","app","pkg","dmg","deb","rpm","jar","apk","iso","img","docm","xlsm","pptm","xlam"));
    AndroidReceiver(Context context, AndroidPeerService owner, Runnable changed) {
        this.context = context.getApplicationContext(); this.owner = owner; this.changed = changed;
        records = new SecretStore(context, "dropsync.incoming.v1"); quarantine = new File(context.getFilesDir(), "receiving");
        if (!quarantine.isDirectory() && !quarantine.mkdirs()) throw new IllegalStateException("Cannot create receive cache");
        try {
            JSONArray values = new JSONArray(records.get("history", "[]"));
            for (int i = Math.max(0, values.length() - 500); i < values.length(); i++) {
                JSONObject value = values.getJSONObject(i);
                if (!"completed".equals(value.optString("status")) && !value.optString("publishingUri").isEmpty()) { deleteDocument(value.optString("publishingUri")); value.remove("publishingUri"); }
                if (Arrays.asList("receiving", "scanning", "publishing", "awaiting-approval", "waiting-for-sender").contains(value.optString("status"))) {
                    value.put("status", "failed").put("error", "Receiving was interrupted. Ask the sender to retry.");
                }
                history.put(value.getString("id"), value);
            }
            File[] partials = quarantine.listFiles();
            if (partials != null) for (File file : partials) if (file.getName().matches("[a-fA-F0-9-]{36}\\.part")) file.delete();
            persist();
        } catch (Exception error) { throw new IllegalStateException("Could not restore protected incoming history", error); }
    }
    private static String now() { return java.time.Instant.now().toString(); }
    private void policy(String name, long size) throws Exception {
        JSONObject settings = owner.settings();
        if (!settings.optBoolean("receivingEnabled", true)) throw new IOException("Receiving is disabled on this device");
        if (size < 0 || size > settings.getLong("maxIncomingFileBytes")) throw new IOException("File exceeds the receiving limit");
        String ext = name.contains(".") ? name.substring(name.lastIndexOf('.') + 1).toLowerCase(Locale.ROOT) : "";
        if (!settings.optBoolean("allowExecutableFiles") && EXECUTABLE.contains(ext)) throw new IOException("Installers, scripts and macro-enabled files are blocked on this device");
    }
    private Parsed parse(Map<String, String> headers) throws Exception {
        if (stopped) throw new IOException("Sharing has stopped");
        String encoded = headers.get("x-dropsync-meta"), signature = headers.get("x-dropsync-signature");
        if (encoded == null || encoded.length() > 12_000 || signature == null) throw new IOException("Missing transfer authentication");
        JSONObject wire = new JSONObject(new String(ProtocolCrypto.decode(encoded), StandardCharsets.UTF_8));
        String id = wire.getString("transferId"), senderId = wire.getString("senderId");
        if (wire.getInt("version") != 2 || !id.matches("[a-fA-F0-9-]{36}") || !wire.getString("recipientId").equals(owner.localDeviceId())) throw new IOException("Unsupported transfer or wrong recipient");
        if (wire.getInt("chunkSize") != EncryptedSender.CHUNK_SIZE || Math.abs(System.currentTimeMillis() - wire.getLong("timestamp")) > 300_000) throw new IOException("Expired or invalid transfer");
        long size = wire.getLong("size"); if (wire.getDouble("size") != (double) size) throw new IOException("Invalid file size");
        JSONObject trusted = owner.trustedIdentity(senderId);
        if (trusted == null || !owner.verifyTransfer(wire, signature, trusted)) throw new IOException("Sender is unpaired or its signature is invalid");
        byte[] key = ProtocolCrypto.transferKey(owner.exchangeKey(), wire);
        JSONObject info = ProtocolCrypto.fileInfo(key, wire); String raw = info.getString("fileName"), hash = info.getString("sha256");
        if (raw.trim().isEmpty() || raw.length() > 500 || !hash.matches("[a-f0-9]{64}")) throw new IOException("Invalid private file metadata");
        String operationId = wire.optString("operationId", id); if (!operationId.matches("[a-fA-F0-9-]{36}")) throw new IOException("Invalid operation identity");
        String name = ProtocolCrypto.safeName(raw); policy(name, size);
        return new Parsed(wire, trusted, key, name, hash, operationId);
    }
    JSONObject prepare(Map<String, String> headers) throws Exception {
        Parsed parsed = parse(headers);
        try { owner.checkThreat(parsed.hash, null); }
        catch (Exception error) { synchronized (this) { if (!stopped) { history.put(parsed.id(), base(parsed).put("status", "failed").put("error", error.getMessage())); persist(); } } changed.run(); throw error; }
        owner.assertTrusted(parsed.wire.getString("senderId"), parsed.trusted);
        return prepareParsed(parsed);
    }
    private synchronized JSONObject prepareParsed(Parsed parsed) throws Exception {
        if (stopped) throw new IOException("Sharing has stopped");
        cleanup();
        if (denied.getOrDefault(parsed.wire.getString("senderId") + ":" + parsed.operationId, 0L) > System.currentTimeMillis()) throw new IOException("Incoming transfer was declined");
        JSONObject completed = completedOperation(parsed);
        if (completed != null) return new JSONObject().put("status", "completed").put("ok", true).put("transferId", parsed.id()).put("receipt", ProtocolCrypto.receipt(parsed.key, parsed.wire, parsed.hash));
        if (seen.containsKey(parsed.id()) || active.containsKey(parsed.id())) throw new IOException("Duplicate transfer request");
        Pending item = pending.get(parsed.id());
        if (item != null && !item.canonical.equals(ProtocolJson.canonical(parsed.wire))) throw new IOException("Metadata changed after approval");
        if (item == null) {
            if (pending.size() >= 20 || seen.size() >= 5000) throw new IOException("Too many incoming requests");
            item = new Pending(parsed); pending.put(parsed.id(), item);
            Lease lease = authorized.get(parsed.wire.getString("senderId") + ":" + parsed.operationId);
            if (((lease != null && lease.matches(parsed)) || !owner.settings().optBoolean("requireIncomingApproval", true)) && !owner.receiveTree().isEmpty()) item.status = "accepted";
            recordPending(item); changed.run();
        }
        if ("accepted".equals(item.status)) {
            authorize(parsed);
            for (Job previous : active.values()) if (previous.parsed.operationId.equals(parsed.operationId) && previous.parsed.wire.optString("senderId").equals(parsed.wire.optString("senderId"))) cancel(previous);
        }
        if (Arrays.asList("rejected", "expired").contains(item.status)) throw new IOException("Incoming transfer was declined or expired");
        return new JSONObject().put("status", item.status).put("transferId", parsed.id()).put("expiresAt", item.expires).put("downloadLimitKBps", owner.settings().optLong("downloadLimitKBps"));
    }
    synchronized JSONArray requests() throws Exception {
        cleanup(); JSONArray result = new JSONArray();
        for (Pending item : pending.values()) if ("pending".equals(item.status)) result.put(new JSONObject().put("id", item.parsed.id())
                .put("deviceId", item.parsed.wire.getString("senderId")).put("deviceName", item.parsed.trusted.optString("name", "Paired device"))
                .put("deviceType", item.parsed.trusted.optString("deviceType", "desktop")).put("fileName", item.parsed.name).put("size", item.parsed.wire.getLong("size")).put("expiresAt", item.expires));
        return result;
    }
    synchronized void decide(String id, boolean accept) throws Exception {
        cleanup(); Pending item = pending.get(id);
        if (item == null || !"pending".equals(item.status)) throw new IOException("This request is no longer pending");
        owner.assertTrusted(item.parsed.wire.getString("senderId"), item.parsed.trusted);
        if (accept && owner.receiveTree().isEmpty()) throw new IOException("Choose a receiving folder before accepting");
        item.status = accept ? "accepted" : "rejected"; item.expires = System.currentTimeMillis() + (accept ? 45_000 : 90_000);
        if (accept) authorize(item.parsed); else { seen.put(id, System.currentTimeMillis()); deny(item.parsed); }
        recordPending(item); changed.run();
    }
    void receive(Map<String, String> headers, InputStream input, Socket socket) throws Exception {
        Parsed parsed = parse(headers); Pending approval; Job job;
        long size = parsed.wire.getLong("size"), wireSize = size + ((size + EncryptedSender.CHUNK_SIZE - 1) / EncryptedSender.CHUNK_SIZE) * 24;
        if (Long.parseLong(headers.getOrDefault("content-length", "-1")) != wireSize) throw new IOException("Invalid encrypted stream length");
        if (quarantine.getUsableSpace() < size + 64L * 1024 * 1024) throw new IOException("Not enough private storage to receive this file");
        synchronized (this) {
            cleanup(); approval = pending.get(parsed.id());
            if (active.size() >= owner.settings().optInt("maxConcurrentIncoming", 3)) throw new IOException("Too many simultaneous incoming transfers");
            if (approval == null || !"accepted".equals(approval.status) || !approval.canonical.equals(ProtocolJson.canonical(parsed.wire)) || seen.containsKey(parsed.id())) throw new IOException("Prepare and accept this transfer first");
            approval.status = "receiving"; seen.put(parsed.id(), System.currentTimeMillis());
            job = new Job(parsed, socket); active.put(parsed.id(), job);
        }
        File part = new File(quarantine, parsed.id() + ".part"); Uri destination = null; long received = 0, wireRead = 0; int expected = 0;
        MessageDigest hash = MessageDigest.getInstance("SHA-256"); DataInputStream stream = new DataInputStream(input);
        try {
            update(job, "receiving", null, true);
            owner.checkThreat(parsed.hash, null);
            job.started = System.nanoTime();
            byte[] prefix = ProtocolCrypto.decode(parsed.wire.getString("noncePrefix")); long checkpoint = 0;
            try (OutputStream output = SecretStore.encryptedOutput(part)) {
                while (wireRead < wireSize) {
                    owner.assertTrusted(parsed.wire.getString("senderId"), parsed.trusted); if (job.cancelled) throw new IOException("Transfer cancelled");
                    int counter = stream.readInt(), length = stream.readInt(); wireRead += 8;
                    if (counter != expected || length < 1 || length > EncryptedSender.CHUNK_SIZE || length > size - received || wireRead + length + 16 > wireSize) throw new IOException("Invalid encrypted frame sequence or size");
                    byte[] encrypted = new byte[length + 16]; stream.readFully(encrypted); wireRead += encrypted.length;
                    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding"); cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(parsed.key, "AES"), new GCMParameterSpec(128, ByteBuffer.allocate(12).put(prefix).putInt(counter).array()));
                    cipher.updateAAD((parsed.id() + "\0" + counter + "\0" + length).getBytes(StandardCharsets.UTF_8)); byte[] plain = cipher.doFinal(encrypted);
                    hash.update(plain); output.write(plain); received += plain.length; expected++; job.bytes = received;
                    owner.limitTransfer(false, plain.length, job.started);
                    if (System.currentTimeMillis() - checkpoint > 300) { checkpoint = System.currentTimeMillis(); update(job, "receiving", null, false); }
                }
            }
            if (received != size || !ProtocolCrypto.hex(hash.digest()).equals(parsed.hash)) throw new IOException("File integrity verification failed");
            owner.assertTrusted(parsed.wire.getString("senderId"), parsed.trusted); policy(parsed.name, size);
            update(job, "scanning", null, true); owner.checkThreat(parsed.hash, part);
            if (job.cancelled) throw new IOException("Transfer cancelled");
            String tree = owner.receiveTree(); if (tree.isEmpty()) throw new IOException("Receiving folder is unavailable");
            Uri parent = Uri.parse(tree), directory = DocumentsContract.buildDocumentUriUsingTree(parent, DocumentsContract.getTreeDocumentId(parent));
            destination = DocumentsContract.createDocument(context.getContentResolver(), directory, "application/octet-stream", parsed.name + ".dropsync-part");
            if (destination == null) throw new IOException("The selected folder cannot create files");
            synchronized (this) { if (stopped || job.cancelled) throw new IOException("Sharing has stopped"); job.data.put("publishingUri", destination.toString()); update(job, "publishing", null, true); }
            try (InputStream source = SecretStore.encryptedInput(part); OutputStream output = context.getContentResolver().openOutputStream(destination, "w")) {
                if (output == null) throw new IOException("Cannot write to selected folder");
                byte[] buffer = new byte[65_536]; int count;
                while ((count = source.read(buffer)) != -1) { owner.assertTrusted(parsed.wire.getString("senderId"), parsed.trusted); if (job.cancelled) throw new IOException("Transfer cancelled"); output.write(buffer, 0, count); }
            }
            owner.assertTrusted(parsed.wire.getString("senderId"), parsed.trusted); if (job.cancelled) throw new IOException("Transfer cancelled");
            policy(parsed.name, size);
            synchronized (this) {
                if (stopped || job.cancelled) throw new IOException("Transfer cancelled");
                owner.assertTrusted(parsed.wire.getString("senderId"), parsed.trusted);
                Uri renamed = DocumentsContract.renameDocument(context.getContentResolver(), destination, parsed.name);
                if (renamed == null) throw new IOException("This storage provider cannot finalize a verified file");
                destination = renamed; job.data.remove("publishingUri"); job.data.put("savedUri", renamed.toString()).put("savedPath", owner.receiveFolderLabel());
                try (android.database.Cursor cursor = context.getContentResolver().query(renamed, new String[]{android.provider.OpenableColumns.DISPLAY_NAME}, null, null, null)) { if (cursor != null && cursor.moveToFirst()) job.data.put("fileName", cursor.getString(0)); }
                update(job, "completed", null, true);
            }
            AndroidPeerService.writeResponse(socket.getOutputStream(), 201, new JSONObject().put("ok", true).put("transferId", parsed.id()).put("receipt", ProtocolCrypto.receipt(parsed.key, parsed.wire, parsed.hash)));
        } catch (Exception error) {
            if (!"completed".equals(job.data.optString("status"))) { if (destination != null) deleteDocument(destination.toString()); synchronized (this) { job.data.remove("publishingUri"); update(job, job.cancelled ? "cancelled" : "failed", error.getMessage(), true); } }
            throw error;
        } finally { part.delete(); active.remove(parsed.id()); synchronized (this) { pending.remove(parsed.id()); } changed.run(); }
    }
    synchronized JSONArray transfers() throws Exception { JSONArray result = new JSONArray(); for (JSONObject value : history.values()) result.put(new JSONObject(value.toString())); return result; }
    synchronized JSONObject file(String id) throws Exception { JSONObject value = history.get(id); if (value == null || !"completed".equals(value.optString("status")) || value.optString("savedUri").isEmpty()) throw new IOException("Received file not found"); return new JSONObject(value.toString()); }
    synchronized void revoke(String deviceId) {
        authorized.entrySet().removeIf((entry) -> entry.getKey().startsWith(deviceId + ":"));
        for (Pending item : pending.values()) if (deviceId.equals(item.parsed.wire.optString("senderId"))) { item.status = "rejected"; try { recordPending(item); } catch (Exception ignored) { } }
        for (Job job : active.values()) if (deviceId.equals(job.parsed.wire.optString("senderId"))) cancel(job);
        changed.run();
    }
    synchronized boolean cancel(String id) throws Exception {
        Job job = active.get(id); if (job != null) { deny(job.parsed); cancel(job); return true; }
        Pending item = pending.get(id); if (item == null) return false; deny(item.parsed); item.status = "rejected"; recordPending(item); changed.run(); return true;
    }
    private void cancel(Job job) { job.cancelled = true; job.worker.interrupt(); try { job.socket.close(); } catch (IOException ignored) { } }
    synchronized void stop() {
        if (stopped) return; stopped = true;
        try {
            for (Job job : active.values()) if (!"completed".equals(job.data.optString("status"))) { cancel(job); job.data.put("status", "failed").put("error", "Sharing stopped. Ask the sender to retry."); history.put(job.parsed.id(), new JSONObject(job.data.toString())); }
            for (Pending item : pending.values()) if (!active.containsKey(item.parsed.id())) history.put(item.parsed.id(), base(item.parsed).put("status", "rejected").put("error", "Sharing stopped"));
            pending.clear(); authorized.clear(); persist();
        } catch (Exception error) { throw new IllegalStateException("Could not persist stopped receiving jobs", error); }
    }
    synchronized void cleanup() {
        long now = System.currentTimeMillis();
        Iterator<Map.Entry<String, Pending>> iterator = pending.entrySet().iterator();
        while (iterator.hasNext()) {
            Pending item = iterator.next().getValue();
            if (now > item.expires && !"receiving".equals(item.status)) { item.status = "expired"; seen.put(item.parsed.id(), now); try { recordPending(item); } catch (Exception ignored) { } iterator.remove(); changed.run(); }
        }
        seen.entrySet().removeIf((entry) -> now - entry.getValue() > 600_000);
        authorized.entrySet().removeIf((entry) -> entry.getValue().expires < now);
        denied.entrySet().removeIf((entry) -> entry.getValue() < now);
    }
    private synchronized void authorize(Parsed parsed) throws Exception {
        String key = parsed.wire.getString("senderId") + ":" + parsed.operationId;
        if (authorized.containsKey(key) && authorized.get(key).matches(parsed)) return;
        if (authorized.size() >= 500) authorized.remove(authorized.keySet().iterator().next());
        authorized.put(key, new Lease(parsed));
    }
    private synchronized void deny(Parsed parsed) {
        String key = parsed.wire.optString("senderId") + ":" + parsed.operationId; authorized.remove(key);
        if (denied.size() >= 500) denied.remove(denied.keySet().iterator().next()); denied.put(key, System.currentTimeMillis() + 900_000);
    }
    private synchronized JSONObject completedOperation(Parsed parsed) throws Exception {
        for (JSONObject value : history.values()) if ("completed".equals(value.optString("status")) && parsed.operationId.equals(value.optString("operationId")) && parsed.wire.getString("senderId").equals(value.optString("deviceId"))) {
            if (value.optLong("size") != parsed.wire.getLong("size") || !parsed.hash.equals(value.optString("sha256")) || !parsed.name.equals(value.optString("requestedName", parsed.name))) throw new IOException("Operation metadata changed"); return value;
        }
        return null;
    }
    private synchronized void recordPending(Pending item) throws Exception {
        if (stopped) return;
        JSONObject value = base(item.parsed).put("status", "pending".equals(item.status) ? "awaiting-approval" : "accepted".equals(item.status) ? "waiting-for-sender" : "rejected");
        history.put(item.parsed.id(), value); persist();
    }
    private synchronized void update(Job job, String status, String error, boolean persist) throws Exception {
        if (stopped) return;
        job.data.put("status", status).put("error", error == null ? JSONObject.NULL : error).put("bytesTransferred", job.bytes).put("updatedAt", now())
                .put("progress", "completed".equals(status) ? 100 : job.parsed.wire.optLong("size") == 0 ? 0 : Math.min(100, job.bytes * 100.0 / job.parsed.wire.getLong("size")));
        history.put(job.parsed.id(), new JSONObject(job.data.toString())); if (persist) persist(); changed.run();
    }
    private static JSONObject base(Parsed parsed) throws Exception { return new JSONObject().put("id", parsed.id()).put("operationId", parsed.operationId).put("direction", "receive")
            .put("deviceId", parsed.wire.getString("senderId")).put("deviceName", parsed.trusted.optString("name", "Paired device")).put("fileName", parsed.name)
            .put("size", parsed.wire.getLong("size")).put("sha256", parsed.hash).put("requestedName", parsed.name).put("bytesTransferred", 0).put("progress", 0).put("encrypted", true).put("createdAt", now()).put("updatedAt", now()); }
    private synchronized void persist() throws Exception {
        while (history.size() > 500) { String removable = null; for (String id : history.keySet()) if (!active.containsKey(id) && !pending.containsKey(id)) { removable = id; break; } if (removable == null) break; history.remove(removable); }
        records.put("history", transfers().toString());
    }
    private void deleteDocument(String value) { if (value == null || value.isEmpty()) return; try { DocumentsContract.deleteDocument(context.getContentResolver(), Uri.parse(value)); } catch (Exception ignored) { } }
    private static final class Parsed {
        final JSONObject wire, trusted; final byte[] key; final String name, hash, operationId;
        Parsed(JSONObject wire, JSONObject trusted, byte[] key, String name, String hash, String operationId) { this.wire=wire; this.trusted=trusted; this.key=key; this.name=name; this.hash=hash; this.operationId=operationId; }
        String id() { return wire.optString("transferId"); }
    }
    private static final class Pending {
        final Parsed parsed; final String canonical; long expires = System.currentTimeMillis() + 90_000; String status = "pending";
        Pending(Parsed parsed) throws Exception { this.parsed=parsed; canonical=ProtocolJson.canonical(parsed.wire); }
    }
    private static final class Job {
        final Parsed parsed; final Socket socket; final JSONObject data; final Thread worker = Thread.currentThread(); volatile long started=System.nanoTime(); volatile boolean cancelled; volatile long bytes;
        Job(Parsed parsed, Socket socket) throws Exception { this.parsed=parsed; this.socket=socket; data=base(parsed); }
    }
    private static final class Lease {
        final Parsed original; final long expires = System.currentTimeMillis() + 900_000;
        Lease(Parsed original) { this.original=original; }
        boolean matches(Parsed other) { return expires > System.currentTimeMillis() && original.hash.equals(other.hash) && original.name.equals(other.name) && original.wire.optLong("size") == other.wire.optLong("size"); }
    }
}
