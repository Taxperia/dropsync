package com.dropsync.app;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.json.JSONObject;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import java.security.MessageDigest;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** DropSync transfer v2 streaming sender; no Android dependency. */
final class EncryptedSender {
    static final int CHUNK_SIZE = 256 * 1024;
    interface Progress { void update(long bytes); default void awaitingApproval(boolean waiting) { } default void remoteLimit(long bytesPerSecond) { } default void throttle(long wireBytes, long startedNanos) throws Exception { } }
    interface TrustCheck { void verify() throws Exception; }

    static final class Control {
        private boolean paused, cancelled;
        private Socket socket;
        private TrustCheck trustCheck = () -> { };
        synchronized void setTrustCheck(TrustCheck value) { trustCheck = value; }
        synchronized void pause() { paused = true; }
        synchronized void resume() { paused = false; notifyAll(); }
        synchronized void cancel() {
            cancelled = true; paused = false; notifyAll();
            try { if (socket != null) socket.close(); } catch (IOException ignored) { }
        }
        synchronized boolean isCancelled() { return cancelled; }
        synchronized boolean isPaused() { return paused; }
        synchronized void checkpoint() throws Exception {
            while (paused && !cancelled) wait();
            if (cancelled) throw new IOException("Transfer cancelled");
            trustCheck.verify();
        }
        synchronized void attach(Socket value) throws Exception { socket = value; checkpoint(); }
    }

    static void send(String host, int port, File file, String name, long size, String sha256,
                     String id, String senderId, String recipientId, String recipientExchangePem,
                     Ed25519PrivateKeyParameters signingKey, Control control, Progress progress) throws Exception {
        send(host, port, file, name, size, sha256, id, id, senderId, recipientId, recipientExchangePem, signingKey, control, progress);
    }
    static void send(String host, int port, File file, String name, long size, String sha256,
                     String id, String operationId, String senderId, String recipientId, String recipientExchangePem,
                     Ed25519PrivateKeyParameters signingKey, Control control, Progress progress) throws Exception {
        if (!file.isFile() || file.length() != size) throw new IOException("Selected file is no longer available");
        SecureRandom random = new SecureRandom();
        X25519PrivateKeyParameters ephemeral = new X25519PrivateKeyParameters(random);
        byte[] salt = new byte[32], prefix = new byte[8], secret = new byte[32];
        random.nextBytes(salt); random.nextBytes(prefix);
        byte[] peerDer = Base64.getMimeDecoder().decode(recipientExchangePem.replaceAll("-----[^-]+-----", "").replaceAll("\\s", ""));
        byte[] spki = new byte[]{0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,0x6e,0x03,0x21,0x00};
        if (peerDer.length != spki.length + 32) throw new IOException("Invalid recipient exchange key");
        for (int i = 0; i < spki.length; i++) if (peerDer[i] != spki[i]) throw new IOException("Invalid recipient exchange key");
        ephemeral.generateSecret(new X25519PublicKeyParameters(peerDer, spki.length), secret, 0);
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(secret, salt, ("DropSync transfer v1\0" + id).getBytes(StandardCharsets.UTF_8)));
        byte[] key = new byte[32]; hkdf.generateBytes(key, 0, key.length);
        byte[] ephemeralDer = new byte[spki.length + 32];
        System.arraycopy(spki, 0, ephemeralDer, 0, spki.length);
        System.arraycopy(ephemeral.generatePublicKey().getEncoded(), 0, ephemeralDer, spki.length, 32);
        String ephemeralPem = "-----BEGIN PUBLIC KEY-----\n" + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(ephemeralDer) + "\n-----END PUBLIC KEY-----\n";
        byte[] infoNonce = new byte[12]; random.nextBytes(infoNonce);
        Cipher infoCipher = Cipher.getInstance("AES/GCM/NoPadding");
        infoCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, infoNonce));
        infoCipher.updateAAD(("DropSync metadata v2\0" + id).getBytes(StandardCharsets.UTF_8));
        byte[] sealedInfo = infoCipher.doFinal(new JSONObject().put("fileName", name).put("sha256", sha256).toString().getBytes(StandardCharsets.UTF_8));
        JSONObject fileInfo = new JSONObject().put("nonce", b64(infoNonce)).put("ciphertext", b64(java.util.Arrays.copyOf(sealedInfo, sealedInfo.length - 16)))
                .put("tag", b64(java.util.Arrays.copyOfRange(sealedInfo, sealedInfo.length - 16, sealedInfo.length)));
        JSONObject meta = new JSONObject().put("version", 2).put("transferId", id).put("senderId", senderId)
                .put("operationId", operationId)
                .put("recipientId", recipientId).put("fileInfo", fileInfo).put("size", size)
                .put("timestamp", System.currentTimeMillis()).put("chunkSize", CHUNK_SIZE)
                .put("ephemeralPublicKey", ephemeralPem).put("salt", b64(salt)).put("noncePrefix", b64(prefix));
        byte[] canonical = ProtocolJson.canonical(meta).getBytes(StandardCharsets.UTF_8);
        Ed25519Signer signer = new Ed25519Signer(); signer.init(true, signingKey); signer.update(canonical, 0, canonical.length);
        long wireSize = size + ((size + CHUNK_SIZE - 1) / CHUNK_SIZE) * 24;
        JSONObject prepared = awaitApproval(host, port, meta, b64(signer.generateSignature()), control, progress);
        if ("completed".equals(prepared.optString("status"))) { verifyReceipt(prepared, key, meta, sha256); return; }
        progress.remoteLimit(Math.max(0, Math.min(1_048_576L, prepared.optLong("downloadLimitKBps"))) * 1024L);
        signer.init(true, signingKey); signer.update(canonical, 0, canonical.length);
        try (Socket socket = new Socket(); InputStream input = new BufferedInputStream(new FileInputStream(file))) {
            control.attach(socket);
            socket.connect(new InetSocketAddress(host, port), 10_000);
            socket.setSoTimeout(180_000);
            OutputStream output = new BufferedOutputStream(socket.getOutputStream());
            String headers = "POST /peer/transfers HTTP/1.1\r\nHost: " + host + ":" + port
                    + "\r\nConnection: close\r\nContent-Type: application/vnd.dropsync.encrypted-stream\r\nContent-Length: " + wireSize
                    + "\r\nX-DropSync-Meta: " + b64(meta.toString().getBytes(StandardCharsets.UTF_8))
                    + "\r\nX-DropSync-Signature: " + b64(signer.generateSignature()) + "\r\n\r\n";
            output.write(headers.getBytes(StandardCharsets.US_ASCII));
            byte[] plain = new byte[CHUNK_SIZE]; long done = 0, wireDone = 0, started = System.nanoTime(); int counter = 0;
            while (done < size) {
                control.checkpoint();
                int length = (int) Math.min(CHUNK_SIZE, size - done), offset = 0;
                while (offset < length) {
                    int count = input.read(plain, offset, length - offset);
                    if (count < 0) throw new EOFException("Selected file ended unexpectedly");
                    offset += count;
                }
                byte[] nonce = ByteBuffer.allocate(12).put(prefix).putInt(counter).array();
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
                cipher.updateAAD((id + "\0" + counter + "\0" + length).getBytes(StandardCharsets.UTF_8));
                byte[] encrypted = cipher.doFinal(plain, 0, length), frame = new byte[8 + encrypted.length];
                System.arraycopy(ByteBuffer.allocate(8).putInt(counter).putInt(length).array(), 0, frame, 0, 8); System.arraycopy(encrypted, 0, frame, 8, encrypted.length);
                for (int index = 0; index < frame.length; index += 4096) {
                    control.checkpoint(); int count = Math.min(4096, frame.length - index); wireDone += count;
                    progress.throttle(wireDone, started); output.write(frame, index, count); output.flush();
                }
                done += length; counter++; progress.update(done);
            }
            control.checkpoint();
            output.flush();
            JSONObject response = readResponse(new BufferedInputStream(socket.getInputStream()));
            verifyReceipt(response, key, meta, sha256);
            control.checkpoint();
        }
    }

    private static void verifyReceipt(JSONObject response, byte[] key, JSONObject meta, String sha256) throws Exception {
        if (!response.optBoolean("ok") || !meta.getString("transferId").equals(response.optString("transferId"))) throw new IOException("Peer did not confirm the transfer");
        JSONObject completed = new JSONObject().put("transferId", meta.getString("transferId")).put("senderId", meta.getString("senderId")).put("recipientId", meta.getString("recipientId"))
                .put("size", meta.getLong("size")).put("sha256", sha256).put("status", "completed");
        Mac mac = Mac.getInstance("HmacSHA256"); mac.init(new SecretKeySpec(key, "HmacSHA256"));
        byte[] expected = mac.doFinal(("DropSync receipt v2\0" + ProtocolJson.canonical(completed)).getBytes(StandardCharsets.UTF_8));
        if (!MessageDigest.isEqual(expected, Base64.getUrlDecoder().decode(response.optString("receipt", "")))) throw new IOException("Peer completion receipt could not be authenticated");
    }
    private static JSONObject awaitApproval(String host, int port, JSONObject meta, String signature, Control control, Progress progress) throws Exception {
        long deadline = System.currentTimeMillis() + 180_000;
        try {
            while (true) {
                control.checkpoint();
                try (Socket socket = new Socket()) {
                    control.attach(socket); socket.connect(new InetSocketAddress(host, port), 10_000); socket.setSoTimeout(180_000);
                    String request = "POST /peer/transfers/prepare HTTP/1.1\r\nHost: " + host + ":" + port
                            + "\r\nConnection: close\r\nContent-Length: 0\r\nX-DropSync-Meta: " + b64(meta.toString().getBytes(StandardCharsets.UTF_8))
                            + "\r\nX-DropSync-Signature: " + signature + "\r\n\r\n";
                    socket.getOutputStream().write(request.getBytes(StandardCharsets.US_ASCII)); socket.getOutputStream().flush();
                    JSONObject response = readResponse(new BufferedInputStream(socket.getInputStream()));
                    if ("accepted".equals(response.optString("status")) || "completed".equals(response.optString("status"))) return response;
                    if (!"pending".equals(response.optString("status")) || System.currentTimeMillis() > deadline) throw new IOException("Incoming request expired or was declined");
                    progress.awaitingApproval(true);
                }
                Thread.sleep(800);
            }
        } finally { progress.awaitingApproval(false); }
    }

    private static final class PeerHttpException extends IOException {
        final int code;
        PeerHttpException(int code, String message) { super(message); this.code = code; }
    }

    static JSONObject readResponse(InputStream input) throws Exception {
        String status = line(input);
        String[] parts = status.split(" ", 3);
        if (parts.length < 2 || !parts[0].startsWith("HTTP/1.")) throw new IOException("Invalid peer response");
        int code = Integer.parseInt(parts[1]);
        Map<String, String> headers = new HashMap<>(); int headerBytes = status.length();
        while (true) {
            String line = line(input); headerBytes += line.length() + 2;
            if (headerBytes > 32_768) throw new IOException("Peer response headers too large");
            if (line.isEmpty()) break;
            int split = line.indexOf(':');
            if (split > 0) headers.put(line.substring(0, split).trim().toLowerCase(Locale.ROOT), line.substring(split + 1).trim());
        }
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        if ("chunked".equalsIgnoreCase(headers.get("transfer-encoding"))) {
            while (true) {
                int length = Integer.parseInt(line(input).split(";", 2)[0].trim(), 16);
                if (length < 0 || length > 65_536 - body.size()) throw new IOException("Peer response too large");
                if (length == 0) break;
                body.write(exact(input, length));
                if (!line(input).isEmpty()) throw new IOException("Invalid peer response chunk");
            }
        } else if (headers.containsKey("content-length")) {
            int length = Integer.parseInt(headers.get("content-length"));
            if (length < 0 || length > 65_536) throw new IOException("Peer response too large");
            body.write(exact(input, length));
        } else {
            byte[] buffer = new byte[4096]; int count;
            while ((count = input.read(buffer)) != -1) {
                if (body.size() + count > 65_536) throw new IOException("Peer response too large");
                body.write(buffer, 0, count);
            }
        }
        JSONObject result = new JSONObject(new String(body.toByteArray(), StandardCharsets.UTF_8));
        if (code < 200 || code >= 300) throw new PeerHttpException(code, result.optString("error", "Peer rejected transfer (" + code + ")"));
        return result;
    }

    private static String b64(byte[] value) { return Base64.getUrlEncoder().withoutPadding().encodeToString(value); }
    private static String line(InputStream input) throws IOException {
        ByteArrayOutputStream result = new ByteArrayOutputStream(); int previous = -1;
        while (result.size() < 8192) {
            int current = input.read();
            if (current < 0) throw new EOFException("Peer closed the connection");
            if (previous == '\r' && current == '\n') {
                byte[] bytes = result.toByteArray();
                return new String(bytes, 0, bytes.length - 1, StandardCharsets.US_ASCII);
            }
            result.write(current); previous = current;
        }
        throw new IOException("Peer response line too large");
    }
    private static byte[] exact(InputStream input, int length) throws IOException {
        byte[] bytes = new byte[length]; int offset = 0;
        while (offset < length) {
            int count = input.read(bytes, offset, length - offset);
            if (count < 0) throw new EOFException("Peer response ended unexpectedly");
            offset += count;
        }
        return bytes;
    }
}
