package com.dropsync.app;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import java.io.*;
import java.security.KeyStore;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;

/** Non-exportable Android Keystore wrapping key; usable by the transfer service. */
final class SecretStore {
    private static final String ALIAS = "DropSync.local.v1";
    private final SharedPreferences preferences;
    SecretStore(Context context, String name) { preferences = context.getSharedPreferences(name, Context.MODE_PRIVATE); }
    private static synchronized javax.crypto.SecretKey key() throws Exception {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore"); store.load(null);
        if (!store.containsAlias(ALIAS)) {
            KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            generator.init(new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256).setUserAuthenticationRequired(false).build());
            generator.generateKey();
        }
        return (javax.crypto.SecretKey) store.getKey(ALIAS, null);
    }
    synchronized String get(String name, String fallback) throws Exception {
        String value = preferences.getString(name, null); if (value == null) return fallback;
        if (!value.startsWith("sealed:v1:")) { put(name, value); return value; }
        byte[] bytes = Base64.getDecoder().decode(value.substring(10));
        if (bytes.length < 28) throw new IOException("Invalid protected local record");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key(), new GCMParameterSpec(128, bytes, 0, 12));
        cipher.updateAAD(name.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return new String(cipher.doFinal(bytes, 12, bytes.length - 12), java.nio.charset.StandardCharsets.UTF_8);
    }
    synchronized void put(String name, String value) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding"); cipher.init(Cipher.ENCRYPT_MODE, key());
        cipher.updateAAD(name.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        byte[] encrypted = cipher.doFinal(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        byte[] bytes = new byte[12 + encrypted.length]; System.arraycopy(cipher.getIV(), 0, bytes, 0, 12); System.arraycopy(encrypted, 0, bytes, 12, encrypted.length);
        if (!preferences.edit().putString(name, "sealed:v1:" + Base64.getEncoder().encodeToString(bytes)).commit()) throw new IOException("Could not protect local record");
    }
    void remove(String name) { preferences.edit().remove(name).commit(); }
    static OutputStream encryptedOutput(File file) throws Exception {
        return new ChunkOutput(file, key());
    }
    static InputStream encryptedInput(File file) throws Exception {
        return new ChunkInput(file, key());
    }
    // Bound AEAD decryption memory even for multi-gigabyte received files. Each
    // 256 KiB chunk is authenticated before release; an authenticated empty final
    // frame detects truncation. Keystore generates every encryption IV itself.
    private static final int MAGIC = 0x44535131, CHUNK = 262144;
    private static byte[] chunkAad(int counter, int size) { return ("DropSync quarantine v1\0" + counter + "\0" + size).getBytes(java.nio.charset.StandardCharsets.UTF_8); }
    static long encryptedSize(File file) throws Exception {
        try (DataInputStream input = new DataInputStream(new BufferedInputStream(new FileInputStream(file)))) {
            if (input.readInt() != MAGIC) throw new IOException("Invalid quarantine format");
            long total = 0, remaining = file.length() - 4;
            while (remaining > 0) { int size = input.readInt(); remaining -= 4; if (size < 0 || size > CHUNK || remaining < size + 28) throw new IOException("Invalid quarantine frame"); int left = size + 28; while (left > 0) { int skipped = input.skipBytes(left); if (skipped == 0) throw new EOFException("Truncated quarantine file"); left -= skipped; } remaining -= size + 28; total += size; if (total > 100L * 1024 * 1024 * 1024) throw new IOException("Quarantine exceeds limits"); if (size == 0) { if (remaining != 0) throw new IOException("Unexpected quarantine data"); return total; } }
            throw new EOFException("Quarantine final frame is missing");
        }
    }
    private static final class ChunkOutput extends OutputStream {
        final DataOutputStream output; final javax.crypto.SecretKey secret; final byte[] buffer = new byte[CHUNK]; int used, counter; boolean closed;
        ChunkOutput(File file, javax.crypto.SecretKey secret) throws Exception { this.secret = secret; output = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(file))); output.writeInt(MAGIC); }
        private void frame(int size) throws IOException {
            try { Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding"); cipher.init(Cipher.ENCRYPT_MODE, secret); cipher.updateAAD(chunkAad(counter++, size)); byte[] bytes = cipher.doFinal(buffer, 0, size); output.writeInt(size); output.write(cipher.getIV()); output.write(bytes); }
            catch (java.security.GeneralSecurityException error) { throw new IOException("Could not protect quarantine chunk", error); }
        }
        @Override public void write(int value) throws IOException { byte[] one = {(byte) value}; write(one, 0, 1); }
        @Override public void write(byte[] bytes, int offset, int length) throws IOException { if (closed) throw new IOException("Quarantine is closed"); if (offset < 0 || length < 0 || offset > bytes.length - length) throw new IndexOutOfBoundsException(); while (length > 0) { int count = Math.min(length, CHUNK - used); System.arraycopy(bytes, offset, buffer, used, count); used += count; offset += count; length -= count; if (used == CHUNK) { frame(used); used = 0; } } }
        @Override public void flush() throws IOException { output.flush(); }
        @Override public void close() throws IOException { if (closed) return; closed = true; try { if (used > 0) frame(used); frame(0); } finally { java.util.Arrays.fill(buffer, (byte) 0); output.close(); } }
    }
    private static final class ChunkInput extends InputStream {
        final DataInputStream input; final javax.crypto.SecretKey secret; byte[] plain = new byte[0]; int position, counter; boolean finished;
        ChunkInput(File file, javax.crypto.SecretKey secret) throws Exception { this.secret = secret; input = new DataInputStream(new BufferedInputStream(new FileInputStream(file))); try { if (input.readInt() != MAGIC) throw new IOException("Invalid quarantine format"); } catch (Exception error) { input.close(); throw error; } }
        private boolean next() throws IOException {
            if (finished) return false; int size = input.readInt(); if (size < 0 || size > CHUNK) throw new IOException("Invalid quarantine chunk"); byte[] nonce = new byte[12], encrypted = new byte[size + 16]; input.readFully(nonce); input.readFully(encrypted);
            try { Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding"); cipher.init(Cipher.DECRYPT_MODE, secret, new GCMParameterSpec(128, nonce)); cipher.updateAAD(chunkAad(counter++, size)); java.util.Arrays.fill(plain, (byte) 0); plain = cipher.doFinal(encrypted); position = 0; }
            catch (java.security.GeneralSecurityException error) { throw new IOException("Quarantine authentication failed", error); }
            if (size == 0) { finished = true; if (input.read() != -1) throw new IOException("Unexpected quarantine data"); return false; } return true;
        }
        @Override public int read() throws IOException { if (position == plain.length && !next()) return -1; return plain[position++] & 255; }
        @Override public int read(byte[] bytes, int offset, int length) throws IOException { if (offset < 0 || length < 0 || offset > bytes.length - length) throw new IndexOutOfBoundsException(); if (length == 0) return 0; if (position == plain.length && !next()) return -1; int count = Math.min(length, plain.length - position); System.arraycopy(plain, position, bytes, offset, count); position += count; return count; }
        @Override public void close() throws IOException { java.util.Arrays.fill(plain, (byte) 0); finished = true; input.close(); }
    }
}
