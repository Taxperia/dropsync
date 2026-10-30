package com.dropsync.app;

import android.content.Context;
import java.io.*;
import java.util.Arrays;
import java.util.UUID;

/** Storage-only instrumentation: dummy data, dedicated preferences, app-cache files. */
final class StorageChecks {
    static void run(Context context) throws Exception {
        String namespace = "dropsync.storage.fixture." + UUID.randomUUID();
        var raw = context.getSharedPreferences(namespace, 0);
        File file = new File(context.getCacheDir(), "quarantine-fixture-" + UUID.randomUUID() + ".part");
        try {
            SecretStore store = new SecretStore(context, namespace);
            store.put("fixture", "dummy-private-record");
            String protectedValue = raw.getString("fixture", "");
            if (!protectedValue.startsWith("sealed:v1:") || protectedValue.contains("dummy-private-record") || !"dummy-private-record".equals(store.get("fixture", ""))) throw new AssertionError("Preference protection failed");
            raw.edit().putString("fixture", "sealed:v1:AAAA").commit();
            boolean rejected = false; try { store.get("fixture", ""); } catch (Exception expected) { rejected = true; }
            if (!rejected) throw new AssertionError("Corrupt record was accepted");
            for (int size : new int[]{0, 1, 262144, 524319}) {
                byte[] source = new byte[size]; for (int i=0;i<size;i++) source[i] = (byte) (i * 31);
                try (OutputStream output = SecretStore.encryptedOutput(file)) { for (int offset=0;offset<size;) { int count = Math.min(7777, size-offset); output.write(source, offset, count); offset += count; } }
                if (SecretStore.encryptedSize(file) != size || !Arrays.equals(source, read(file))) throw new AssertionError("Quarantine round trip changed content");
                try (RandomAccessFile changed = new RandomAccessFile(file, "rw")) { changed.seek(20); int value = changed.read(); changed.seek(20); changed.write(value ^ 1); }
                rejected = false; try { read(file); } catch (Exception expected) { rejected = true; }
                if (!rejected) throw new AssertionError("Tampered quarantine was accepted");
                try (OutputStream output = SecretStore.encryptedOutput(file)) { output.write(source); }
                try (RandomAccessFile changed = new RandomAccessFile(file, "rw")) { changed.setLength(changed.length() - 1); }
                rejected = false; try { read(file); } catch (Exception expected) { rejected = true; }
                if (!rejected) throw new AssertionError("Truncated quarantine was accepted");
            }
        } finally { file.delete(); raw.edit().clear().commit(); }
    }
    private static byte[] read(File file) throws Exception {
        try (InputStream input = SecretStore.encryptedInput(file); ByteArrayOutputStream output = new ByteArrayOutputStream()) { byte[] buffer = new byte[8192]; int count; while ((count = input.read(buffer)) != -1) output.write(buffer, 0, count); return output.toByteArray(); }
    }
}
