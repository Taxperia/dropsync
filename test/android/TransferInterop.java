package com.dropsync.app;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.json.JSONObject;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

/** Calls the exact sender shipped in the APK against the Node receiver. */
public final class TransferInterop {
    public static void main(String[] args) throws Exception {
        JSONObject fixture = new JSONObject(Files.readString(Path.of(args[0])));
        long[] progress = {0};
        EncryptedSender.Control control = new EncryptedSender.Control();
        if (fixture.optBoolean("pauseFirst")) {
            control.pause();
            new Thread(() -> { try { Thread.sleep(150); control.resume(); } catch (Exception ignored) { } }).start();
        }
        try {
            EncryptedSender.send("127.0.0.1", fixture.getInt("port"), new File(fixture.getString("file")),
                    fixture.getString("name"), fixture.getLong("size"), fixture.getString("sha256"),
                    fixture.getString("id"), fixture.getString("senderId"), fixture.getString("recipientId"),
                    fixture.getString("exchangeKey"), new Ed25519PrivateKeyParameters(Base64.getUrlDecoder().decode(fixture.getString("seed")), 0),
                    control, bytes -> progress[0] = bytes);
            System.out.println(new JSONObject().put("ok", true).put("bytes", progress[0]));
        } catch (Exception error) { System.out.println(new JSONObject().put("ok", false).put("error", error.getMessage())); }
    }
}
