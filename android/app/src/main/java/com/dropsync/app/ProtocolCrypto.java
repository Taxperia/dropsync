package com.dropsync.app;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.json.JSONObject;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.io.IOException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

final class ProtocolCrypto {
    static byte[] decode(String value) { return Base64.getUrlDecoder().decode(value); }
    static byte[] transferKey(X25519PrivateKeyParameters privateKey, JSONObject meta) throws Exception {
        byte[] der = Base64.getMimeDecoder().decode(meta.getString("ephemeralPublicKey").replaceAll("-----[^-]+-----", "").replaceAll("\\s", ""));
        byte[] prefix = new byte[]{0x30,0x2a,0x30,0x05,0x06,0x03,0x2b,0x65,0x6e,0x03,0x21,0x00};
        if (der.length != 44 || !Arrays.equals(prefix, Arrays.copyOf(der, 12))) throw new IOException("Invalid exchange key");
        byte[] salt = decode(meta.getString("salt")), secret = new byte[32], key = new byte[32];
        if (salt.length != 32 || decode(meta.getString("noncePrefix")).length != 8) throw new IOException("Invalid encryption parameters");
        privateKey.generateSecret(new X25519PublicKeyParameters(der, 12), secret, 0);
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(secret, salt, ("DropSync transfer v1\0" + meta.getString("transferId")).getBytes(StandardCharsets.UTF_8))); hkdf.generateBytes(key, 0, 32);
        Arrays.fill(secret, (byte) 0); return key;
    }
    static JSONObject fileInfo(byte[] key, JSONObject meta) throws Exception {
        JSONObject sealed = meta.getJSONObject("fileInfo"); byte[] nonce = decode(sealed.getString("nonce")), tag = decode(sealed.getString("tag")), encrypted = decode(sealed.getString("ciphertext"));
        if (nonce.length != 12 || tag.length != 16 || encrypted.length > 4096) throw new IOException("Invalid private metadata");
        byte[] body = Arrays.copyOf(encrypted, encrypted.length + 16); System.arraycopy(tag, 0, body, encrypted.length, 16);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding"); cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        cipher.updateAAD(("DropSync metadata v2\0" + meta.getString("transferId")).getBytes(StandardCharsets.UTF_8));
        return new JSONObject(new String(cipher.doFinal(body), StandardCharsets.UTF_8));
    }
    static String receipt(byte[] key, JSONObject meta, String hash) throws Exception {
        JSONObject data = new JSONObject().put("transferId", meta.getString("transferId")).put("senderId", meta.getString("senderId"))
                .put("recipientId", meta.getString("recipientId")).put("size", meta.getLong("size")).put("sha256", hash).put("status", "completed");
        Mac mac = Mac.getInstance("HmacSHA256"); mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(("DropSync receipt v2\0" + ProtocolJson.canonical(data)).getBytes(StandardCharsets.UTF_8)));
    }
    static String hex(byte[] bytes) { StringBuilder result = new StringBuilder(); for (byte b : bytes) result.append(String.format(Locale.ROOT, "%02x", b & 255)); return result.toString(); }
    static String safeName(String value) {
        String name = value.replaceAll("[\\x00-\\x1f\\x7f\\u202a-\\u202e\\u2066-\\u2069<>:\"/\\\\|?*]", "_").replaceAll("[. ]+$", "");
        if (name.isEmpty()) return "Shared file";
        name = name.substring(0, Math.min(180, name.length()));
        return name.matches("(?i)^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\\..*)?$") ? "_" + name : name;
    }
}
