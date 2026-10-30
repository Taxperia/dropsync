package com.dropsync.app;

import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/** Runs the production encoder with Android's real org.json sources on the host JVM. */
public final class ProtocolInterop {
    public static void main(String[] args) throws Exception {
        JSONObject fixture = new JSONObject(Files.readString(Path.of(args[0])));
        if (!JSONObject.quote("/").contains("\\/")) throw new AssertionError("Expected Android org.json slash escaping");
        JSONArray cases = fixture.getJSONArray("cases");
        for (int i = 0; i < cases.length(); i++) {
            JSONObject item = cases.getJSONObject(i);
            if (!item.getString("expected").equals(ProtocolJson.canonical(item.get("value")))) {
                throw new AssertionError("Java/Node canonical byte mismatch in case " + i);
            }
        }
        JSONObject data = fixture.getJSONObject("data");
        String canonical = ProtocolJson.canonical(data);
        KeyFactory keys = KeyFactory.getInstance("Ed25519");
        byte[] publicDer = pem(data.getString("signingPublicKey"));
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(keys.generatePublic(new X509EncodedKeySpec(publicDer)));
        verifier.update(canonical.getBytes(StandardCharsets.UTF_8));
        if (!verifier.verify(Base64.getUrlDecoder().decode(fixture.getString("nodeSignature")))) {
            throw new AssertionError("Android cannot verify Node announcement");
        }
        // Reproduce the old Android encoding and prove why it rejected this packet.
        verifier.initVerify(keys.generatePublic(new X509EncodedKeySpec(publicDer)));
        verifier.update(canonical.replace("/", "\\/").getBytes(StandardCharsets.UTF_8));
        if (verifier.verify(Base64.getUrlDecoder().decode(fixture.getString("nodeSignature")))) {
            throw new AssertionError("Fixture must reproduce the old signature failure");
        }
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(keys.generatePrivate(new PKCS8EncodedKeySpec(pem(fixture.getString("privateKey")))));
        signer.update(canonical.getBytes(StandardCharsets.UTF_8));
        System.out.println(new JSONObject().put("type", "dropsync-announce").put("data", data)
                .put("signature", Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign())));
    }

    private static byte[] pem(String value) {
        return Base64.getDecoder().decode(value.replaceAll("-----[^-]+-----", "").replaceAll("\\s", ""));
    }
}
