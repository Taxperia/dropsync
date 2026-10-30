package com.dropsync.app;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.webkit.WebView;
import org.json.JSONObject;
import java.io.File;
import java.io.FileOutputStream;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/** End-to-end APK share → content URI → pairing → real encrypted transfer smoke. */
public final class ShareSmoke extends Instrumentation {
    private Bundle arguments;
    public void onCreate(Bundle arguments) { super.onCreate(arguments); this.arguments = arguments; start(); }
    public void onStart() {
        Bundle result = new Bundle();
        if (arguments != null && "true".equals(arguments.getString("storage-only"))) {
            try { StorageChecks.run(getTargetContext()); result.putString("stream", "Keystore preferences and bounded quarantine authentication passed."); finish(Activity.RESULT_OK, result); }
            catch (Throwable error) { result.putString("stream", android.util.Log.getStackTraceString(error)); finish(Activity.RESULT_CANCELED, result); }
            return;
        }
        try { smoke(); result.putString("stream", "APK cold/warm shares, native staging, pairing and encrypted sending passed."); finish(Activity.RESULT_OK, result); }
        catch (Throwable error) { result.putString("stream", android.util.Log.getStackTraceString(error)); finish(Activity.RESULT_CANCELED, result); }
    }
    private void smoke() throws Exception {
        ActivityMonitor monitor = addMonitor("com.dropsync.app.MainActivity", null, false);
        getTargetContext().startActivity(sourceIntent(false));
        MainActivity activity = (MainActivity) monitor.waitForActivityWithTimeout(15_000);
        if (activity == null) throw new AssertionError("The shared file did not open DropSync");
        removeMonitor(monitor);
        Field peerField = MainActivity.class.getDeclaredField("peerService"); peerField.setAccessible(true);
        AndroidPeerService peer = (AndroidPeerService) peerField.get(activity);
        Field webField = MainActivity.class.getDeclaredField("webView"); webField.setAccessible(true);
        WebView web = (WebView) webField.get(activity);
        waitUntil(() -> new JSONObject(peer.request("/api/bootstrap", "GET", "")).getJSONArray("stagedFiles").length() == 1);
        JSONObject found = response(peer.request("/api/devices/manual", "POST", new JSONObject().put("address", arguments.getString("address")).toString()));
        String id = found.getJSONObject("device").getString("deviceId");
        response(peer.request("/api/pair", "POST", new JSONObject().put("deviceId", id).put("code", arguments.getString("code")).toString()));
        waitUntil(() -> "true".equals(js(web, "typeof runtimeState !== 'undefined' && realRuntimeActive")));
        js(web, "localStorage.setItem('dropsync.onboarded.v1','true'); for(let i=0;i<3;i++) document.querySelector('#onboardNext')?.click(); location.hash='#dashboard'; window.dispatchEvent(new Event('dropsync-native-devices'));");
        waitUntil(() -> "true".equals(js(web, "document.querySelectorAll('#sendDeviceList .send-device').length === 1")));
        js(web, "openSend({}); document.querySelector('#sendContinue').click(); document.querySelector('#startTransfer').click();");
        waitUntil(() -> completed(peer) == 1);
        getTargetContext().startActivity(sourceIntent(true));
        waitUntil(() -> response(peer.request("/api/bootstrap", "GET", "")).getJSONArray("stagedFiles").length() == 2);
        waitUntil(() -> "true".equals(js(web, "document.querySelectorAll('#pickedList li').length === 2")));
        // Emulator NAT does not relay LAN announcements; refresh the manually
        // discovered peer and wait for native staging to enable the buttons.
        response(peer.request("/api/devices/manual", "POST", new JSONObject().put("address", arguments.getString("address")).toString()));
        js(web, "window.dispatchEvent(new Event('dropsync-native-devices'));");
        waitUntil(() -> "true".equals(js(web, "!document.querySelector('#sendContinue').disabled && document.querySelectorAll('#sendDeviceList .send-device').length === 1")));
        if (completed(peer) != 1) throw new AssertionError("Shared files must wait for confirmation");
        js(web, "document.querySelector('#sendContinue').click(); document.querySelector('#startTransfer').click();");
        waitUntil(() -> completed(peer) == 3);
        // Exercise the native document-picker result handler with a granted URI.
        // The system picker UI itself is not automated by this test.
        Field callback = MainActivity.class.getDeclaredField("fileCallback"); callback.setAccessible(true);
        boolean[] released = {false};
        callback.set(activity, (android.webkit.ValueCallback<Uri[]>) values -> { released[0] = values == null; });
        runOnMainSync(() -> activity.onActivityResult(42, Activity.RESULT_OK,
                new Intent().setData(Uri.parse("content://com.dropsync.app.test.files/smoke-single.bin"))));
        waitUntil(() -> response(peer.request("/api/bootstrap", "GET", "")).getJSONArray("stagedFiles").length() == 1);
        if (!released[0]) throw new AssertionError("Native picker must release its WebView callback");
        waitUntil(() -> "true".equals(js(web, "document.querySelectorAll('#pickedList li').length === 1")));
        response(peer.request("/api/devices/manual", "POST", new JSONObject().put("address", arguments.getString("address")).toString()));
        js(web, "window.dispatchEvent(new Event('dropsync-native-devices'));");
        waitUntil(() -> "true".equals(js(web, "!document.querySelector('#sendContinue').disabled && document.querySelectorAll('#sendDeviceList .send-device').length === 1")));
        js(web, "document.querySelector('#sendContinue').click(); document.querySelector('#startTransfer').click();");
        waitUntil(() -> completed(peer) == 4);
        android.graphics.Bitmap screenshot = getUiAutomation().takeScreenshot();
        if (screenshot != null) {
            try (FileOutputStream output = new FileOutputStream(new File(getTargetContext().getFilesDir(), "smoke-screen.png"))) {
                screenshot.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, output);
            } finally { screenshot.recycle(); }
        }
    }
    private int completed(AndroidPeerService peer) throws Exception {
        org.json.JSONArray list = response(peer.request("/api/transfers", "GET", "")).getJSONArray("transfers"); int result = 0;
        for (int i = 0; i < list.length(); i++) if ("completed".equals(list.getJSONObject(i).getString("status"))) result++;
        return result;
    }
    private Intent sourceIntent(boolean multiple) {
        return new Intent().setClassName("com.dropsync.app.test", "com.dropsync.app.ShareSmokeSourceActivity")
                .putExtra("multiple", multiple).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
    }
    private static JSONObject response(String encoded) throws Exception { JSONObject value = new JSONObject(encoded); if (value.has("__error")) throw new AssertionError(value.getString("__error")); return value; }
    private interface Condition { boolean ready() throws Exception; }
    private void waitUntil(Condition condition) throws Exception {
        long end = System.currentTimeMillis() + 30_000;
        while (System.currentTimeMillis() < end) { if (condition.ready()) return; Thread.sleep(150); }
        throw new AssertionError("Timed out waiting for Android share/transfer state");
    }
    private String js(WebView web, String script) throws Exception {
        CountDownLatch done = new CountDownLatch(1); String[] result = {null};
        runOnMainSync(() -> web.evaluateJavascript(script, value -> { result[0] = value; done.countDown(); }));
        if (!done.await(10, TimeUnit.SECONDS)) throw new AssertionError("WebView callback timed out");
        return result[0];
    }
}
