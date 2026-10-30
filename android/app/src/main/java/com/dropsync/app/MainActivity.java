package com.dropsync.app;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.webkit.JavascriptInterface;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import org.json.JSONObject;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.ArrayList;
import java.util.List;
import java.util.LinkedHashSet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import android.content.ClipData;
import android.os.Parcelable;
import android.widget.Toast;

public final class MainActivity extends Activity {
    private static final int FILE_CHOOSER_REQUEST = 42;
    private static final int RECEIVE_FOLDER_REQUEST = 43;
    private WebView webView;
    private ValueCallback<Uri[]> fileCallback;
    private boolean pickerActive;
    private Uri pendingAuth;
    private AndroidPeerService peerService;
    private AppUpdates appUpdates;
    private final Runnable nativeChanged = () -> {
        if (!destroyed && webView != null) webView.post(() -> { if (!destroyed) webView.evaluateJavascript("window.dispatchEvent(new Event('dropsync-native-devices'))", null); });
    };
    private final android.os.Handler updateHandler = new android.os.Handler(android.os.Looper.getMainLooper());
    private final Runnable automaticUpdateCheck = new Runnable() {
        @Override public void run() {
            if (destroyed) return;
            if (appUpdates != null && appUpdates.automatic()) requests.execute(() -> appUpdates.request("/api/updates/check", "POST", "{}"));
            updateHandler.postDelayed(this, 6 * 60 * 60_000L);
        }
    };
    private final ExecutorService imports = Executors.newSingleThreadExecutor();
    private final ExecutorService requests = Executors.newFixedThreadPool(3);
    private volatile boolean destroyed;
    private static final String ASSET_ORIGIN = "https://appassets.androidplatform.net";
    private static final Set<String> ASSETS = new HashSet<>(Arrays.asList("index.html", "styles.css", "app.js", "runtime.js", "updates-ui.js", "project-info.js", "feature-settings.js", "workspace-features.js", "product.js", "auth.js", "auth-config.js", "welcome.html", "welcome.css", "welcome.js"));

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        getWindow().setStatusBarColor(Color.rgb(13, 14, 17));
        getWindow().setNavigationBarColor(Color.rgb(13, 14, 17));

        webView = new WebView(this);
        webView.setBackgroundColor(Color.rgb(19, 20, 24));
        setContentView(webView);
        try { appUpdates = new AppUpdates(this); } catch (Exception ignored) { /* visible unavailable state in update settings */ }
        updateHandler.postDelayed(automaticUpdateCheck, 30_000);

        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setCacheMode(WebSettings.LOAD_NO_CACHE);
        settings.setAllowFileAccess(false);
        settings.setAllowContentAccess(true);
        settings.setAllowFileAccessFromFileURLs(false);
        settings.setAllowUniversalAccessFromFileURLs(false);
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        settings.setMediaPlaybackRequiresUserGesture(true);
        settings.setBuiltInZoomControls(false);
        settings.setDisplayZoomControls(false);
        settings.setUserAgentString(settings.getUserAgentString() + " DropSyncAndroid/0.7.0");

        peerService = DropSyncRuntime.peer(this); DropSyncRuntime.add(nativeChanged); DropSyncService.start(this);
        if (android.os.Build.VERSION.SDK_INT >= 33 && checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED) requestPermissions(new String[]{android.Manifest.permission.POST_NOTIFICATIONS}, 44);

        webView.addJavascriptInterface(new AndroidBridge(), "DropSyncAndroid");
        webView.setWebViewClient(new WebViewClient() {
            @Override
            public WebResourceResponse shouldInterceptRequest(WebView view, WebResourceRequest request) {
                Uri uri = request.getUrl();
                if (!"appassets.androidplatform.net".equals(uri.getHost())) return null;
                String name = uri.getPath() == null ? "" : uri.getPath().replaceFirst("^/", "");
                if (!ASSETS.contains(name)) return new WebResourceResponse("text/plain", "UTF-8", 404, "Not Found", null, new ByteArrayInputStream(new byte[0]));
                try {
                    String mime = name.endsWith(".js") ? "application/javascript" : name.endsWith(".css") ? "text/css" : "text/html";
                    return new WebResourceResponse(mime, "UTF-8", getAssets().open("www/" + name));
                } catch (java.io.IOException error) {
                    return new WebResourceResponse("text/plain", "UTF-8", 404, "Not Found", null, new ByteArrayInputStream(new byte[0]));
                }
            }
            @Override
            public void onPageFinished(WebView view, String url) {
                deliverAuth();
            }
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                Uri uri = request.getUrl();
                boolean internal = "https".equals(uri.getScheme()) && "appassets.androidplatform.net".equals(uri.getHost());
                if (internal && ("/".equals(uri.getPath()) || "/welcome.html".equals(uri.getPath()))) {
                    view.loadUrl(ASSET_ORIGIN + "/index.html#account");
                    return true;
                }
                return !internal;
            }
        });
        webView.setWebChromeClient(new WebChromeClient() {
            @Override
            public boolean onShowFileChooser(
                    WebView view,
                    ValueCallback<Uri[]> callback,
                    FileChooserParams params
            ) {
                if (fileCallback != null) fileCallback.onReceiveValue(null);
                fileCallback = callback;

                Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
                intent.addCategory(Intent.CATEGORY_OPENABLE);
                intent.setType("*/*");
                intent.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, params.getMode() == FileChooserParams.MODE_OPEN_MULTIPLE);
                try { pickerActive = true; startActivityForResult(intent, FILE_CHOOSER_REQUEST); }
                catch (RuntimeException error) { pickerActive = false; fileCallback.onReceiveValue(null); fileCallback = null; Toast.makeText(MainActivity.this, "No file picker is available", Toast.LENGTH_LONG).show(); }
                return true;
            }
        });

        // A new activity has no in-memory account session. Start at entry;
        // product.js shows the introduction only until it has been completed.
        webView.loadUrl(ASSET_ORIGIN + "/index.html#dashboard");
        pendingAuth = getIntent().getData();
        if (savedInstanceState == null || !savedInstanceState.getBoolean("shareHandled")) acceptShare(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        pendingAuth = intent.getData();
        deliverAuth();
        acceptShare(intent);
    }

    @Override
    protected void onSaveInstanceState(Bundle state) {
        state.putBoolean("shareHandled", true);
        super.onSaveInstanceState(state);
    }

    private void acceptShare(Intent intent) {
        if (!Intent.ACTION_SEND.equals(intent.getAction()) && !Intent.ACTION_SEND_MULTIPLE.equals(intent.getAction())) return;
        try {
            LinkedHashSet<Uri> uris = new LinkedHashSet<>();
            if (Intent.ACTION_SEND_MULTIPLE.equals(intent.getAction())) {
                ArrayList<Parcelable> streams = intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM);
                if (streams != null) for (Parcelable stream : streams) {
                    if (!(stream instanceof Uri)) throw new IllegalArgumentException("Invalid shared file");
                    uris.add((Uri) stream);
                }
            } else {
                Parcelable stream = intent.getParcelableExtra(Intent.EXTRA_STREAM);
                if (stream != null && !(stream instanceof Uri)) throw new IllegalArgumentException("Invalid shared file");
                if (stream != null) uris.add((Uri) stream);
            }
            ClipData clip = intent.getClipData();
            if (clip != null) for (int i = 0; i < clip.getItemCount(); i++) {
                Uri uri = clip.getItemAt(i).getUri(); if (uri != null) uris.add(uri);
            }
            CharSequence text = intent.getCharSequenceExtra(Intent.EXTRA_TEXT);
            if (text == null && clip != null && clip.getItemCount() > 0) text = clip.getItemAt(0).getText();
            submitImport(new ArrayList<>(uris), text == null ? null : text.toString());
        } catch (RuntimeException error) { Toast.makeText(this, "Could not open shared content: " + error.getMessage(), Toast.LENGTH_LONG).show(); }
    }

    private void submitImport(List<Uri> uris, String text) {
        if (uris.size() > 100) { Toast.makeText(this, "Share up to 100 files at a time", Toast.LENGTH_LONG).show(); return; }
        if (uris.isEmpty() && (text == null || text.isEmpty())) return;
        for (Uri uri : uris) if (!"content".equals(uri.getScheme())) {
            Toast.makeText(this, "Choose files through an Android content provider", Toast.LENGTH_LONG).show(); return;
        }
        Toast.makeText(this, "Preparing selected files…", Toast.LENGTH_SHORT).show();
        peerService.beginImport();
        imports.execute(() -> peerService.importFiles(uris, text));
    }

    private void deliverAuth() {
        if (pendingAuth == null || webView == null) return;
        if (!"dropsync".equals(pendingAuth.getScheme()) || !"auth".equals(pendingAuth.getHost()) || !"/callback".equals(pendingAuth.getPath())) { pendingAuth = null; return; }
        String code = pendingAuth.getQueryParameter("code");
        String error = pendingAuth.getQueryParameter("error_description");
        webView.evaluateJavascript("typeof window.completeDropSyncAuth === 'function'", ready -> {
            if (!"true".equals(ready)) return;
            pendingAuth = null;
            webView.evaluateJavascript("window.completeDropSyncAuth(" + JSONObject.quote(code == null ? "" : code) + "," + JSONObject.quote(error == null ? "" : error) + ")", null);
        });
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == RECEIVE_FOLDER_REQUEST || requestCode == FILE_CHOOSER_REQUEST) pickerActive = false;
        if (requestCode == RECEIVE_FOLDER_REQUEST) {
            if (resultCode == RESULT_OK && data != null && data.getData() != null) {
                Uri uri = data.getData();
                try {
                    getContentResolver().takePersistableUriPermission(uri, data.getFlags() & (Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION));
                    String label = android.provider.DocumentsContract.getTreeDocumentId(uri);
                    peerService.selectReceiveTree(uri, label); nativeChanged.run();
                } catch (Exception error) { Toast.makeText(this, "Could not use this folder: " + error.getMessage(), Toast.LENGTH_LONG).show(); }
            }
            return;
        }
        if (requestCode != FILE_CHOOSER_REQUEST || fileCallback == null) return;

        Uri[] result = null;
        if (resultCode == RESULT_OK && data != null) {
            if (data.getClipData() != null) {
                int count = data.getClipData().getItemCount();
                result = new Uri[count];
                for (int index = 0; index < count; index += 1) {
                    result[index] = data.getClipData().getItemAt(index).getUri();
                }
            } else if (data.getData() != null) {
                result = new Uri[]{data.getData()};
            }
        }
        // The native service streams content:// files into staging. No base64 or
        // WebView File copy is needed, including for photos owned by other apps.
        fileCallback.onReceiveValue(null);
        fileCallback = null;
        if (result != null && result.length > 0) submitImport(Arrays.asList(result), null);
    }

    @Override
    public void onBackPressed() {
        if (webView.canGoBack()) webView.goBack();
        else super.onBackPressed();
    }

    @Override
    protected void onDestroy() {
        destroyed = true;
        imports.shutdownNow();
        requests.shutdownNow();
        updateHandler.removeCallbacks(automaticUpdateCheck);
        DropSyncRuntime.remove(nativeChanged);
        if (webView != null) {
            webView.loadUrl("about:blank");
            webView.destroy();
        }
        super.onDestroy();
    }

    private final class AndroidBridge {
        @JavascriptInterface
        public void openExternal(String value) {
            Uri uri = Uri.parse(value);
            if (!"https".equals(uri.getScheme()) || uri.getHost() == null) return;
            runOnUiThread(() -> {
                try { startActivity(new Intent(Intent.ACTION_VIEW, uri)); }
                catch (android.content.ActivityNotFoundException ignored) { }
            });
        }
        @JavascriptInterface
        public boolean isNativeApp() {
            return true;
        }
        @JavascriptInterface
        public boolean isTelevision() { return ((android.app.UiModeManager) getSystemService(UI_MODE_SERVICE)).getCurrentModeType() == android.content.res.Configuration.UI_MODE_TYPE_TELEVISION; }

        @JavascriptInterface
        public String getPlatform() {
            return "android";
        }

        @JavascriptInterface
        public String request(String path, String method, String body) {
            if (peerService == null) return "{\"__error\":\"Android peer service is unavailable\"}";
            return nativeRequest(path, method, body);
        }

        @JavascriptInterface
        public void requestAsync(String id, String path, String method, String body) {
            if (destroyed) return;
            requests.execute(() -> {
                String response = nativeRequest(path, method, body);
                runOnUiThread(() -> {
                    if (!destroyed && webView != null) webView.evaluateJavascript(
                            "window.completeDropSyncRequest && window.completeDropSyncRequest(" + JSONObject.quote(id) + "," + JSONObject.quote(response) + ")", null);
                });
            });
        }
    }

    private String nativeRequest(String path, String method, String body) {
        if ("/api/system/background-settings".equals(path) && "POST".equals(method)) { runOnUiThread(() -> { try { startActivity(new Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:" + getPackageName()))); } catch (RuntimeException ignored) { Toast.makeText(this, "Open Android app settings for DropSync", Toast.LENGTH_LONG).show(); } }); return "{\"ok\":true}"; }
        if ("/api/clipboard/read".equals(path) && "POST".equals(method)) {
            try {
                if (!peerService.settings().optBoolean("clipboardEnabled")) throw new java.io.IOException("Enable clipboard sharing in Security first");
                android.content.ClipboardManager manager = (android.content.ClipboardManager) getSystemService(CLIPBOARD_SERVICE); ClipData data = manager.getPrimaryClip();
                CharSequence text = data == null || data.getItemCount() == 0 ? null : data.getItemAt(0).getText();
                if (text == null || text.length() > 1_000_000) throw new java.io.IOException("The clipboard has no supported text");
                return new JSONObject().put("text", text.toString()).toString();
            } catch (Exception error) { return "{\"__error\":" + JSONObject.quote(error.getMessage()) + "}"; }
        }
        if ("/api/storage/choose".equals(path) && "POST".equals(method)) {
            runOnUiThread(() -> { try { Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION | Intent.FLAG_GRANT_PREFIX_URI_PERMISSION); pickerActive = true; startActivityForResult(intent, RECEIVE_FOLDER_REQUEST); } catch (RuntimeException error) { pickerActive = false; Toast.makeText(this, "No folder picker is available on this device", Toast.LENGTH_LONG).show(); } });
            return "{\"pending\":true}";
        }
        if (path.matches("/api/received/[a-fA-F0-9-]{36}/(open|show)") && "POST".equals(method)) {
            try {
                String id = path.split("/")[3]; JSONObject file = peerService.receivedFile(id); Uri uri = Uri.parse(file.getString("savedUri"));
                final boolean folder = path.endsWith("/show");
                final Uri target = folder ? android.provider.DocumentsContract.buildDocumentUriUsingTree(uri, android.provider.DocumentsContract.getTreeDocumentId(uri)) : uri;
                String fileName = file.optString("fileName");
                runOnUiThread(() -> { try { String type = folder ? "vnd.android.document/directory" : getContentResolver().getType(target); if (!folder && (type == null || "application/octet-stream".equals(type))) { int dot = fileName.lastIndexOf('.'); if (dot >= 0) type = android.webkit.MimeTypeMap.getSingleton().getMimeTypeFromExtension(fileName.substring(dot + 1).toLowerCase(java.util.Locale.ROOT)); } Intent intent = new Intent(Intent.ACTION_VIEW).setDataAndType(target, type == null ? "application/octet-stream" : type).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION); startActivity(intent); } catch (RuntimeException error) { Toast.makeText(this, "Open the selected folder in your Files app", Toast.LENGTH_LONG).show(); } });
                return "{\"ok\":true}";
            } catch (Exception error) { return "{\"__error\":" + JSONObject.quote(error.getMessage()) + "}"; }
        }
        if (path.matches("/api/received/[a-fA-F0-9-]{36}/thumbnail") && "GET".equals(method)) return nativeThumbnail(path.split("/")[3]);
        if (path.startsWith("/api/updates/")) return appUpdates == null ? "{\"__error\":\"Update service unavailable\"}" : appUpdates.request(path, method, body);
        return peerService.request(path, method, body);
    }

    private String nativeThumbnail(String id) {
        try {
            JSONObject file = peerService.receivedFile(id); String name = file.getString("fileName").toLowerCase(java.util.Locale.ROOT);
            if (!name.matches(".*\\.(png|jpe?g|webp|gif)$")) throw new java.io.IOException("No image preview");
            Uri uri = Uri.parse(file.getString("savedUri")); android.graphics.BitmapFactory.Options options = new android.graphics.BitmapFactory.Options(); options.inJustDecodeBounds = true;
            try (java.io.InputStream input = getContentResolver().openInputStream(uri)) { android.graphics.BitmapFactory.decodeStream(input, null, options); }
            if (options.outWidth < 1 || options.outHeight < 1 || (long) options.outWidth * options.outHeight > 40_000_000) throw new java.io.IOException("Image exceeds preview limits");
            options.inSampleSize = Math.max(1, Math.max(options.outWidth, options.outHeight) / 320); options.inJustDecodeBounds = false;
            android.graphics.Bitmap bitmap; try (java.io.InputStream input = getContentResolver().openInputStream(uri)) { bitmap = android.graphics.BitmapFactory.decodeStream(input, null, options); }
            if (bitmap == null) throw new java.io.IOException("Cannot preview this image");
            java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream(); bitmap.compress(android.graphics.Bitmap.CompressFormat.JPEG, 75, output); bitmap.recycle();
            return new JSONObject().put("dataUrl", "data:image/jpeg;base64," + android.util.Base64.encodeToString(output.toByteArray(), android.util.Base64.NO_WRAP)).toString();
        } catch (Exception error) { return "{\"__error\":\"Image preview unavailable\"}"; }
    }

    @Override protected void onResume() {
        super.onResume();
        if (peerService != null && !DropSyncRuntime.running()) { peerService = DropSyncRuntime.peer(this); DropSyncService.start(this); nativeChanged.run(); }
    }
    @Override protected void onStop() {
        super.onStop();
        try { if (peerService != null && !pickerActive && !isChangingConfigurations() && !peerService.settings().optBoolean("keepRunningInBackground", true)) stopService(new Intent(this, DropSyncService.class)); } catch (Exception ignored) { }
    }
}
