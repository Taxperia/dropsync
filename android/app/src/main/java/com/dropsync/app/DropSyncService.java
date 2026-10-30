package com.dropsync.app;

import android.app.*;
import android.content.*;
import android.content.pm.ServiceInfo;
import android.net.*;
import android.net.wifi.WifiManager;
import android.os.*;
import org.json.*;
import java.util.*;
import java.util.concurrent.Executors;

/** User-started connected-device service with actionable transfer notifications. */
public final class DropSyncService extends Service {
    private static final int SERVICE_ID = 701;
    private static final String CHANNEL = "dropsync.transfers", REQUESTS = "dropsync.requests";
    private AndroidPeerService peer;
    private final Runnable refreshed = this::refresh;
    private final Map<String, String> previous = new HashMap<>();
    private final Set<Integer> requestNotifications = new HashSet<>();
    private PowerManager.WakeLock wakeLock;
    private WifiManager.WifiLock wifiLock;
    private ConnectivityManager.NetworkCallback networkCallback;
    private final java.util.concurrent.ExecutorService commands = Executors.newSingleThreadExecutor();
    private final Handler tickHandler = new Handler(Looper.getMainLooper());
    private long lastWake;
    private final Runnable tick = new Runnable() { @Override public void run() { refresh(); tickHandler.postDelayed(this, 30_000); } };
    public static void start(Context context) { context.startForegroundService(new Intent(context, DropSyncService.class)); }
    @Override public void onCreate() {
        super.onCreate(); NotificationManager manager = getSystemService(NotificationManager.class);
        manager.createNotificationChannel(new NotificationChannel(CHANNEL, "File transfers", NotificationManager.IMPORTANCE_DEFAULT));
        manager.createNotificationChannel(new NotificationChannel(REQUESTS, "Incoming file requests", NotificationManager.IMPORTANCE_HIGH));
        Notification notification = ongoing("Ready for paired devices");
        if (Build.VERSION.SDK_INT >= 29) startForeground(SERVICE_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE); else startForeground(SERVICE_ID, notification);
        peer = DropSyncRuntime.peer(this); DropSyncRuntime.add(refreshed);
        wakeLock = ((PowerManager) getSystemService(POWER_SERVICE)).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "DropSync:transfer"); wakeLock.setReferenceCounted(false);
        wifiLock = ((WifiManager) getApplicationContext().getSystemService(WIFI_SERVICE)).createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, "DropSync:transfer"); wifiLock.setReferenceCounted(false);
        networkCallback = new ConnectivityManager.NetworkCallback() { @Override public void onAvailable(Network network) { DropSyncRuntime.changed(); } @Override public void onLost(Network network) { DropSyncRuntime.changed(); } };
        getSystemService(ConnectivityManager.class).registerDefaultNetworkCallback(networkCallback); refresh();
        tickHandler.postDelayed(tick, 30_000);
    }
    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && "stop".equals(intent.getAction())) { stopSelf(); return START_NOT_STICKY; }
        if (intent != null && intent.getAction() != null) commands.execute(() -> {
            String id = intent.getStringExtra("id"), action = intent.getAction(); if (id == null || !id.matches("[a-fA-F0-9-]{36}")) return;
            String path = "accept".equals(action) || "decline".equals(action) ? "/api/incoming/" + id : "/api/transfers/" + id + ("retry".equals(action) ? "/retry" : "/action");
            String body = "accept".equals(action) || "decline".equals(action) ? "{\"accept\":" + "accept".equals(action) + "}" : "retry".equals(action) ? "{}" : "{\"action\":\"cancel\"}";
            String response = peer.request(path, "POST", body);
            try { JSONObject result = new JSONObject(response); if (result.has("__error")) show(900, "Open DropSync to continue", result.optString("__error"), null, null); } catch (Exception ignored) { }
            DropSyncRuntime.changed();
        });
        return START_NOT_STICKY;
    }
    private PendingIntent open() { return PendingIntent.getActivity(this, 1, new Intent(this, MainActivity.class), PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE); }
    private PendingIntent action(String action, String id) {
        Intent intent = new Intent(this, DropSyncService.class).setAction(action).putExtra("id", id);
        return PendingIntent.getService(this, (action + id).hashCode(), intent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
    }
    private Notification ongoing(String text) {
        return new Notification.Builder(this, CHANNEL).setSmallIcon(android.R.drawable.stat_sys_upload).setContentTitle("DropSync sharing is active").setContentText(text)
                .setContentIntent(open()).setVisibility(Notification.VISIBILITY_PRIVATE).setOngoing(true).setOnlyAlertOnce(true).addAction(new Notification.Action.Builder(null, "Stop sharing", action("stop", "service")).build()).build();
    }
    private void show(int id, String title, String text, String transferId, String operation) {
        Notification.Builder builder = new Notification.Builder(this, "accept".equals(operation) ? REQUESTS : CHANNEL).setSmallIcon(android.R.drawable.stat_sys_download_done)
                .setContentTitle(title).setContentText(text).setStyle(new Notification.BigTextStyle().bigText(text)).setContentIntent(open()).setVisibility(Notification.VISIBILITY_PRIVATE).setOnlyAlertOnce(true).setOngoing("cancel".equals(operation)).setAutoCancel(!"cancel".equals(operation));
        if (transferId != null && operation != null) builder.addAction(new Notification.Action.Builder(null, "accept".equals(operation) ? "Accept" : "retry".equals(operation) ? "Retry" : "Cancel transfer", action(operation, transferId)).build());
        if ("accept".equals(operation)) builder.addAction(new Notification.Action.Builder(null, "Decline", action("decline", transferId)).build());
        try { getSystemService(NotificationManager.class).notify(id, builder.build()); } catch (SecurityException ignored) { }
    }
    private void refresh() {
        if (peer == null) return;
        try {
            JSONObject settings = peer.settings(); boolean notify = settings.optBoolean("notificationsEnabled", true); int active = 0;
            JSONArray transfers = peer.allTransfers(), incoming = new JSONObject(peer.request("/api/incoming", "GET", "")).optJSONArray("requests");
            Set<Integer> pendingIds = new HashSet<>();
            if (incoming != null) for (int i = 0; i < incoming.length(); i++) {
                JSONObject item = incoming.getJSONObject(i); int id = 1000 + (item.getString("id").hashCode() & 0x3fffffff); pendingIds.add(id);
                if (!requestNotifications.contains(id) && notify) show(id, "Incoming file from " + item.optString("deviceName"), item.optString("fileName"), item.getString("id"), settings.optBoolean("receiveFolderSelected") ? "accept" : null);
            }
            for (int id : requestNotifications) if (!pendingIds.contains(id)) getSystemService(NotificationManager.class).cancel(id);
            requestNotifications.clear(); requestNotifications.addAll(pendingIds);
            for (int i = 0; i < transfers.length(); i++) {
                JSONObject transfer = transfers.getJSONObject(i); String id = transfer.getString("id"), status = transfer.optString("status"), old = previous.put(id, status);
                if (Arrays.asList("connecting","sending","receiving","scanning","publishing","retrying","awaiting-acceptance").contains(status)) active++;
                if (old != null && !status.equals(old) && notify) {
                    if (Arrays.asList("connecting","sending","receiving","scanning","publishing","retrying","paused").contains(status)) show(2000 + (id.hashCode() & 0x3fffffff), "Transfer " + status, transfer.optString("fileName"), id, "cancel");
                    if ("cancelled".equals(status)) getSystemService(NotificationManager.class).cancel(2000 + (id.hashCode() & 0x3fffffff));
                    if ("completed".equals(status)) show(2000 + (id.hashCode() & 0x3fffffff), "Transfer completed", transfer.optString("fileName"), null, null);
                    if ("failed".equals(status)) show(2000 + (id.hashCode() & 0x3fffffff), "Transfer interrupted", transfer.optString("fileName") + ": " + transfer.optString("error"), "send".equals(transfer.optString("direction")) ? id : null, "send".equals(transfer.optString("direction")) ? "retry" : null);
                }
            }
            if (previous.size() > 1000) previous.keySet().retainAll(new HashSet<>(historyIds(transfers)));
            if (active > 0) { if (!wakeLock.isHeld() || System.currentTimeMillis() - lastWake >= 60_000) { wakeLock.acquire(120_000L); lastWake = System.currentTimeMillis(); } if (!wifiLock.isHeld()) wifiLock.acquire(); }
            else { if (wakeLock.isHeld()) wakeLock.release(); if (wifiLock.isHeld()) wifiLock.release(); }
            getSystemService(NotificationManager.class).notify(SERVICE_ID, ongoing(active > 0 ? active + " active transfer(s)" : "Ready for paired devices · tap to open"));
        } catch (Exception ignored) { }
    }
    private List<String> historyIds(JSONArray transfers) throws Exception { List<String> result = new ArrayList<>(); for (int i=0;i<transfers.length();i++) result.add(transfers.getJSONObject(i).getString("id")); return result; }
    @Override public void onDestroy() {
        tickHandler.removeCallbacksAndMessages(null);
        DropSyncRuntime.remove(refreshed); commands.shutdownNow();
        if (networkCallback != null) getSystemService(ConnectivityManager.class).unregisterNetworkCallback(networkCallback);
        if (wakeLock != null && wakeLock.isHeld()) wakeLock.release(); if (wifiLock != null && wifiLock.isHeld()) wifiLock.release();
        DropSyncRuntime.stop(); super.onDestroy();
    }
    @Override public IBinder onBind(Intent intent) { return null; }
}
