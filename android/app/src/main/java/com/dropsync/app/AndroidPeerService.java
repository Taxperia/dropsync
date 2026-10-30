package com.dropsync.app;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.net.Uri;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.InterfaceAddress;
import java.net.MulticastSocket;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Native, dependency-light DropSync/1 discovery and pairing peer for Android. */
final class AndroidPeerService {
    interface Listener { void onDevicesChanged(); }

    private static final String MULTICAST_ADDRESS = "239.255.42.99";
    private static final int DISCOVERY_PORT = 45555;
    private static final int PEER_PORT = 47821;
    private static final long DEVICE_TTL_MS = 15_000L;
    private static final byte[] ED25519_SPKI_PREFIX = hex("302a300506032b6570032100");
    private static final byte[] X25519_SPKI_PREFIX = hex("302a300506032b656e032100");

    private final Context context;
    private final SharedPreferences preferences;
    private final SecretStore secrets;
    private final AndroidPreferences configuration;
    private final AndroidReceiver receiver;
    private final SecureRandom random = new SecureRandom();
    private final ScheduledExecutorService workers = Executors.newScheduledThreadPool(5);
    private final java.util.concurrent.ThreadPoolExecutor peerConnections = new java.util.concurrent.ThreadPoolExecutor(4, 4, 0, TimeUnit.SECONDS,
            new java.util.concurrent.ArrayBlockingQueue<>(8));
    private final java.util.concurrent.ThreadPoolExecutor probes = new java.util.concurrent.ThreadPoolExecutor(2, 2, 0, TimeUnit.SECONDS, new java.util.concurrent.ArrayBlockingQueue<>(50));
    private final java.util.concurrent.atomic.AtomicBoolean probing = new java.util.concurrent.atomic.AtomicBoolean();
    private final java.util.Set<Socket> acceptedSockets = ConcurrentHashMap.newKeySet();
    private final ConcurrentHashMap<String, Peer> discovered = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Peer> trusted = new ConcurrentHashMap<>();
    private final Listener listener;
    private final Ed25519PrivateKeyParameters signingPrivate;
    private final X25519PrivateKeyParameters exchangePrivate;
    private final String signingPublicPem;
    private final String exchangePublicPem;
    private final String deviceId;
    private volatile boolean running;
    private volatile MulticastSocket discoverySocket;
    private volatile ServerSocket peerServer;
    private volatile WifiManager.MulticastLock multicastLock;
    private volatile PairingSession pairingSession;
    private final Object bandwidthLock = new Object();
    private double downloadTokens;
    private long downloadTick = System.nanoTime();
    private volatile String lastError;
    private volatile long lastAnnouncedAt;
    private volatile long lastReceivedAt;
    private volatile int receivedCount;
    private final Map<String, NetworkInterface> joinedInterfaces = new HashMap<>();
    private volatile List<LanInterface> discoveryInterfaces = Collections.emptyList();
    private final AndroidTransfers transfers;
    private final java.util.concurrent.atomic.AtomicInteger importing = new java.util.concurrent.atomic.AtomicInteger();
    private final java.util.concurrent.atomic.AtomicLong importRevision = new java.util.concurrent.atomic.AtomicLong();
    private volatile long acknowledgedImport;
    private volatile String importError;

    AndroidPeerService(Context context, Listener listener) {
        this.context = context.getApplicationContext();
        this.listener = listener;
        this.preferences = context.getSharedPreferences("dropsync.native.v1", Context.MODE_PRIVATE);
        this.secrets = new SecretStore(context, "dropsync.native.v1");
        this.configuration = new AndroidPreferences(context);
        byte[] signingSeed = readOrCreateSecret("signingSeed", 32);
        byte[] exchangeSeed = readOrCreateSecret("exchangeSeed", 32);
        signingPrivate = new Ed25519PrivateKeyParameters(signingSeed, 0);
        exchangePrivate = new X25519PrivateKeyParameters(exchangeSeed, 0);
        signingPublicPem = pem("PUBLIC KEY", concat(ED25519_SPKI_PREFIX, signingPrivate.generatePublicKey().getEncoded()));
        exchangePublicPem = pem("PUBLIC KEY", concat(X25519_SPKI_PREFIX, exchangePrivate.generatePublicKey().getEncoded()));
        deviceId = hexString(sha256(concat(ED25519_SPKI_PREFIX, signingPrivate.generatePublicKey().getEncoded()))).substring(0, 32);
        loadTrusted();
        transfers = new AndroidTransfers(this.context, this::notifyDevices, configuration);
        receiver = new AndroidReceiver(this.context, this, this::notifyDevices);
    }

    void start() {
        if (running) return;
        running = true;
        acquireMulticastLock();
        workers.execute(this::runDiscovery);
        workers.execute(this::runPeerServer);
        workers.scheduleAtFixedRate(this::announceSafely, 400, 4_000, TimeUnit.MILLISECONDS);
        workers.scheduleAtFixedRate(this::cleanup, 5_000, 5_000, TimeUnit.MILLISECONDS);
        workers.scheduleAtFixedRate(this::refreshManualPeers, 1000, 8000, TimeUnit.MILLISECONDS);
    }

    synchronized void stop() {
        running = false;
        try { if (discoverySocket != null) discoverySocket.close(); } catch (Exception ignored) { }
        try { if (peerServer != null) peerServer.close(); } catch (Exception ignored) { }
        if (multicastLock != null && multicastLock.isHeld()) multicastLock.release();
        workers.shutdownNow();
        peerConnections.shutdownNow();
        probes.shutdownNow();
        for (Socket socket : acceptedSockets) try { socket.close(); } catch (IOException ignored) { }
        transfers.stop();
        receiver.stop();
        configuration.close();
    }

    void beginImport() { importing.incrementAndGet(); notifyDevices(); }

    void importFiles(List<Uri> uris, String text) {
        try {
            importError = null;
            if (uris.isEmpty()) transfers.stageText(text);
            else for (Uri uri : uris) transfers.stageUri(uri);
        } catch (Exception error) { importError = error.getMessage(); }
        finally { importing.decrementAndGet(); importRevision.incrementAndGet(); notifyDevices(); }
    }

    String request(String path, String method, String body) {
        try {
            if (!running) throw new IOException("Sharing is stopped. Reopen DropSync to start sharing again.");
            JSONObject input = body == null || body.isEmpty() ? new JSONObject() : new JSONObject(body);
            if ("/api/bootstrap".equals(path)) return bootstrap().toString();
            if (("/api/notifications/read".equals(path) || "/api/notifications/clear".equals(path)) && "POST".equals(method)) return updateSettings(new JSONObject().put("ui", new JSONObject().put(path.endsWith("/clear") ? "notifications-clear-at" : "notifications-read-at", System.currentTimeMillis()))).toString();
            if ("/api/project/license".equals(path) && "GET".equals(method)) { try (InputStream stream = context.getAssets().open("www/LICENSE")) { return new JSONObject().put("text", new String(readToEnd(stream, 65536), StandardCharsets.UTF_8)).toString(); } }
            if ("/api/devices".equals(path)) return new JSONObject().put("devices", devices()).toString();
            if ("/api/pairing/session".equals(path) && "POST".equals(method)) return createPairingSession().toString();
            if ("/api/pair".equals(path) && "POST".equals(method)) return pair(input.getString("deviceId"), input.getString("code")).toString();
            if ("/api/devices/manual".equals(path) && "POST".equals(method)) return manualPeer(input.optString("address")).toString();
            if ("/api/settings".equals(path) && "PUT".equals(method)) return updateSettings(input).toString();
            if ("/api/transfers".equals(path) && "GET".equals(method)) return new JSONObject().put("transfers", allTransfers()).toString();
            if ("/api/incoming".equals(path) && "GET".equals(method)) return new JSONObject().put("requests", receiver.requests()).toString();
            if (path.matches("/api/incoming/[a-fA-F0-9-]{36}") && "POST".equals(method)) { receiver.decide(path.substring("/api/incoming/".length()), input.getBoolean("accept")); return new JSONObject().put("requests", receiver.requests()).put("transfers", allTransfers()).toString(); }
            if ("/api/stage/text".equals(path) && "POST".equals(method)) { transfers.stageText(input.getString("text")); return new JSONObject().put("stagedFiles", transfers.stagedFiles()).toString(); }
            if ("/api/security/virustotal".equals(path) && "GET".equals(method)) return new JSONObject().put("configured", !configuration.apiKey().isEmpty()).put("persisted", true).toString();
            if ("/api/security/virustotal/key".equals(path) && "POST".equals(method)) { configuration.apiKey(input.optString("key").trim()); return new JSONObject().put("configured", !configuration.apiKey().isEmpty()).toString(); }
            if (path.matches("/api/transfers/[a-fA-F0-9-]{36}/retry") && "POST".equals(method)) return retryTransfer(path.substring("/api/transfers/".length(), path.length() - "/retry".length())).toString();
            if ("/api/transfers?status=completed".equals(path) && "DELETE".equals(method)) {
                int before = transfers.transfers().length(); transfers.clearCompleted();
                return new JSONObject().put("removed", before - transfers.transfers().length()).toString();
            }
            if ("/api/transfers/send".equals(path) && "POST".equals(method)) return sendFiles(input).toString();
            if (path.matches("/api/stage/[a-f0-9-]{36}") && "DELETE".equals(method)) {
                transfers.removeStage(path.substring("/api/stage/".length()));
                return new JSONObject().put("ok", true).toString();
            }
            if (path.matches("/api/transfers/[a-f0-9-]{36}/action") && "POST".equals(method)) {
                String id = path.substring("/api/transfers/".length(), path.length() - "/action".length());
                if ("cancel".equals(input.optString("action")) && receiver.cancel(id)) return new JSONObject().put("ok", true).toString();
                return new JSONObject().put("transfer", transfers.control(id, input.getString("action"))).toString();
            }
            if ("/api/import/ack".equals(path) && "POST".equals(method)) {
                acknowledgedImport = Math.max(acknowledgedImport, Math.min(importRevision.get(), input.getLong("revision")));
                return new JSONObject().put("ok", true).toString();
            }
            if (path.startsWith("/api/trusted/") && "DELETE".equals(method)) {
                String id = path.substring("/api/trusted/".length()).toLowerCase(Locale.ROOT);
                trusted.remove(id); transfers.revokeDevice(id); receiver.revoke(id); saveTrusted(); notifyDevices();
                return new JSONObject().put("removed", true).toString();
            }
            throw new Exception("Unsupported Android request");
        } catch (Exception error) {
            try { return new JSONObject().put("__error", error.getMessage() == null ? "Android peer request failed" : error.getMessage()).toString(); }
            catch (Exception ignored) { return "{\"__error\":\"Android peer request failed\"}"; }
        }
    }

    private JSONObject bootstrap() throws Exception {
        JSONObject settings = settings();
        JSONObject discovery = new JSONObject()
                .put("port", DISCOVERY_PORT)
                .put("multicastAddress", MULTICAST_ADDRESS)
                .put("lastAnnouncedAt", lastAnnouncedAt == 0 ? JSONObject.NULL : lastAnnouncedAt)
                .put("lastReceivedAt", lastReceivedAt == 0 ? JSONObject.NULL : lastReceivedAt)
                .put("receivedCount", receivedCount)
                .put("lastError", lastError == null ? JSONObject.NULL : lastError)
                .put("interfaces", discoveryInterfaceInfo());
        JSONArray trustedDevices = new JSONArray();
        for (Peer peer : trusted.values()) trustedDevices.put(peer.trustedJson());
        return new JSONObject()
                .put("version", "0.7.0")
                .put("csrfToken", "native")
                .put("self", selfInfo())
                .put("settings", settings)
                .put("managedSettings", settings.getJSONArray("managedSettings"))
                .put("discovery", discovery)
                .put("devices", devices())
                .put("trustedDevices", trustedDevices)
                .put("transfers", allTransfers())
                .put("incomingRequests", receiver.requests())
                .put("stagedFiles", transfers.stagedFiles())
                .put("importState", new JSONObject().put("busy", importing.get() > 0)
                        .put("revision", importRevision.get()).put("pending", importRevision.get() > acknowledgedImport)
                        .put("error", importError == null ? JSONObject.NULL : importError))
                .put("security", new JSONObject()
                        .put("protocol", "DropSync transfer/2 (discovery and pairing/1)")
                        .put("identity", "Ed25519")
                        .put("keyAgreement", "X25519 + HKDF-SHA-256")
                        .put("encryption", "AES-256-GCM per 256 KiB chunk"))
                .put("system", new JSONObject())
                .put("capabilities", new JSONObject()
                        .put("discovery", true).put("pairing", true)
                        .put("transferSend", true).put("transferReceive", settings.optBoolean("receivingEnabled", true)));
    }

    private JSONObject sendFiles(JSONObject input) throws Exception {
        String id = input.getString("deviceId");
        Peer live = discovered.get(id), pinned = trusted.get(id);
        if (live == null || System.currentTimeMillis() - live.lastSeen > DEVICE_TTL_MS) throw new Exception("Device is not online");
        if (pinned == null || !configuration.peerAllowed(id)) throw new Exception("Pair an allowed device before sending");
        if (!pinned.signingPublicKey.equals(live.signingPublicKey) || !pinned.exchangePublicKey.equals(live.exchangePublicKey)) throw new Exception("Peer identity changed; pair again");
        if (!live.capabilities.optBoolean("transferReceive", true)) throw new Exception("This device does not support receiving files");
        return new JSONObject().put("transfers", transfers.send(id, live.name, live.address, live.port,
                pinned.exchangePublicKey, deviceId, signingPrivate, input.getJSONArray("fileIds"), () -> {
                    Peer current = trusted.get(id);
                    if (current == null || !configuration.peerAllowed(id) || !current.signingPublicKey.equals(pinned.signingPublicKey) || !current.exchangePublicKey.equals(pinned.exchangePublicKey)) throw new IOException("Device trust was removed or its identity changed");
                }, () -> {
                    Peer current = discovered.get(id); if (current == null) current = live;
                    return new JSONObject().put("address", current.address).put("port", current.port);
                }, input.has("operationId") ? input.getString("operationId") : null));
    }

    private String ownDeviceType() { return context.getSystemService(android.app.UiModeManager.class).getCurrentModeType() == android.content.res.Configuration.UI_MODE_TYPE_TELEVISION ? "tv" : "phone"; }

    private JSONObject selfInfo() throws Exception {
        return new JSONObject()
                .put("deviceId", deviceId)
                .put("name", getDeviceName())
                .put("deviceType", ownDeviceType())
                .put("fingerprint", fingerprint(signingPublicPem))
                .put("port", PEER_PORT)
                .put("addresses", localAddresses());
    }

    private JSONArray localAddresses() {
        JSONArray result = new JSONArray();
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface item = interfaces.nextElement();
                if (!item.isUp() || item.isLoopback()) continue;
                Enumeration<InetAddress> addresses = item.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress address = addresses.nextElement();
                    if (address.getAddress().length == 4 && !address.isLoopbackAddress()) result.put(address.getHostAddress());
                }
            }
        } catch (Exception ignored) { }
        return result;
    }

    private JSONObject updateSettings(JSONObject patch) throws Exception {
        JSONObject settings = configuration.update(patch); announceSafely(); notifyDevices();
        if (patch.has("virusTotalEnabled") || patch.has("virusTotalUploadUnknown") || patch.has("virusTotalBlockUnknown")) NativeThreatScanner.reset();
        return new JSONObject().put("settings", settings);
    }

    private String getDeviceName() {
        try { return configuration.get().getString("deviceName"); } catch (Exception error) { throw new IllegalStateException(error); }
    }

    JSONObject settings() throws Exception { return configuration.get(); }
    String localDeviceId() { return deviceId; }
    X25519PrivateKeyParameters exchangeKey() { return exchangePrivate; }
    String receiveTree() { return configuration.tree(); }
    String receiveFolderLabel() { return configuration.folderLabel(); }
    void selectReceiveTree(Uri uri, String label) throws Exception { configuration.selectTree(uri, label); notifyDevices(); }
    JSONObject receivedFile(String id) throws Exception { return receiver.file(id); }
    JSONObject trustedIdentity(String id) throws Exception { Peer peer = trusted.get(id); return peer == null || !configuration.peerAllowed(id) ? null : peer.identityJson().put("name", peer.name).put("deviceType", peer.deviceType); }
    boolean verifyTransfer(JSONObject meta, String signature, JSONObject peer) throws Exception { return verify(ProtocolJson.canonical(meta).getBytes(StandardCharsets.UTF_8), signature, peer.getString("signingPublicKey")); }
    void assertTrusted(String id, JSONObject pinned) throws Exception {
        Peer current = trusted.get(id);
        if (current == null || !configuration.peerAllowed(id) || !current.signingPublicKey.equals(pinned.getString("signingPublicKey")) || !current.exchangePublicKey.equals(pinned.getString("exchangePublicKey"))) throw new IOException("Device trust was removed or changed");
    }
    void checkThreat(String hash, java.io.File encryptedFile) throws Exception { NativeThreatScanner.inspect(context, configuration, hash, encryptedFile, true); }
    void limitTransfer(boolean sending, long bytes, long startedNanos) throws Exception {
        long remaining = bytes;
        while (remaining > 0) {
            if (Thread.currentThread().isInterrupted()) throw new java.io.InterruptedIOException("Transfer interrupted");
            long rate = configuration.get().optLong("downloadLimitKBps") * 1024L; if (rate <= 0) return;
            synchronized (bandwidthLock) { long now = System.nanoTime(); downloadTokens = Math.min(Math.max(256, rate / 4.0), downloadTokens + (now - downloadTick) * rate / 1_000_000_000.0); downloadTick = now; long used = Math.min(remaining, (long) downloadTokens); downloadTokens -= used; remaining -= used; }
            if (remaining > 0) Thread.sleep(Math.min(100, Math.max(1, Math.min(remaining, Math.max(256, rate / 4)) * 1000 / rate)));
        }
    }
    JSONArray allTransfers() throws Exception { JSONArray result = transfers.transfers(), incoming = receiver.transfers(); for (int i = 0; i < incoming.length(); i++) result.put(incoming.get(i)); return result; }
    private JSONObject retryTransfer(String id) throws Exception {
        JSONObject previous = transfers.find(id);
        if (!Arrays.asList("failed", "cancelled").contains(previous.optString("status"))) throw new IOException("Only stopped transfers may be retried");
        return sendFiles(new JSONObject().put("deviceId", previous.getString("deviceId")).put("operationId", previous.optString("operationId", previous.getString("id"))).put("fileIds", new JSONArray().put(previous.getString("stagedFileId"))));
    }

    private JSONArray devices() throws Exception {
        cleanup();
        Map<String, Peer> merged = new HashMap<>();
        for (Peer peer : trusted.values()) merged.put(peer.deviceId, peer.offlineCopy());
        merged.putAll(discovered);
        List<Peer> list = new ArrayList<>(merged.values());
        list.sort(Comparator.comparing((Peer peer) -> !trusted.containsKey(peer.deviceId)).thenComparing(peer -> peer.name.toLowerCase(Locale.ROOT)));
        JSONArray result = new JSONArray();
        for (Peer peer : list) result.put(peer.publicJson(trusted.containsKey(peer.deviceId)));
        return result;
    }

    private void runDiscovery() {
        while (running) {
          try (MulticastSocket socket = new MulticastSocket(null)) {
            socket.setReuseAddress(true);
            socket.bind(new InetSocketAddress(DISCOVERY_PORT));
            socket.setSoTimeout(2_000);
            socket.setBroadcast(true);
            socket.setTimeToLive(1);
            discoverySocket = socket;
            announceSafely();
            byte[] buffer = new byte[8192];
            while (running) {
                DatagramPacket datagram = new DatagramPacket(buffer, buffer.length);
                try {
                    socket.receive(datagram);
                    if (configuration.get().optBoolean("discoveryEnabled", true)) handleAnnouncement(new String(datagram.getData(), datagram.getOffset(), datagram.getLength(), StandardCharsets.UTF_8), datagram.getAddress().getHostAddress());
                } catch (java.net.SocketTimeoutException ignored) { }
            }
          } catch (Exception error) {
            if (running) lastError = "LAN discovery unavailable: " + error.getMessage();
          } finally {
            discoverySocket = null;
            synchronized (joinedInterfaces) { joinedInterfaces.clear(); }
          }
          if (running) {
            try { Thread.sleep(2_000); }
            catch (InterruptedException ignored) { Thread.currentThread().interrupt(); return; }
          }
        }
    }

    private List<LanInterface> refreshDiscoveryInterfaces(MulticastSocket socket) throws Exception {
        List<LanInterface> active = new ArrayList<>();
        Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
        while (interfaces != null && interfaces.hasMoreElements()) {
            NetworkInterface item = interfaces.nextElement();
            if (!item.isUp() || item.isLoopback()) continue;
            for (InterfaceAddress address : item.getInterfaceAddresses()) {
                if (address.getAddress().getAddress().length != 4 || address.getAddress().isLoopbackAddress()) continue;
                active.add(new LanInterface(item, address.getAddress(), address.getBroadcast()));
            }
        }
        synchronized (joinedInterfaces) {
            Map<String, NetworkInterface> current = new HashMap<>();
            for (LanInterface entry : active) {
                String key = entry.network.getName() + ":" + entry.address.getHostAddress();
                current.put(key, entry.network);
                if (joinedInterfaces.containsKey(key)) continue;
                try {
                    socket.joinGroup(new InetSocketAddress(MULTICAST_ADDRESS, DISCOVERY_PORT), entry.network);
                    joinedInterfaces.put(key, entry.network);
                } catch (Exception error) {
                    lastError = "Could not join LAN interface " + entry.network.getName() + ": " + error.getMessage();
                }
            }
            Iterator<Map.Entry<String, NetworkInterface>> joined = joinedInterfaces.entrySet().iterator();
            while (joined.hasNext()) {
                Map.Entry<String, NetworkInterface> entry = joined.next();
                if (current.containsKey(entry.getKey())) continue;
                try { socket.leaveGroup(new InetSocketAddress(MULTICAST_ADDRESS, DISCOVERY_PORT), entry.getValue()); }
                catch (Exception ignored) { }
                joined.remove();
            }
        }
        discoveryInterfaces = active;
        return active;
    }

    private JSONArray discoveryInterfaceInfo() throws Exception {
        JSONArray result = new JSONArray();
        for (LanInterface entry : discoveryInterfaces) {
            result.put(new JSONObject().put("name", entry.network.getName())
                    .put("address", entry.address.getHostAddress())
                    .put("broadcast", entry.broadcast == null ? JSONObject.NULL : entry.broadcast.getHostAddress()));
        }
        return result;
    }

    private static final class LanInterface {
        final NetworkInterface network;
        final InetAddress address, broadcast;
        LanInterface(NetworkInterface network, InetAddress address, InetAddress broadcast) {
            this.network = network; this.address = address; this.broadcast = broadcast;
        }
    }

    private void acquireMulticastLock() {
        try {
            WifiManager wifi = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
            multicastLock = wifi.createMulticastLock("DropSyncDiscovery");
            multicastLock.setReferenceCounted(false);
            multicastLock.acquire();
        } catch (Exception error) { lastError = "Could not enable Wi-Fi multicast: " + error.getMessage(); }
    }

    private void announceSafely() {
        try {
            MulticastSocket socket = discoverySocket;
            if (!running || socket == null || socket.isClosed() || !configuration.get().optBoolean("discoveryEnabled", true)) return;
            synchronized (socket) {
                byte[] payload = announcement().toString().getBytes(StandardCharsets.UTF_8);
                boolean sent = false;
                for (LanInterface entry : refreshDiscoveryInterfaces(socket)) {
                    try {
                        socket.setNetworkInterface(entry.network);
                        socket.send(new DatagramPacket(payload, payload.length, InetAddress.getByName(MULTICAST_ADDRESS), DISCOVERY_PORT));
                        sent = true;
                    } catch (Exception error) { lastError = "LAN multicast failed on " + entry.network.getName() + ": " + error.getMessage(); }
                    // A multicast failure must not prevent the broadcast fallback.
                    if (entry.broadcast != null) {
                        try {
                            socket.send(new DatagramPacket(payload, payload.length, entry.broadcast, DISCOVERY_PORT));
                            sent = true;
                        } catch (Exception error) { lastError = "LAN broadcast failed on " + entry.network.getName() + ": " + error.getMessage(); }
                    }
                }
                if (sent) lastAnnouncedAt = System.currentTimeMillis();
                else lastError = "No LAN announcement sent. Check the Wi-Fi connection and local network access.";
            }
        } catch (Exception error) { lastError = "LAN announcement failed: " + error.getMessage(); }
    }

    private JSONObject announcement() throws Exception {
        JSONObject data = publicIdentity()
                .put("name", getDeviceName())
                .put("deviceType", ownDeviceType())
                .put("port", PEER_PORT)
                .put("capabilities", capabilities())
                .put("timestamp", System.currentTimeMillis())
                .put("nonce", base64Url(randomBytes(12)));
        return new JSONObject().put("type", "dropsync-announce").put("data", data).put("signature", sign(canonical(data).getBytes(StandardCharsets.UTF_8)));
    }

    private JSONObject capabilities() throws Exception {
        return new JSONObject().put("pairing", true).put("transferSend", true).put("transferReceive", settings().optBoolean("receivingEnabled", true));
    }

    private JSONObject publicIdentity() throws Exception {
        return new JSONObject().put("version", 1).put("deviceId", deviceId)
                .put("signingPublicKey", signingPublicPem).put("exchangePublicKey", exchangePublicPem);
    }

    private void handleAnnouncement(String encoded, String address) {
        try {
            if (!privateAddress(address)) return;
            JSONObject packet = new JSONObject(encoded);
            if (!"dropsync-announce".equals(packet.optString("type"))) return;
            JSONObject data = packet.getJSONObject("data");
            String id = data.getString("deviceId");
            if (deviceId.equals(id) || Math.abs(System.currentTimeMillis() - data.getLong("timestamp")) > 120_000) return;
            if (!validateIdentity(data)) return;
            int port = data.getInt("port");
            String name = data.getString("name").trim();
            if (port < 1 || port > 65535 || name.isEmpty() || name.length() > 48) return;
            if (!verify(canonical(data).getBytes(StandardCharsets.UTF_8), packet.getString("signature"), data.getString("signingPublicKey"))) return;
            Peer peer = Peer.fromIdentity(data, name, address, port, data.optJSONObject("capabilities"));
            Peer pinned = trusted.get(id);
            if (pinned != null && (!pinned.signingPublicKey.equals(peer.signingPublicKey) || !pinned.exchangePublicKey.equals(peer.exchangePublicKey))) return;
            if (!discovered.containsKey(id) && discovered.size() >= 256) {
                if (pinned == null) return;
                String evict = null;
                for (String existing : discovered.keySet()) if (!trusted.containsKey(existing)) { evict = existing; break; }
                if (evict == null) return;
                discovered.remove(evict);
            }
            if (pinned != null && !pinned.deviceType.equals(peer.deviceType)) {
                trusted.put(id, pinned.withDeviceType(peer.deviceType)); saveTrusted();
            }
            discovered.put(id, peer);
            lastReceivedAt = System.currentTimeMillis();
            receivedCount += 1;
            notifyDevices();
        } catch (Exception ignored) { }
    }

    private void cleanup() {
        if (receiver != null) receiver.cleanup();
        long now = System.currentTimeMillis();
        boolean changed = false;
        for (Map.Entry<String, Peer> item : discovered.entrySet()) {
            if (now - item.getValue().lastSeen > DEVICE_TTL_MS) changed |= discovered.remove(item.getKey(), item.getValue());
        }
        if (changed) notifyDevices();
    }

    private void notifyDevices() { if (listener != null) listener.onDevicesChanged(); }

    private JSONObject createPairingSession() throws Exception {
        int number = 100_000 + random.nextInt(900_000);
        pairingSession = new PairingSession(String.valueOf(number), System.currentTimeMillis() + 300_000L);
        return new JSONObject().put("code", pairingSession.code).put("expiresAt", pairingSession.expiresAt).put("self", selfInfo());
    }

    private JSONObject pair(String id, String code) throws Exception {
        if (!configuration.peerAllowed(id)) throw new IOException("This device is blocked by organization policy");
        if (!code.matches("^[0-9]{6}$")) throw new Exception("Enter the six-digit pairing code");
        Peer peer = discovered.get(id);
        if (peer == null) throw new Exception("Device is no longer online");
        String requestId = UUID.randomUUID().toString();
        X25519PrivateKeyParameters ephemeral = new X25519PrivateKeyParameters(random);
        byte[] salt = randomBytes(32);
        byte[] secret = new byte[32];
        ephemeral.generateSecret(new X25519PublicKeyParameters(rawPublic(peer.exchangePublicKey, X25519_SPKI_PREFIX), 0), secret, 0);
        byte[] key = hkdf(secret, salt, ("DropSync transfer v1\0pairing:" + requestId).getBytes(StandardCharsets.UTF_8), 32);
        JSONObject payload = new JSONObject().put("code", code).put("identity", publicIdentity())
                .put("name", getDeviceName()).put("deviceType", ownDeviceType()).put("timestamp", System.currentTimeMillis()).put("port", PEER_PORT);
        payload.put("proof", sign(ProtocolJson.canonical(pairingProof(payload)).getBytes(StandardCharsets.UTF_8)));
        JSONObject sealed = seal(key, requestId, payload);
        JSONObject envelope = new JSONObject().put("version", 1).put("requestId", requestId)
                .put("ephemeralPublicKey", pem("PUBLIC KEY", concat(X25519_SPKI_PREFIX, ephemeral.generatePublicKey().getEncoded())))
                .put("salt", base64Url(salt));
        copyJson(sealed, envelope);
        JSONObject response = httpJson(peer.address, peer.port, "POST", "/peer/pair", envelope);
        JSONObject opened = open(key, requestId, response);
        JSONObject identity = opened.getJSONObject("identity");
        if (!validateIdentity(identity) || !id.equals(identity.getString("deviceId"))) throw new Exception("Peer identity changed during pairing");
        if (!peer.signingPublicKey.equals(identity.getString("signingPublicKey")) || !peer.exchangePublicKey.equals(identity.getString("exchangePublicKey"))) throw new Exception("Peer key mismatch detected");
        Peer saved = Peer.fromIdentity(identity, opened.optString("name", peer.name), peer.address, peer.port, peer.capabilities, peer.deviceType);
        trusted.put(id, saved); saveTrusted(); notifyDevices();
        configuration.rememberPeer(peer.address + ":" + peer.port);
        return new JSONObject().put("trusted", saved.trustedJson());
    }

    private JSONObject manualPeer(String value) throws Exception { return probeManualPeer(value, true); }
    private JSONObject probeManualPeer(String value, boolean remember) throws Exception {
        String input = value == null ? "" : value.trim();
        if (input.isEmpty()) throw new Exception("Enter the other device's local IPv4 address");
        String host = input;
        int port = PEER_PORT;
        int colon = input.lastIndexOf(':');
        if (colon > 0 && input.indexOf(':') == colon) {
            host = input.substring(0, colon);
            port = Integer.parseInt(input.substring(colon + 1));
        }
        if (port < 1 || port > 65535) throw new IOException("Enter a valid port");
        if (!host.matches("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$")) {
            if (host.length() > 253 || !host.toLowerCase(Locale.ROOT).matches("^[a-z0-9][a-z0-9.-]*\\.ts\\.net$")) throw new IOException("Enter a private IPv4 address or full Tailscale MagicDNS name");
            String resolved = null;
            for (InetAddress candidate : InetAddress.getAllByName(host)) {
                byte[] bytes = candidate.getAddress();
                if (bytes.length == 4 && (bytes[0] & 255) == 100 && (bytes[1] & 255) >= 64 && (bytes[1] & 255) <= 127) { resolved = candidate.getHostAddress(); break; }
            }
            if (resolved == null) throw new IOException("MagicDNS name must resolve to a Tailscale IPv4 address");
            host = resolved;
        }
        for (String octet : host.split("\\.")) if (Integer.parseInt(octet) > 255) throw new IOException("Invalid IPv4 address");
        byte[] ip = InetAddress.getByName(host).getAddress();
        int a = ip[0] & 255, b = ip[1] & 255;
        if (!(a == 10 || a == 127 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) || (a == 100 && b >= 64 && b <= 127))) throw new IOException("Only private LAN or Tailscale addresses are allowed");
        JSONObject packet = httpJson(host, port, "GET", "/peer/info", null);
        handleAnnouncement(packet.toString(), InetAddress.getByName(host).getHostAddress());
        String id = packet.getJSONObject("data").getString("deviceId");
        Peer peer = discovered.get(id);
        if (peer == null) throw new Exception("Invalid signed DropSync identity");
        if (remember) configuration.rememberPeer(input);
        return new JSONObject().put("device", peer.publicJson(trusted.containsKey(id)));
    }
    private void refreshManualPeers() {
        if (!running || !probing.compareAndSet(false, true)) return;
        try {
            JSONArray values = configuration.manualPeers();
            if (values.length() == 0) { probing.set(false); return; }
            java.util.concurrent.atomic.AtomicInteger left = new java.util.concurrent.atomic.AtomicInteger(values.length());
            for (int i=0;i<values.length();i++) {
                String address = values.getString(i);
                try { probes.execute(() -> { try { probeManualPeer(address, false); } catch (Exception ignored) { } finally { if (left.decrementAndGet() == 0) probing.set(false); } }); }
                catch (java.util.concurrent.RejectedExecutionException error) { if (left.decrementAndGet() == 0) probing.set(false); }
            }
        } catch (Exception error) { probing.set(false); }
    }

    private void runPeerServer() {
        try {
            ServerSocket server = new ServerSocket();
            server.setReuseAddress(true);
            server.bind(new InetSocketAddress(PEER_PORT));
            peerServer = server;
            while (running) {
                Socket socket = server.accept();
                acceptedSockets.add(socket);
                try { peerConnections.execute(() -> handlePeerConnection(socket)); }
                catch (java.util.concurrent.RejectedExecutionException error) { acceptedSockets.remove(socket); socket.close(); }
            }
        } catch (Exception error) {
            if (running) lastError = "Peer service unavailable on port " + PEER_PORT + ": " + error.getMessage();
        }
    }

    private void handlePeerConnection(Socket socket) {
        try {
            if (!privateAddress(socket.getInetAddress().getHostAddress())) throw new IOException("Only private LAN or Tailscale peers are allowed");
            socket.setSoTimeout(10_000);
            BufferedInputStream input = new BufferedInputStream(socket.getInputStream());
            String first = readLine(input);
            String[] request = first.split(" ");
            if (request.length < 2) throw new Exception("Invalid request");
            Map<String, String> headers = new HashMap<>();
            String line;
            int totalHeaders = first.length();
            while (!(line = readLine(input)).isEmpty()) {
                totalHeaders += line.length() + 2;
                if (totalHeaders > 16_384) throw new IOException("Request headers too large");
                int split = line.indexOf(':');
                if (split > 0) headers.put(line.substring(0, split).trim().toLowerCase(Locale.ROOT), line.substring(split + 1).trim());
            }
            if ("POST".equals(request[0]) && "/peer/transfers".equals(request[1])) { socket.setSoTimeout(120_000); receiver.receive(headers, input, socket); return; }
            if ("POST".equals(request[0]) && "/peer/transfers/prepare".equals(request[1])) { writeResponse(socket.getOutputStream(), 200, receiver.prepare(headers)); return; }
            int length = Integer.parseInt(headers.getOrDefault("content-length", "0"));
            if (length < 0 || length > 65_536) throw new Exception("Request is too large");
            byte[] body = readExact(input, length);
            if ("GET".equals(request[0]) && "/peer/info".equals(request[1])) {
                writeResponse(socket.getOutputStream(), 200, announcement());
            } else if ("POST".equals(request[0]) && "/peer/pair".equals(request[1])) {
                writeResponse(socket.getOutputStream(), 200, acceptPair(new JSONObject(new String(body, StandardCharsets.UTF_8)), socket.getInetAddress().getHostAddress()));
            } else writeResponse(socket.getOutputStream(), 404, new JSONObject().put("error", "Unknown peer endpoint"));
        } catch (Exception error) {
            try { writeResponse(socket.getOutputStream(), 400, new JSONObject().put("error", "Peer request was rejected or interrupted. Check the receiving device for details.")); } catch (Exception ignored) { }
        } finally { acceptedSockets.remove(socket); try { socket.close(); } catch (Exception ignored) { } }
    }

    private synchronized JSONObject acceptPair(JSONObject envelope, String sourceAddress) throws Exception {
        if (envelope.optInt("version") != 1 || !envelope.optString("requestId").matches("^[a-fA-F0-9-]{36}$")) throw new IOException("Unsupported pairing envelope");
        PairingSession session = pairingSession;
        if (session == null || session.expiresAt < System.currentTimeMillis()) throw new Exception("No active pairing session");
        session.attempts += 1;
        if (session.attempts > 5) { pairingSession = null; throw new Exception("Too many pairing attempts"); }
        String requestId = envelope.getString("requestId");
        byte[] salt = base64UrlDecode(envelope.getString("salt"));
        if (salt.length != 32) throw new Exception("Invalid pairing salt");
        byte[] secret = new byte[32];
        exchangePrivate.generateSecret(new X25519PublicKeyParameters(rawPublic(envelope.getString("ephemeralPublicKey"), X25519_SPKI_PREFIX), 0), secret, 0);
        byte[] key = hkdf(secret, salt, ("DropSync transfer v1\0pairing:" + requestId).getBytes(StandardCharsets.UTF_8), 32);
        JSONObject payload = open(key, requestId, envelope);
        if (!constantTimeEquals(session.code, payload.optString("code"))) throw new Exception("Pairing code is invalid");
        JSONObject identity = payload.getJSONObject("identity");
        if (!validateIdentity(identity) || payload.optString("name").trim().isEmpty() || payload.optString("name").length() > 48 || Math.abs(System.currentTimeMillis() - payload.getLong("timestamp")) > 120_000) throw new Exception("Invalid peer identity");
        if (!verify(ProtocolJson.canonical(pairingProof(payload)).getBytes(StandardCharsets.UTF_8), payload.optString("proof"), identity.getString("signingPublicKey"))) throw new Exception("Pairing identity proof is invalid; update both devices");
        String id = identity.getString("deviceId");
        if (!configuration.peerAllowed(id)) throw new IOException("Device is not allowed by organization policy");
        if (payload.has("port") && (!(payload.get("port") instanceof Number) || payload.getDouble("port") != payload.getInt("port") || payload.getInt("port") < 1 || payload.getInt("port") > 65535)) throw new IOException("Invalid peer port");
        Peer pinned = trusted.get(id);
        if (pinned != null && (!pinned.signingPublicKey.equals(identity.getString("signingPublicKey")) || !pinned.exchangePublicKey.equals(identity.getString("exchangePublicKey")))) throw new Exception("Pinned identity changed. Remove trust and verify the fingerprint before pairing again.");
        Peer live = discovered.get(id);
        String address = sourceAddress;
        int port = payload.optInt("port", live == null ? PEER_PORT : live.port);
        Peer peer = Peer.fromIdentity(identity, payload.optString("name", "DropSync device"), address, port, live == null ? null : live.capabilities,
                live == null ? payload.optString("deviceType", "desktop") : live.deviceType);
        trusted.put(id, peer); saveTrusted(); pairingSession = null; notifyDevices();
        if (privateAddress(sourceAddress)) { configuration.rememberPeer(sourceAddress + ":" + port); try { probes.execute(() -> { try { probeManualPeer(sourceAddress + ":" + port, false); } catch (Exception ignored) { } }); } catch (java.util.concurrent.RejectedExecutionException ignored) { } }
        return seal(key, requestId, new JSONObject().put("identity", publicIdentity()).put("name", getDeviceName()).put("deviceType", ownDeviceType()));
    }

    private JSONObject httpJson(String host, int port, String method, String path, JSONObject body) throws Exception {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), 5_000);
            socket.setSoTimeout(10_000);
            byte[] encoded = body == null ? new byte[0] : body.toString().getBytes(StandardCharsets.UTF_8);
            BufferedOutputStream output = new BufferedOutputStream(socket.getOutputStream());
            String head = method + " " + path + " HTTP/1.1\r\nHost: " + host + ":" + port + "\r\nConnection: close\r\nAccept: application/json\r\n" +
                    (encoded.length > 0 ? "Content-Type: application/json\r\nContent-Length: " + encoded.length + "\r\n" : "") + "\r\n";
            output.write(head.getBytes(StandardCharsets.US_ASCII)); output.write(encoded); output.flush();
            BufferedInputStream input = new BufferedInputStream(socket.getInputStream());
            String status = readLine(input);
            String[] statusParts = status.split(" ", 3);
            int statusCode = statusParts.length > 1 ? Integer.parseInt(statusParts[1]) : 500;
            int contentLength = -1;
            String line;
            int headerBytes = status.length();
            while (!(line = readLine(input)).isEmpty()) {
                headerBytes += line.length() + 2;
                if (headerBytes > 16_384) throw new IOException("Peer response headers too large");
                int split = line.indexOf(':');
                if (split > 0 && "content-length".equals(line.substring(0, split).trim().toLowerCase(Locale.ROOT))) contentLength = Integer.parseInt(line.substring(split + 1).trim());
            }
            if (contentLength < -1 || contentLength > 65_536) throw new IOException("Peer response too large");
            byte[] response = contentLength >= 0 ? readExact(input, contentLength) : readToEnd(input, 65_536);
            JSONObject json = response.length == 0 ? new JSONObject() : new JSONObject(new String(response, StandardCharsets.UTF_8));
            if (statusCode < 200 || statusCode >= 300) throw new Exception(json.optString("error", "Peer request failed (" + statusCode + ")"));
            return json;
        }
    }

    private static JSONObject pairingProof(JSONObject payload) throws Exception {
        JSONObject proof = new JSONObject().put("code", payload.getString("code")).put("identity", payload.getJSONObject("identity"))
                .put("name", payload.getString("name")).put("deviceType", payload.optString("deviceType", "desktop")).put("timestamp", payload.getLong("timestamp"));
        if (payload.has("port")) proof.put("port", payload.get("port")); return proof;
    }

    private static boolean privateAddress(String address) {
        try { byte[] ip = InetAddress.getByName(address).getAddress(); if (ip.length != 4) return false; int a = ip[0] & 255, b = ip[1] & 255; return a == 10 || a == 127 || (a == 169 && b == 254) || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) || (a == 100 && b >= 64 && b <= 127); } catch (Exception ignored) { return false; }
    }

    private JSONObject seal(byte[] key, String requestId, JSONObject payload) throws Exception {
        byte[] nonce = randomBytes(12);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        cipher.updateAAD(("DropSync pairing v1\0" + requestId).getBytes(StandardCharsets.UTF_8));
        byte[] encryptedAndTag = cipher.doFinal(payload.toString().getBytes(StandardCharsets.UTF_8));
        int tagOffset = encryptedAndTag.length - 16;
        return new JSONObject().put("nonce", base64Url(nonce))
                .put("ciphertext", base64Url(slice(encryptedAndTag, 0, tagOffset)))
                .put("tag", base64Url(slice(encryptedAndTag, tagOffset, encryptedAndTag.length)));
    }

    private JSONObject open(byte[] key, String requestId, JSONObject sealed) throws Exception {
        byte[] nonce = base64UrlDecode(sealed.getString("nonce"));
        byte[] ciphertext = base64UrlDecode(sealed.getString("ciphertext"));
        byte[] tag = base64UrlDecode(sealed.getString("tag"));
        if (nonce.length != 12 || tag.length != 16 || ciphertext.length > 32 * 1024) throw new Exception("Invalid pairing envelope");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        cipher.updateAAD(("DropSync pairing v1\0" + requestId).getBytes(StandardCharsets.UTF_8));
        return new JSONObject(new String(cipher.doFinal(concat(ciphertext, tag)), StandardCharsets.UTF_8));
    }

    private String sign(byte[] message) {
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, signingPrivate); signer.update(message, 0, message.length);
        return base64Url(signer.generateSignature());
    }

    private static boolean verify(byte[] message, String signature, String publicPem) {
        try {
            Ed25519Signer verifier = new Ed25519Signer();
            verifier.init(false, new Ed25519PublicKeyParameters(rawPublic(publicPem, ED25519_SPKI_PREFIX), 0));
            verifier.update(message, 0, message.length);
            return verifier.verifySignature(base64UrlDecode(signature));
        } catch (Exception ignored) { return false; }
    }

    private static boolean validateIdentity(JSONObject identity) {
        try {
            if (identity.getInt("version") != 1 || !identity.getString("deviceId").matches("^[a-f0-9]{32}$")) return false;
            byte[] signingRaw = rawPublic(identity.getString("signingPublicKey"), ED25519_SPKI_PREFIX);
            rawPublic(identity.getString("exchangePublicKey"), X25519_SPKI_PREFIX);
            String expected = hexString(sha256(concat(ED25519_SPKI_PREFIX, signingRaw))).substring(0, 32);
            return expected.equals(identity.getString("deviceId"));
        } catch (Exception ignored) { return false; }
    }

    private byte[] readOrCreateSecret(String key, int length) {
        try {
            String encoded = secrets.get(key, null);
            if (encoded != null) { byte[] value = base64UrlDecode(encoded); if (value.length != length) throw new IOException("Invalid protected device identity"); return value; }
            byte[] value = randomBytes(length); secrets.put(key, base64Url(value)); return value;
        } catch (Exception error) { throw new IllegalStateException("Could not unlock the existing device identity", error); }
    }

    private void loadTrusted() {
        try {
            JSONObject stored = new JSONObject(secrets.get("trusted", "{}"));
            Iterator<String> keys = stored.keys();
            while (keys.hasNext()) {
                String id = keys.next();
                JSONObject item = stored.getJSONObject(id);
                if (validateIdentity(item)) trusted.put(id, Peer.fromStored(item));
            }
        } catch (Exception error) { throw new IllegalStateException("Could not unlock device trust", error); }
    }

    private synchronized void saveTrusted() {
        if (!running) return;
        try {
            JSONObject value = new JSONObject();
            for (Peer peer : trusted.values()) value.put(peer.deviceId, peer.storedJson());
            secrets.put("trusted", value.toString());
        } catch (Exception error) { throw new IllegalStateException("Could not save protected device trust", error); }
    }

    static void writeResponse(OutputStream raw, int status, JSONObject body) throws Exception {
        byte[] encoded = body.toString().getBytes(StandardCharsets.UTF_8);
        String reason = status >= 200 && status < 300 ? "OK" : "Error";
        raw.write(("HTTP/1.1 " + status + " " + reason + "\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: " + encoded.length + "\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
        raw.write(encoded); raw.flush();
    }

    private static String readLine(InputStream input) throws IOException {
        ByteArrayOutputStream line = new ByteArrayOutputStream();
        int previous = -1;
        while (line.size() < 8192) {
            int current = input.read();
            if (current < 0) throw new EOFException("Unexpected end of request");
            if (previous == '\r' && current == '\n') {
                byte[] bytes = line.toByteArray();
                return new String(bytes, 0, Math.max(0, bytes.length - 1), StandardCharsets.US_ASCII);
            }
            line.write(current); previous = current;
        }
        throw new IOException("Header line is too long");
    }

    private static byte[] readExact(InputStream input, int length) throws IOException {
        byte[] result = new byte[length]; int offset = 0;
        while (offset < length) { int count = input.read(result, offset, length - offset); if (count < 0) throw new EOFException(); offset += count; }
        return result;
    }

    private static byte[] readToEnd(InputStream input, int limit) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream(); byte[] buffer = new byte[4096]; int count;
        while ((count = input.read(buffer)) >= 0) { if (output.size() + count > limit) throw new IOException("Response is too large"); output.write(buffer, 0, count); }
        return output.toByteArray();
    }

    private static byte[] hkdf(byte[] inputKey, byte[] salt, byte[] info, int length) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(salt, "HmacSHA256"));
        byte[] prk = mac.doFinal(inputKey);
        ByteArrayOutputStream output = new ByteArrayOutputStream(); byte[] previous = new byte[0]; int counter = 1;
        while (output.size() < length) {
            mac.init(new SecretKeySpec(prk, "HmacSHA256"));
            mac.update(previous); mac.update(info); mac.update((byte) counter++); previous = mac.doFinal(); output.write(previous);
        }
        return slice(output.toByteArray(), 0, length);
    }

    private static String canonical(Object value) throws Exception {
        return ProtocolJson.canonical(value);
    }

    private static void copyJson(JSONObject source, JSONObject target) throws Exception { Iterator<String> keys = source.keys(); while (keys.hasNext()) { String key = keys.next(); target.put(key, source.get(key)); } }
    private byte[] randomBytes(int length) { byte[] result = new byte[length]; random.nextBytes(result); return result; }
    private static boolean constantTimeEquals(String left, String right) { return MessageDigest.isEqual(left.getBytes(StandardCharsets.UTF_8), right.getBytes(StandardCharsets.UTF_8)); }
    private static byte[] sha256(byte[] value) { try { return MessageDigest.getInstance("SHA-256").digest(value); } catch (Exception error) { throw new IllegalStateException(error); } }
    private static String fingerprint(String publicPem) throws Exception { String hex = hexString(sha256(der(publicPem))).toUpperCase(Locale.ROOT); return hex.substring(0,4)+"-"+hex.substring(4,8)+"-"+hex.substring(8,12)+"-"+hex.substring(12,16); }
    private static String pem(String type, byte[] der) { return "-----BEGIN " + type + "-----\n" + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(der) + "\n-----END " + type + "-----\n"; }
    private static byte[] der(String pem) { return Base64.getMimeDecoder().decode(pem.replaceAll("-----[^-]+-----", "").replaceAll("\\s", "")); }
    private static byte[] rawPublic(String pem, byte[] prefix) throws Exception { byte[] value = der(pem); if (value.length != prefix.length + 32) throw new Exception("Invalid public key"); for (int i=0;i<prefix.length;i++) if (value[i]!=prefix[i]) throw new Exception("Unsupported public key"); return slice(value,prefix.length,value.length); }
    private static String base64Url(byte[] value) { return Base64.getUrlEncoder().withoutPadding().encodeToString(value); }
    private static byte[] base64UrlDecode(String value) { return Base64.getUrlDecoder().decode(value); }
    private static byte[] concat(byte[]... values) { int size=0; for(byte[] value:values)size+=value.length; byte[] result=new byte[size]; int offset=0; for(byte[] value:values){System.arraycopy(value,0,result,offset,value.length);offset+=value.length;} return result; }
    private static byte[] slice(byte[] value, int start, int end) { byte[] result=new byte[end-start]; System.arraycopy(value,start,result,0,result.length); return result; }
    private static byte[] hex(String value) { byte[] result=new byte[value.length()/2]; for(int i=0;i<result.length;i++)result[i]=(byte)Integer.parseInt(value.substring(i*2,i*2+2),16); return result; }
    private static String hexString(byte[] value) { StringBuilder result=new StringBuilder(value.length*2); for(byte item:value)result.append(String.format(Locale.ROOT,"%02x",item&255)); return result.toString(); }

    private static final class PairingSession {
        final String code; final long expiresAt; int attempts;
        PairingSession(String code, long expiresAt) { this.code = code; this.expiresAt = expiresAt; }
    }

    private static final class Peer {
        final String deviceId, name, address, signingPublicKey, exchangePublicKey, deviceType;
        final int port; final long lastSeen; final JSONObject capabilities;
        Peer(String deviceId, String name, String address, int port, String signingPublicKey, String exchangePublicKey, long lastSeen, JSONObject capabilities, String deviceType) {
            this.deviceId=deviceId; this.name=name; this.address=address; this.port=port; this.signingPublicKey=signingPublicKey; this.exchangePublicKey=exchangePublicKey; this.lastSeen=lastSeen;
            this.capabilities=capabilities == null ? new JSONObject() : capabilities;
            this.deviceType = "phone".equals(deviceType) || "browser".equals(deviceType) || "tv".equals(deviceType) ? deviceType : "desktop";
        }
        static Peer fromIdentity(JSONObject identity, String name, String address, int port, JSONObject capabilities) throws Exception {
            return fromIdentity(identity, name, address, port, capabilities, identity.optString("deviceType",
                    capabilities != null && !capabilities.optBoolean("transferReceive", true) ? "phone" : "desktop"));
        }
        static Peer fromIdentity(JSONObject identity, String name, String address, int port, JSONObject capabilities, String deviceType) throws Exception {
            return new Peer(identity.getString("deviceId"), name, address, port, identity.getString("signingPublicKey"), identity.getString("exchangePublicKey"), System.currentTimeMillis(), capabilities, deviceType);
        }
        static Peer fromStored(JSONObject value) throws Exception {
            JSONObject capabilities = value.optJSONObject("capabilities");
            return new Peer(value.getString("deviceId"),value.getString("name"),value.optString("address"),value.optInt("port",PEER_PORT),value.getString("signingPublicKey"),value.getString("exchangePublicKey"),value.optLong("lastSeen"),capabilities,
                    value.optString("deviceType", capabilities != null && !capabilities.optBoolean("transferReceive", true) ? "phone" : "desktop"));
        }
        Peer offlineCopy() { return new Peer(deviceId,name,address,port,signingPublicKey,exchangePublicKey,lastSeen,capabilities,deviceType); }
        Peer withDeviceType(String type) { return new Peer(deviceId,name,address,port,signingPublicKey,exchangePublicKey,lastSeen,capabilities,type); }
        JSONObject identityJson() throws Exception { return new JSONObject().put("version",1).put("deviceId",deviceId).put("signingPublicKey",signingPublicKey).put("exchangePublicKey",exchangePublicKey); }
        JSONObject storedJson() throws Exception { JSONObject value=identityJson(); return value.put("name",name).put("deviceType",deviceType).put("address",address).put("port",port).put("lastSeen",lastSeen).put("capabilities",capabilities); }
        JSONObject trustedJson() throws Exception { return new JSONObject().put("deviceId",deviceId).put("name",name).put("deviceType",deviceType).put("fingerprint",fingerprint(signingPublicKey)).put("pairedAt",lastSeen); }
        JSONObject publicJson(boolean isTrusted) throws Exception { return new JSONObject().put("deviceId",deviceId).put("name",name).put("deviceType",deviceType).put("address",address).put("port",port).put("trusted",isTrusted).put("online",System.currentTimeMillis()-lastSeen<=DEVICE_TTL_MS && !address.isEmpty()).put("lastSeen",lastSeen).put("fingerprint",fingerprint(signingPublicKey)).put("capabilities",capabilities); }
    }
}
