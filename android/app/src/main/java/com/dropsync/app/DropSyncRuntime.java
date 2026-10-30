package com.dropsync.app;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import java.util.concurrent.CopyOnWriteArraySet;

/** Process lifetime is owned by the foreground service, never by an Activity. */
final class DropSyncRuntime {
    private static AndroidPeerService peer;
    private static final Handler handler = new Handler(Looper.getMainLooper());
    private static final CopyOnWriteArraySet<Runnable> listeners = new CopyOnWriteArraySet<>();
    private static final java.util.concurrent.atomic.AtomicBoolean queued = new java.util.concurrent.atomic.AtomicBoolean();
    static synchronized AndroidPeerService peer(Context context) {
        if (peer == null) { peer = new AndroidPeerService(context.getApplicationContext(), DropSyncRuntime::changed); peer.start(); }
        return peer;
    }
    static void add(Runnable listener) { listeners.add(listener); }
    static void remove(Runnable listener) { listeners.remove(listener); }
    static synchronized boolean running() { return peer != null; }
    static void changed() { if (queued.compareAndSet(false, true)) handler.postDelayed(() -> { queued.set(false); for (Runnable listener : listeners) listener.run(); }, 250); }
    static synchronized void stop() { if (peer != null) peer.stop(); peer = null; changed(); }
}
