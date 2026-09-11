package org.tsicoop.sign.framework;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Fixed-window (per-minute) in-memory rate limiter, keyed by appId (§9,
 * Chunk 9). In-memory is sufficient for the single-node Phase 1 deployment
 * this plan targets — a multi-node deployment would need a shared store,
 * but that's out of scope until the plan actually calls for horizontal
 * scale (§5.1 notes local_fs itself doesn't scale across nodes either).
 */
public class RateLimiter {

    private record Window(long windowStartMillis, AtomicInteger count) {
    }

    private static final long WINDOW_MILLIS = 60_000;

    private final ConcurrentHashMap<String, Window> windows = new ConcurrentHashMap<>();

    /** Returns true if this request is within the App's requests-per-minute budget. */
    public boolean tryAcquire(String appId, int rpm) {
        long now = System.currentTimeMillis();
        Window window = windows.compute(appId, (id, existing) -> {
            if (existing == null || now - existing.windowStartMillis() >= WINDOW_MILLIS) {
                return new Window(now, new AtomicInteger(0));
            }
            return existing;
        });
        return window.count().incrementAndGet() <= rpm;
    }
}
