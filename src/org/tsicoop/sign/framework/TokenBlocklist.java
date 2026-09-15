package org.tsicoop.sign.framework;

import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory blocklist for revoked JWT IDs (jti claims) - matches
 * tsi-compass's TokenBlocklist. Entries self-expire when the original
 * token's own expiry passes, so the map doesn't grow unboundedly.
 *
 * Limitation (same as tsi-compass): state is lost on server restart, so a
 * token revoked just before a restart becomes valid again until it
 * naturally expires. A DB-backed store would close that gap if it ever
 * matters in practice.
 */
public final class TokenBlocklist {

    private static final ConcurrentHashMap<String, Long> revokedJtis = new ConcurrentHashMap<>();

    private TokenBlocklist() {
    }

    /** expiresAtMs is the token's own expiry (epoch ms) - once past it, the entry is dead weight anyway. */
    public static void revoke(String jti, long expiresAtMs) {
        revokedJtis.put(jti, expiresAtMs);
    }

    public static boolean isRevoked(String jti) {
        Long expiresAt = revokedJtis.get(jti);
        if (expiresAt == null) return false;
        if (System.currentTimeMillis() > expiresAt) {
            revokedJtis.remove(jti);
            return false;
        }
        return true;
    }
}
