package org.tsicoop.sign.framework;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Generates App API keys and hashes them for storage/lookup (§4.1, §6).
 * Only key_hash is ever persisted; the raw key is shown once at issuance.
 */
public final class ApiKeyGenerator {

    private static final SecureRandom RANDOM = new SecureRandom();

    private ApiKeyGenerator() {
    }

    public record GeneratedKey(String rawKey, String keyPrefix, String keyHash) {
    }

    public static GeneratedKey generate() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        String rawKey = "sk_" + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        String keyPrefix = rawKey.substring(0, Math.min(12, rawKey.length()));
        return new GeneratedKey(rawKey, keyPrefix, sha256Hex(rawKey));
    }

    public static String sha256Hex(String value) {
        return HashUtil.sha256Hex(value);
    }
}
