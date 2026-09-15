package org.tsicoop.sign.framework;

import java.security.SecureRandom;

/**
 * Generates App API key+secret pairs and hashes the secret for storage
 * (§4.1, §6) - the shared tenant-credential shape used across the TSI
 * stack (tsi-ledger's App.generateToken/apps.api_key+api_secret_hash is
 * the canonical reference; tsi-nexus mirrors it). api_key is a non-secret
 * public identifier, returned every time a key is listed; api_secret is
 * shown once at issuance/rotation and only its SHA-256 hash is persisted.
 */
public final class ApiKeyGenerator {

    private static final SecureRandom RANDOM = new SecureRandom();

    private ApiKeyGenerator() {
    }

    public record GeneratedKeyPair(String apiKey, String apiSecret, String apiSecretHash) {
    }

    public static GeneratedKeyPair generate() {
        String apiKey = token("key_");
        String apiSecret = token("sk_");
        return new GeneratedKeyPair(apiKey, apiSecret, sha256Hex(apiSecret));
    }

    private static String token(String prefix) {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return prefix + toHex(bytes);
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static String sha256Hex(String value) {
        return HashUtil.sha256Hex(value);
    }
}
