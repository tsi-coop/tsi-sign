package org.tsicoop.sign.pki;

import java.io.FileInputStream;
import java.security.KeyStore;

/**
 * Loads the local PKI KeyStore (.pfx/.jks) used for synchronous, no-network
 * sealing (§7 Local PKI flow). Chunk 5 loads it once at servlet init; a
 * reload/rotate operation is left to the admin console (Chunk 11).
 */
public class LocalKeyStoreProvider {

    private static final String DEFAULT_PATH = "/etc/tsi-sign/keystore.p12";
    private static final String DEFAULT_TYPE = "PKCS12";
    private static final String DEFAULT_PASSWORD = "changeit";

    private final KeyStore keyStore;
    private final char[] keyPassword;

    public LocalKeyStoreProvider() throws Exception {
        String path = envOrDefault("KEYSTORE_PATH", DEFAULT_PATH);
        String type = envOrDefault("KEYSTORE_TYPE", DEFAULT_TYPE);
        String password = envOrDefault("KEYSTORE_PASSWORD", DEFAULT_PASSWORD);

        this.keyPassword = password.toCharArray();
        this.keyStore = KeyStore.getInstance(type);
        try (FileInputStream in = new FileInputStream(path)) {
            keyStore.load(in, keyPassword);
        }
    }

    public KeyStore.PrivateKeyEntry getPrivateKeyEntry(String alias) throws Exception {
        KeyStore.ProtectionParameter protection = new KeyStore.PasswordProtection(keyPassword);
        KeyStore.Entry entry = keyStore.getEntry(alias, protection);
        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            throw new IllegalArgumentException("No private key entry found for alias: " + alias);
        }
        return (KeyStore.PrivateKeyEntry) entry;
    }

    private static String envOrDefault(String name, String defaultValue) {
        String value = System.getenv(name);
        return value != null ? value : defaultValue;
    }
}
