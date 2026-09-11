package org.tsicoop.sign.pki;

import java.io.FileInputStream;
import java.security.KeyStore;

/**
 * Loads the local PKI KeyStore (.pfx/.jks) used for synchronous, no-network
 * sealing (§7 Local PKI flow). Loaded once into a static holder — since
 * Chunk 9's refactor to the TSI framework's Action pattern, a new instance
 * of the owning Action (and thus of this class) is constructed per request,
 * so the actual KeyStore parse must not repeat on every request. A
 * reload/rotate operation is left to the admin console (Chunk 11).
 */
public class LocalKeyStoreProvider {

    private static final String DEFAULT_PATH = "/etc/tsi-sign/keystore.p12";
    private static final String DEFAULT_TYPE = "PKCS12";
    private static final String DEFAULT_PASSWORD = "changeit";

    private static volatile KeyStore sharedKeyStore;
    private static volatile char[] sharedKeyPassword;

    public LocalKeyStoreProvider() throws Exception {
        if (sharedKeyStore == null) {
            synchronized (LocalKeyStoreProvider.class) {
                if (sharedKeyStore == null) {
                    String path = envOrDefault("KEYSTORE_PATH", DEFAULT_PATH);
                    String type = envOrDefault("KEYSTORE_TYPE", DEFAULT_TYPE);
                    char[] password = envOrDefault("KEYSTORE_PASSWORD", DEFAULT_PASSWORD).toCharArray();

                    KeyStore keyStore = KeyStore.getInstance(type);
                    try (FileInputStream in = new FileInputStream(path)) {
                        keyStore.load(in, password);
                    }
                    sharedKeyPassword = password;
                    sharedKeyStore = keyStore;
                }
            }
        }
    }

    public synchronized KeyStore.PrivateKeyEntry getPrivateKeyEntry(String alias) throws Exception {
        KeyStore.ProtectionParameter protection = new KeyStore.PasswordProtection(sharedKeyPassword);
        KeyStore.Entry entry = sharedKeyStore.getEntry(alias, protection);
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
