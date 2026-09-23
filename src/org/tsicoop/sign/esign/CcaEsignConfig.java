package org.tsicoop.sign.esign;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Per-provider configuration for {@link CcaEsignAdapter}, read from env vars prefixed
 * {@code ESIGN_<PROVIDER_ID>_} (e.g. {@code ESIGN_EMUDHRA_URL}):
 * <ul>
 *   <li>{@code URL} (required) - the ESP's eSign form endpoint the signer's browser is sent to</li>
 *   <li>{@code ASP_ID} (required) - your ASP identifier issued by that CA</li>
 *   <li>{@code TRUST_CERTS} (required) - comma-separated PEM file(s): the CA/CCA certificate(s) the
 *       signer's certificate must chain to</li>
 *   <li>{@code ESP_CERT} (required) - comma-separated PEM file(s): the ESP's response-signing
 *       certificate(s), PINNED - a response must be signed by exactly one of them. (Chaining to the CA
 *       is not enough: any customer of that CA holds a certificate that chains to it.)</li>
 *   <li>{@code ASP_KEY_ALIAS} (default {@code tsi_asp_signing}) - the ASP request-signing key; taken
 *       from {@code ASP_KEYSTORE_PATH}/{@code _TYPE}/{@code _PASSWORD} if set, else the deployment's
 *       {@code KEYSTORE_*} keystore</li>
 *   <li>{@code VERSION} (default 2.1), {@code AUTH_MODE} (default 1 = Aadhaar OTP)</li>
 * </ul>
 * plus the deployment-wide {@code PUBLIC_BASE_URL} (browser-reachable URL of this server).
 */
public record CcaEsignConfig(
        String providerId, String displayName, String endpointUrl, String aspId, String version, String authMode,
        String aspKeyAlias, String aspKeystorePath, String aspKeystoreType, String aspKeystorePassword,
        List<Path> trustCertFiles, List<Path> espCertFiles, String publicBaseUrl
) {

    public static CcaEsignConfig fromEnv(String providerId, String displayName) {
        String prefix = "ESIGN_" + providerId.toUpperCase().replace('-', '_') + "_";
        List<String> missing = new ArrayList<>();
        String url = required(prefix + "URL", missing);
        String aspId = required(prefix + "ASP_ID", missing);
        String trust = required(prefix + "TRUST_CERTS", missing);
        String esp = required(prefix + "ESP_CERT", missing);
        if (!missing.isEmpty()) {
            throw new IllegalArgumentException("eSign provider '" + providerId + "' is not configured on this deployment - set "
                    + String.join(", ", missing) + ".");
        }
        List<Path> trustFiles = paths(trust);
        List<Path> espFiles = paths(esp);
        return new CcaEsignConfig(providerId, displayName, url, aspId,
                envOr(prefix + "VERSION", "2.1"), envOr(prefix + "AUTH_MODE", "1"),
                envOr(prefix + "ASP_KEY_ALIAS", "tsi_asp_signing"),
                System.getenv(prefix + "ASP_KEYSTORE_PATH"), envOr(prefix + "ASP_KEYSTORE_TYPE", "PKCS12"),
                System.getenv(prefix + "ASP_KEYSTORE_PASSWORD"), trustFiles, espFiles,
                stripTrailingSlash(envOr("PUBLIC_BASE_URL", "http://localhost:8088")));
    }

    private static List<Path> paths(String commaSeparated) {
        List<Path> out = new ArrayList<>();
        for (String p : commaSeparated.split(",")) {
            if (!p.isBlank()) {
                out.add(Path.of(p.trim()));
            }
        }
        return out;
    }

    private static String required(String name, List<String> missing) {
        String v = System.getenv(name);
        if (v == null || v.isBlank()) {
            missing.add(name);
            return null;
        }
        return v;
    }

    private static String envOr(String name, String fallback) {
        String v = System.getenv(name);
        return v != null && !v.isBlank() ? v : fallback;
    }

    private static String stripTrailingSlash(String s) {
        return s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
    }
}
