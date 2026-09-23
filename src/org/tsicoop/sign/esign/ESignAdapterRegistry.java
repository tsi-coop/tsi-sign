package org.tsicoop.sign.esign;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Resolves a providerId to an {@link ESignAdapter} (BYO-CA: the engine never names a concrete CA).
 * Every provider here is {@link CcaEsignAdapter} - the CCA eSign API is one protocol - configured
 * per provider by env vars ({@link CcaEsignConfig}); the provider list below only fixes the ids
 * and the label shown on the visible signature stamp. A CA whose API genuinely departs from the
 * CCA spec gets its own {@link ESignAdapter} implementation, wired into {@link #build}.
 *
 * <p>Two resolution rules, mirroring {@code StorageProviderRegistry}, kept deliberately separate:
 * <ul>
 *   <li>{@link #resolve(String)} - for an *existing* eSign session, keyed by the providerId
 *   persisted on that row (esign_sessions.provider_id), so changing a default never strands an
 *   in-flight session.</li>
 *   <li>{@link #resolveForInitiate(String, String)} - for a *new* session: the request's explicit
 *   providerId, else the App's default_provider_id if it names a known eSign provider, else the
 *   deployment default ({@code DEFAULT_ESIGN_PROVIDER_ID}, falling back to {@code sandbox}).</li>
 * </ul>
 * An App's default_provider_id is shared with the local-seal flow (its console placeholder is
 * {@code local_pki}), so a value that isn't a known eSign provider is skipped rather than
 * treated as an error; an explicit request providerId that isn't known is an error.
 */
public class ESignAdapterRegistry {

    public static final String DEFAULT_PROVIDER_ENV = "DEFAULT_ESIGN_PROVIDER_ID";
    public static final String SANDBOX = "sandbox";

    /** providerId -> stamp label. See README "Supported eSign providers" for each one's verification status. */
    private static final Map<String, String> PROVIDERS = new LinkedHashMap<>();

    static {
        PROVIDERS.put(SANDBOX, "Aadhaar eSign (TSI Sandbox)");
        PROVIDERS.put("cca_generic", "Aadhaar eSign");
        PROVIDERS.put("emudhra", "Aadhaar eSign (eMudhra)");
        PROVIDERS.put("cdac", "Aadhaar eSign (C-DAC)");
        PROVIDERS.put("protean", "Aadhaar eSign (Protean)");
        PROVIDERS.put("vsign", "Aadhaar eSign (VSign)");
        PROVIDERS.put("capricorn", "Aadhaar eSign (Capricorn)");
        PROVIDERS.put("xtratrust", "Aadhaar eSign (XtraTrust)");
    }

    private static final Map<String, ESignAdapter> CACHE = new ConcurrentHashMap<>();

    public static boolean isRegistered(String providerId) {
        return providerId != null && PROVIDERS.containsKey(providerId);
    }

    public static Iterable<String> providerIds() {
        return PROVIDERS.keySet();
    }

    /** @throws IllegalArgumentException if providerId is unknown, or known but not configured on this deployment. */
    public static ESignAdapter resolve(String providerId) {
        if (!isRegistered(providerId)) {
            throw new IllegalArgumentException(
                    "No eSign provider configured for providerId '" + providerId + "' on this deployment.");
        }
        ESignAdapter cached = CACHE.get(providerId);
        if (cached != null) {
            return cached;
        }
        ESignAdapter built = build(providerId);
        CACHE.put(providerId, built);
        return built;
    }

    public static ESignAdapter resolveForInitiate(String requestedProviderId, String appDefaultProviderId) {
        if (requestedProviderId != null && !requestedProviderId.isBlank()) {
            return resolve(requestedProviderId);
        }
        if (isRegistered(appDefaultProviderId)) {
            return resolve(appDefaultProviderId);
        }
        return resolve(deploymentDefaultProviderId());
    }

    static String deploymentDefaultProviderId() {
        String value = System.getenv(DEFAULT_PROVIDER_ENV);
        return value != null && !value.isBlank() ? value : SANDBOX;
    }

    private static ESignAdapter build(String providerId) {
        return new CcaEsignAdapter(CcaEsignConfig.fromEnv(providerId, PROVIDERS.get(providerId)));
    }

    private ESignAdapterRegistry() {
    }
}
