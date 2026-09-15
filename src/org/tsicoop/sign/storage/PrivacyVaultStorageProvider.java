package org.tsicoop.sign.storage;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.tsicoop.sign.framework.HashUtil;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Base64;

/**
 * Delegates the "sealed"/"original" PDF store to a co-deployed TSI Privacy
 * Vault instance (Chunk 12, §5.1) — inherits Vault's field-level encryption
 * and its own independent access audit trail on top of TSI Sign's own
 * audit_logs.
 *
 * <p>Confirmed against Privacy Vault's actual shipped API
 * (org.tsicoop.privacyvault.api.client.Vault): a single endpoint,
 * {@code POST {baseUrl}/api/client/vault}, dispatched by {@code _func} in
 * the JSON body — the same InputProcessor/_func convention TSI Sign itself
 * uses. Auth is a flat {@code X-API-Key} header (no AUTH_MODE suffix in
 * Privacy Vault's own _processor.tsi for this path); the caller must already
 * have WRITE/READ permission on the configured entity_code.
 *
 * <p>Privacy Vault has no delete/remove case at all for vault entities
 * ({@code Vault.java}'s dispatch switch has no such branch) — {@link
 * #delete} throws rather than silently no-op-ing. Nothing in TSI Sign calls
 * DocumentStorageProvider.delete() today, so this is a documented
 * limitation, not a behavior regression.
 */
public class PrivacyVaultStorageProvider implements DocumentStorageProvider {

    public static final String PROVIDER_ID = "privacy_vault";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final String baseUrl;
    private final String apiKey;
    private final String entityCode;
    private final HttpClient httpClient;

    /** Config resolved by StorageProviderRegistry (System Settings DB row, falling back to PRIVACY_VAULT_* env vars). */
    public PrivacyVaultStorageProvider(String baseUrl, String apiKey, String entityCode) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.apiKey = apiKey;
        this.entityCode = entityCode;
        this.httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    }

    @Override
    public String getProviderId() {
        return PROVIDER_ID;
    }

    @Override
    public StorageObjectRef store(String appSlug, String documentId, String variant, byte[] content)
            throws StorageException {
        ObjectNode body = MAPPER.createObjectNode();
        body.put("_func", "store_data");
        body.put("entityType", "FILE");
        body.put("entityName", entityCode);
        body.put("content", Base64.getEncoder().encodeToString(content));
        body.put("fileName", appSlug + "-" + documentId + "-" + variant + ".pdf");

        JsonNode response = call(body, "store document in Privacy Vault");
        String referenceKey = response.path("reference_key").asText(null);
        if (referenceKey == null) {
            throw new StorageException("Privacy Vault store_data response missing reference_key: " + response);
        }
        return new StorageObjectRef(PROVIDER_ID, referenceKey, HashUtil.sha256Hex(content));
    }

    @Override
    public byte[] retrieve(StorageObjectRef ref) throws StorageException {
        requireOwnProvider(ref);
        ObjectNode body = MAPPER.createObjectNode();
        body.put("_func", "fetch_data");
        body.put("reference-key", ref.storageKey());

        JsonNode response = call(body, "retrieve document from Privacy Vault");
        String value = response.path("value").asText(null);
        if (value == null) {
            throw new StorageException("Privacy Vault fetch_data response missing value: " + response);
        }
        return Base64.getDecoder().decode(value);
    }

    @Override
    public void delete(StorageObjectRef ref) throws StorageException {
        requireOwnProvider(ref);
        throw new StorageException("delete is not supported by the Privacy Vault storage provider - "
                + "TSI Privacy Vault's vault_entities API has no delete/remove operation.");
    }

    private JsonNode call(ObjectNode body, String action) throws StorageException {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + "/api/client/vault"))
                    .timeout(Duration.ofSeconds(30))
                    .header("Content-Type", "application/json")
                    .header("X-API-Key", apiKey)
                    .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            JsonNode json = MAPPER.readTree(response.body());
            if (response.statusCode() >= 400 || !json.path("success").asBoolean(false)) {
                throw new StorageException("Failed to " + action + " (HTTP " + response.statusCode() + "): "
                        + response.body());
            }
            return json;
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new StorageException("Failed to " + action, e);
        }
    }

    private void requireOwnProvider(StorageObjectRef ref) throws StorageException {
        if (!PROVIDER_ID.equals(ref.providerId())) {
            throw new StorageException("StorageObjectRef belongs to provider '" + ref.providerId()
                    + "', not '" + PROVIDER_ID + "'");
        }
    }
}
