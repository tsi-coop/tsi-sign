package org.tsicoop.sign.service.v1;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.tsicoop.sign.framework.Action;
import org.tsicoop.sign.framework.InputProcessor;
import org.tsicoop.sign.framework.OutputProcessor;

/**
 * Deployment-wide System Settings screen - today just the storage backend
 * config (default provider + s3/privacy_vault connection details) that used
 * to be env-var only (see StorageProviderRegistry). PLATFORM_ADMIN only:
 * this is deployment-critical config that also houses secrets (S3 secret
 * key, Privacy Vault API key), same sensitivity bar as Users & Roles.
 * funcs: get_settings, update_settings.
 */
public class SystemSettings implements Action {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final SystemSettingsRepository settingsRepository = new SystemSettingsRepository();
    private final AuthorizationService authorizationService = new AuthorizationService();

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        return true;
    }

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        if (!authorizationService.canManageSystemSettings(InputProcessor.getUserRole(req))) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "Platform Admin only.");
            return;
        }

        JsonNode body = InputProcessor.getInput(req);
        String func = body.path("_func").asText("");
        try {
            switch (func) {
                case "get_settings":
                    getSettings(res);
                    break;
                case "update_settings":
                    updateSettings(body, res);
                    break;
                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Unknown _func: " + func);
            }
        } catch (Exception e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", e.getMessage());
        }
    }

    /** Secrets are never sent back to the browser - only whether one is currently configured. */
    private void getSettings(HttpServletResponse res) throws Exception {
        SystemSettingsRepository.SystemSettingsRecord settings = settingsRepository.get();
        OutputProcessor.send(res, HttpServletResponse.SC_OK, toJson(settings));
    }

    /**
     * Blank/omitted secret fields (s3SecretKey, privacyVaultApiKey) leave
     * the existing stored value unchanged - the console never round-trips a
     * secret in plaintext, so "I didn't type anything" must not overwrite
     * it with blank. Every other field is a full replace (blank/omitted =
     * clear it back to "fall back to the env var").
     */
    private void updateSettings(JsonNode body, HttpServletResponse res) throws Exception {
        SystemSettingsRepository.SystemSettingsRecord existing = settingsRepository.get();

        String s3SecretKey = body.hasNonNull("s3SecretKey") && !body.get("s3SecretKey").asText().isBlank()
                ? body.get("s3SecretKey").asText() : existing.s3SecretKey();
        String privacyVaultApiKey = body.hasNonNull("privacyVaultApiKey") && !body.get("privacyVaultApiKey").asText().isBlank()
                ? body.get("privacyVaultApiKey").asText() : existing.privacyVaultApiKey();

        SystemSettingsRepository.SystemSettingsRecord updated = new SystemSettingsRepository.SystemSettingsRecord(
                blankToNull(body.path("defaultStorageProviderId").asText(null)),
                blankToNull(body.path("s3Endpoint").asText(null)),
                blankToNull(body.path("s3Region").asText(null)),
                blankToNull(body.path("s3Bucket").asText(null)),
                blankToNull(body.path("s3AccessKey").asText(null)),
                s3SecretKey,
                body.hasNonNull("s3PathStyleAccess") ? body.get("s3PathStyleAccess").asBoolean() : null,
                blankToNull(body.path("s3Sse").asText(null)),
                blankToNull(body.path("s3KmsKeyId").asText(null)),
                blankToNull(body.path("privacyVaultBaseUrl").asText(null)),
                privacyVaultApiKey,
                blankToNull(body.path("privacyVaultEntityCode").asText(null)));

        settingsRepository.update(updated);
        getSettings(res);
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }

    private ObjectNode toJson(SystemSettingsRepository.SystemSettingsRecord settings) {
        ObjectNode json = MAPPER.createObjectNode();
        json.put("defaultStorageProviderId", settings.defaultStorageProviderId());
        json.put("s3Endpoint", settings.s3Endpoint());
        json.put("s3Region", settings.s3Region());
        json.put("s3Bucket", settings.s3Bucket());
        json.put("s3AccessKey", settings.s3AccessKey());
        json.put("s3SecretKeyConfigured", settings.s3SecretKey() != null && !settings.s3SecretKey().isBlank());
        if (settings.s3PathStyleAccess() != null) {
            json.put("s3PathStyleAccess", settings.s3PathStyleAccess());
        } else {
            json.putNull("s3PathStyleAccess");
        }
        json.put("s3Sse", settings.s3Sse());
        json.put("s3KmsKeyId", settings.s3KmsKeyId());
        json.put("privacyVaultBaseUrl", settings.privacyVaultBaseUrl());
        json.put("privacyVaultApiKeyConfigured", settings.privacyVaultApiKey() != null && !settings.privacyVaultApiKey().isBlank());
        json.put("privacyVaultEntityCode", settings.privacyVaultEntityCode());
        return json;
    }
}
