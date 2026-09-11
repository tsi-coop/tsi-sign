package org.tsicoop.sign.service.v1;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.tsicoop.sign.framework.Action;
import org.tsicoop.sign.framework.InputProcessor;
import org.tsicoop.sign.framework.OutputProcessor;

/** §10.2 API Keys tab, RBAC-scoped per §10.9. funcs: list_keys, issue_key, revoke_key. */
public class Keys implements Action {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final AppRepository appRepository = new AppRepository();
    private final ApiKeyRepository apiKeyRepository = new ApiKeyRepository();
    private final AuthorizationService authorizationService = new AuthorizationService();

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        return true;
    }

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JsonNode body = InputProcessor.getInput(req);
        String func = body.path("_func").asText("");
        String role = InputProcessor.getUserRole(req);
        String userId = InputProcessor.getUserId(req);
        String appId = body.path("appId").asText(null);

        try {
            if (appId == null) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "appId is required.");
                return;
            }

            switch (func) {
                case "list_keys":
                    if (!authorizationService.canRead(role, userId, appId)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "You do not have access to this App.");
                        return;
                    }
                    listKeys(res, appId);
                    break;
                case "issue_key":
                    if (!authorizationService.canWrite(role, userId, appId)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "You do not have write access to this App.");
                        return;
                    }
                    issueKey(res, appId);
                    break;
                case "revoke_key":
                    if (!authorizationService.canWrite(role, userId, appId)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "You do not have write access to this App.");
                        return;
                    }
                    revokeKey(body, res, appId);
                    break;
                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Unknown _func: " + func);
            }
        } catch (Exception e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", e.getMessage());
        }
    }

    private void listKeys(HttpServletResponse res, String appId) throws Exception {
        if (appRepository.findById(appId).isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such App.");
            return;
        }
        ArrayNode array = MAPPER.createArrayNode();
        for (ApiKeyRepository.ApiKeyRecord key : apiKeyRepository.listForApp(appId)) {
            ObjectNode node = array.addObject();
            node.put("keyId", key.keyId());
            node.put("keyPrefix", key.keyPrefix());
            node.put("isActive", key.isActive());
            node.put("createdAt", key.createdAt());
            node.put("revokedAt", key.revokedAt());
        }
        OutputProcessor.send(res, HttpServletResponse.SC_OK, array);
    }

    private void issueKey(HttpServletResponse res, String appId) throws Exception {
        if (appRepository.findById(appId).isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such App.");
            return;
        }
        var key = apiKeyRepository.issue(appId);
        ObjectNode json = MAPPER.createObjectNode();
        json.put("apiKey", key.rawKey());
        json.put("keyPrefix", key.keyPrefix());
        OutputProcessor.send(res, HttpServletResponse.SC_CREATED, json);
    }

    private void revokeKey(JsonNode body, HttpServletResponse res, String appId) throws Exception {
        String keyId = body.path("keyId").asText(null);
        if (keyId == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "keyId is required.");
            return;
        }
        boolean revoked = apiKeyRepository.revoke(appId, keyId);
        if (!revoked) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such active key for this App.");
            return;
        }
        OutputProcessor.send(res, HttpServletResponse.SC_OK, MAPPER.createObjectNode().put("status", "revoked"));
    }
}
