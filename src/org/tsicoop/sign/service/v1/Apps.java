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

import java.sql.SQLException;
import java.util.Optional;
import java.util.Set;

/**
 * §10.2 Apps / Signing Defaults / Admins, RBAC-scoped per §10.9 (Chunk 9).
 * funcs: create_app, list_apps, get_app, update_signing_defaults,
 * update_rate_limit, list_admins, add_admin, remove_admin.
 */
public class Apps implements Action {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final AppRepository appRepository = new AppRepository();
    private final ApiKeyRepository apiKeyRepository = new ApiKeyRepository();
    private final AppAdminRepository appAdminRepository = new AppAdminRepository();
    private final PlatformUserRepository platformUserRepository = new PlatformUserRepository();
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

        try {
            switch (func) {
                case "create_app":
                    if (!authorizationService.canCreateApp(role)) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "Only a Platform Admin can create Apps.");
                        return;
                    }
                    createApp(body, res);
                    return;
                case "list_apps":
                    listApps(body, res, role, userId);
                    return;
                default:
                    // Every remaining func takes an appId and is scoped by read/write RBAC.
                    break;
            }

            String appId = body.path("appId").asText(null);
            if (appId == null) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "appId is required.");
                return;
            }

            switch (func) {
                case "get_app":
                    if (!requireRead(res, role, userId, appId)) return;
                    getApp(res, appId);
                    break;
                case "update_signing_defaults":
                    if (!requireWrite(res, role, userId, appId)) return;
                    updateSigningDefaults(body, res, appId);
                    break;
                case "update_rate_limit":
                    if (!requireWrite(res, role, userId, appId)) return;
                    updateRateLimit(body, res, appId);
                    break;
                case "update_storage_provider":
                    if (!requireWrite(res, role, userId, appId)) return;
                    updateStorageProvider(body, res, appId);
                    break;
                case "list_admins":
                    if (!requireRead(res, role, userId, appId)) return;
                    listAdmins(res, appId);
                    break;
                case "add_admin":
                    if (!requireWrite(res, role, userId, appId)) return;
                    addAdmin(body, res, appId);
                    break;
                case "remove_admin":
                    if (!requireWrite(res, role, userId, appId)) return;
                    removeAdmin(body, res, appId);
                    break;
                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Unknown _func: " + func);
            }
        } catch (Exception e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", e.getMessage());
        }
    }

    private boolean requireRead(HttpServletResponse res, String role, String userId, String appId) throws Exception {
        if (!authorizationService.canRead(role, userId, appId)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "You do not have access to this App.");
            return false;
        }
        return true;
    }

    private boolean requireWrite(HttpServletResponse res, String role, String userId, String appId) throws Exception {
        if (!authorizationService.canWrite(role, userId, appId)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "You do not have write access to this App.");
            return false;
        }
        return true;
    }

    private void createApp(JsonNode body, HttpServletResponse res) throws Exception {
        String appName = body.path("appName").asText(null);
        String appSlug = body.path("appSlug").asText(null);
        String defaultProviderId = body.path("defaultProviderId").asText(null);
        String defaultKeyAlias = body.path("defaultKeyAlias").asText(null);
        String webhookUrl = body.path("webhookUrl").asText(null);

        if (appName == null || appSlug == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "appName and appSlug are required.");
            return;
        }

        String appId;
        try {
            appId = appRepository.create(appName, appSlug, defaultProviderId, defaultKeyAlias, webhookUrl);
        } catch (SQLException e) {
            if ("23505".equals(e.getSQLState())) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict", "appSlug is already in use.");
                return;
            }
            throw e;
        }

        var pair = apiKeyRepository.issue(appId);

        ObjectNode json = MAPPER.createObjectNode();
        json.put("appId", appId);
        json.put("appName", appName);
        json.put("appSlug", appSlug);
        json.put("apiKey", pair.apiKey());
        json.put("apiSecret", pair.apiSecret());
        json.put("warning", "Store the API secret now - it is shown only once and cannot be retrieved again.");
        OutputProcessor.send(res, HttpServletResponse.SC_CREATED, json);
    }

    /** Dashboard/Apps list (§10.1, §10.9): APP_MANAGER sees only their scoped Apps. Paginated. */
    private void listApps(JsonNode body, HttpServletResponse res, String role, String userId) throws Exception {
        Set<String> scopedAppIds = "APP_MANAGER".equals(role) ? appAdminRepository.listAppIdsForUser(userId) : null;

        InputProcessor.Page paging = InputProcessor.parsePaging(body);
        ArrayNode array = MAPPER.createArrayNode();
        for (AppRepository.AppRecord app : appRepository.list(scopedAppIds, paging.page(), paging.pageSize())) {
            array.add(toJson(app));
        }
        int totalCount = appRepository.count(scopedAppIds);
        ObjectNode json = MAPPER.createObjectNode();
        json.set("apps", array);
        json.put("totalCount", totalCount);
        json.put("page", paging.page());
        json.put("pageSize", paging.pageSize());
        json.put("totalPages", Math.max(1, (totalCount + paging.pageSize() - 1) / paging.pageSize()));
        OutputProcessor.send(res, HttpServletResponse.SC_OK, json);
    }

    private void getApp(HttpServletResponse res, String appId) throws Exception {
        Optional<AppRepository.AppRecord> appOpt = appRepository.findById(appId);
        if (appOpt.isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such App.");
            return;
        }
        OutputProcessor.send(res, HttpServletResponse.SC_OK, toJson(appOpt.get()));
    }

    private void updateSigningDefaults(JsonNode body, HttpServletResponse res, String appId) throws Exception {
        if (appRepository.findById(appId).isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such App.");
            return;
        }
        appRepository.updateSigningDefaults(appId,
                body.path("defaultProviderId").asText(null),
                body.path("defaultKeyAlias").asText(null),
                body.path("webhookUrl").asText(null));
        OutputProcessor.send(res, HttpServletResponse.SC_OK, MAPPER.createObjectNode().put("status", "updated"));
    }

    private void updateRateLimit(JsonNode body, HttpServletResponse res, String appId) throws Exception {
        if (appRepository.findById(appId).isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such App.");
            return;
        }
        Integer rateLimitRpm = body.hasNonNull("rateLimitRpm") ? body.get("rateLimitRpm").asInt() : null;
        appRepository.updateRateLimit(appId, rateLimitRpm);
        OutputProcessor.send(res, HttpServletResponse.SC_OK, MAPPER.createObjectNode().put("status", "updated"));
    }

    /** Chunk 12, §5.2: per-App storage backend override (null = deployment-wide default). */
    private void updateStorageProvider(JsonNode body, HttpServletResponse res, String appId) throws Exception {
        if (appRepository.findById(appId).isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such App.");
            return;
        }
        appRepository.updateStorageProvider(appId, body.path("storageProviderId").asText(null));
        OutputProcessor.send(res, HttpServletResponse.SC_OK, MAPPER.createObjectNode().put("status", "updated"));
    }

    private void listAdmins(HttpServletResponse res, String appId) throws Exception {
        if (appRepository.findById(appId).isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such App.");
            return;
        }
        ArrayNode array = MAPPER.createArrayNode();
        for (AppAdminRepository.AssignedUser user : appAdminRepository.listUsersForApp(appId)) {
            ObjectNode node = array.addObject();
            node.put("userId", user.userId());
            node.put("email", user.email());
            node.put("fullName", user.fullName());
        }
        OutputProcessor.send(res, HttpServletResponse.SC_OK, array);
    }

    private void addAdmin(JsonNode body, HttpServletResponse res, String appId) throws Exception {
        if (appRepository.findById(appId).isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such App.");
            return;
        }
        String targetUserId = body.path("userId").asText(null);
        if (targetUserId == null || platformUserRepository.findById(targetUserId).isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "A valid userId is required.");
            return;
        }
        appAdminRepository.assign(appId, targetUserId);
        OutputProcessor.send(res, HttpServletResponse.SC_OK, MAPPER.createObjectNode().put("status", "assigned"));
    }

    private void removeAdmin(JsonNode body, HttpServletResponse res, String appId) throws Exception {
        String targetUserId = body.path("userId").asText(null);
        if (targetUserId == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "userId is required.");
            return;
        }
        appAdminRepository.unassign(appId, targetUserId);
        OutputProcessor.send(res, HttpServletResponse.SC_OK, MAPPER.createObjectNode().put("status", "removed"));
    }

    private ObjectNode toJson(AppRepository.AppRecord app) {
        ObjectNode node = MAPPER.createObjectNode();
        node.put("appId", app.appId());
        node.put("appName", app.appName());
        node.put("appSlug", app.appSlug());
        node.put("isActive", app.isActive());
        node.put("defaultProviderId", app.defaultProviderId());
        node.put("defaultKeyAlias", app.defaultKeyAlias());
        node.put("webhookUrl", app.webhookUrl());
        node.put("storageProviderId", app.storageProviderId());
        if (app.rateLimitRpm() != null) {
            node.put("rateLimitRpm", app.rateLimitRpm());
        } else {
            node.putNull("rateLimitRpm");
        }
        node.put("createdAt", app.createdAt());
        return node;
    }
}
