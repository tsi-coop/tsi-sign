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

import java.util.Set;

/**
 * §10.9 Audit screen - CONSOLE only, cross-App audit_logs read. Every role
 * that can reach the console can see it: PLATFORM_ADMIN/AUDITOR see every
 * App's events, APP_MANAGER is scoped to their assigned Apps (AUDITOR
 * exists specifically for this kind of read-only visibility). funcs:
 * list_audit_logs.
 */
public class AuditLogs implements Action {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final AuditLogRepository auditLogRepository = new AuditLogRepository();
    private final AppAdminRepository appAdminRepository = new AppAdminRepository();

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        return true;
    }

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JsonNode body = InputProcessor.getInput(req);
        String func = body.path("_func").asText("");
        try {
            switch (func) {
                case "list_audit_logs":
                    listAuditLogs(req, body, res);
                    break;
                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Unknown _func: " + func);
            }
        } catch (Exception e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", e.getMessage());
        }
    }

    private void listAuditLogs(HttpServletRequest req, JsonNode body, HttpServletResponse res) throws Exception {
        String role = InputProcessor.getUserRole(req);
        String userId = InputProcessor.getUserId(req);
        Set<String> scopedAppIds = "APP_MANAGER".equals(role) ? appAdminRepository.listAppIdsForUser(userId) : null;

        String appIdFilter = body.path("appId").asText(null);
        if (appIdFilter != null && scopedAppIds != null && !scopedAppIds.contains(appIdFilter)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "You do not have access to this App.");
            return;
        }
        String eventType = body.path("eventType").asText(null);

        InputProcessor.Page paging = InputProcessor.parsePaging(body);
        ArrayNode array = MAPPER.createArrayNode();
        for (AuditLogRepository.AuditLogSummary entry :
                auditLogRepository.listAll(scopedAppIds, appIdFilter, eventType, paging.page(), paging.pageSize())) {
            ObjectNode node = array.addObject();
            node.put("auditId", entry.auditId());
            node.put("appId", entry.appId());
            node.put("appName", entry.appName());
            node.put("documentId", entry.documentId());
            node.put("documentTitle", entry.documentTitle());
            node.put("eventType", entry.eventType());
            node.put("actorType", entry.actorType());
            node.put("actorId", entry.actorId());
            node.put("actorName", entry.actorName());
            node.put("ipAddress", entry.ipAddress());
            node.put("createdAt", entry.createdAt());
        }
        int totalCount = auditLogRepository.countAll(scopedAppIds, appIdFilter, eventType);
        ObjectNode json = MAPPER.createObjectNode();
        json.set("auditLogs", array);
        json.put("totalCount", totalCount);
        json.put("page", paging.page());
        json.put("pageSize", paging.pageSize());
        json.put("totalPages", Math.max(1, (totalCount + paging.pageSize() - 1) / paging.pageSize()));
        OutputProcessor.send(res, HttpServletResponse.SC_OK, json);
    }
}
