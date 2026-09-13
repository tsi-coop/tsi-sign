package org.tsicoop.sign.service.v1;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.tsicoop.sign.framework.Action;
import org.tsicoop.sign.framework.InputProcessor;
import org.tsicoop.sign.framework.OutputProcessor;

import java.util.List;
import java.util.Set;

/**
 * §10.1 Dashboard - aggregate counts across every App the caller can see:
 * every App for PLATFORM_ADMIN/AUDITOR, only assigned Apps for APP_MANAGER
 * (same scoping as Apps.listApps). funcs: get_stats.
 */
public class Dashboard implements Action {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final AppRepository appRepository = new AppRepository();
    private final AppAdminRepository appAdminRepository = new AppAdminRepository();
    private final TemplateRepository templateRepository = new TemplateRepository();
    private final DocumentRepository documentRepository = new DocumentRepository();

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
                case "get_stats":
                    getStats(res, role, userId);
                    return;
                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Unknown _func: " + func);
            }
        } catch (Exception e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", e.getMessage());
        }
    }

    private void getStats(HttpServletResponse res, String role, String userId) throws Exception {
        Set<String> scopedAppIds = "APP_MANAGER".equals(role) ? appAdminRepository.listAppIdsForUser(userId) : null;

        int totalApps = 0;
        int activeApps = 0;
        for (AppRepository.AppRecord app : appRepository.list()) {
            if (scopedAppIds != null && !scopedAppIds.contains(app.appId())) {
                continue;
            }
            totalApps++;
            if (app.isActive()) activeApps++;
        }

        ObjectNode json = MAPPER.createObjectNode();
        json.put("totalApps", totalApps);
        json.put("activeApps", activeApps);
        json.put("totalTemplates", templateRepository.countForApps(scopedAppIds));
        json.put("documentsSigned", documentRepository.countForApps(scopedAppIds, List.of("SIGNED")));
        json.put("documentsWaiting", documentRepository.countForApps(scopedAppIds, List.of("DRAFT", "PENDING")));
        OutputProcessor.send(res, HttpServletResponse.SC_OK, json);
    }
}
