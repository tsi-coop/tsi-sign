package org.tsicoop.sign.service.v1;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.mindrot.jbcrypt.BCrypt;
import org.tsicoop.sign.framework.Action;
import org.tsicoop.sign.framework.InputProcessor;
import org.tsicoop.sign.framework.OutputProcessor;

import java.util.Optional;

/**
 * §10.7 Platform Users & Roles — PLATFORM_ADMIN only (§10.9): platform_users
 * CRUD and app_admins assignment (which Apps an APP_MANAGER administers).
 * funcs: list_users, create_user, activate_user, deactivate_user,
 * list_user_apps, update_user_app_assignment.
 */
public class PlatformUsers implements Action {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final PlatformUserRepository userRepository = new PlatformUserRepository();
    private final AppAdminRepository appAdminRepository = new AppAdminRepository();
    private final AuthorizationService authorizationService = new AuthorizationService();

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        return true;
    }

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        if (!authorizationService.canManagePlatformUsers(InputProcessor.getUserRole(req))) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "Platform Admin only.");
            return;
        }

        JsonNode body = InputProcessor.getInput(req);
        String func = body.path("_func").asText("");
        try {
            switch (func) {
                case "list_users":
                    listUsers(res);
                    break;
                case "create_user":
                    createUser(body, res);
                    break;
                case "activate_user":
                    userRepository.setActive(requireUserId(body, res), true);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, MAPPER.createObjectNode().put("status", "activated"));
                    break;
                case "deactivate_user":
                    userRepository.setActive(requireUserId(body, res), false);
                    OutputProcessor.send(res, HttpServletResponse.SC_OK, MAPPER.createObjectNode().put("status", "deactivated"));
                    break;
                case "list_user_apps":
                    listUserApps(body, res);
                    break;
                case "update_user_app_assignment":
                    updateUserAppAssignment(body, res);
                    break;
                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Unknown _func: " + func);
            }
        } catch (Exception e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", e.getMessage());
        }
    }

    private String requireUserId(JsonNode body, HttpServletResponse res) {
        return body.path("userId").asText(null);
    }

    private void listUsers(HttpServletResponse res) throws Exception {
        ArrayNode array = MAPPER.createArrayNode();
        for (PlatformUserRepository.PlatformUserRecord user : userRepository.listAll()) {
            ObjectNode node = array.addObject();
            node.put("userId", user.userId());
            node.put("email", user.email());
            node.put("fullName", user.fullName());
            node.put("role", user.role());
            node.put("isActive", user.isActive());
        }
        OutputProcessor.send(res, HttpServletResponse.SC_OK, array);
    }

    private void createUser(JsonNode body, HttpServletResponse res) throws Exception {
        String email = body.path("email").asText(null);
        String fullName = body.path("fullName").asText(null);
        String password = body.path("password").asText(null);
        String role = body.path("role").asText("APP_MANAGER");

        if (email == null || fullName == null || password == null || password.length() < 8) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request",
                    "email, fullName, and a password of at least 8 characters are required.");
            return;
        }
        if (!role.equals("PLATFORM_ADMIN") && !role.equals("APP_MANAGER") && !role.equals("AUDITOR")) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid role.");
            return;
        }

        String passwordHash = BCrypt.hashpw(password, BCrypt.gensalt());
        String userId = userRepository.create(email, fullName, passwordHash, role);

        ObjectNode json = MAPPER.createObjectNode();
        json.put("userId", userId);
        json.put("email", email);
        json.put("role", role);
        OutputProcessor.send(res, HttpServletResponse.SC_CREATED, json);
    }

    private void listUserApps(JsonNode body, HttpServletResponse res) throws Exception {
        String userId = body.path("userId").asText(null);
        if (userId == null || userRepository.findById(userId).isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such platform user.");
            return;
        }
        ArrayNode array = MAPPER.createArrayNode();
        for (String appId : appAdminRepository.listAppIdsForUser(userId)) {
            array.add(appId);
        }
        OutputProcessor.send(res, HttpServletResponse.SC_OK, array);
    }

    private void updateUserAppAssignment(JsonNode body, HttpServletResponse res) throws Exception {
        String userId = body.path("userId").asText(null);
        String appId = body.path("appId").asText(null);
        boolean assign = body.path("assign").asBoolean(true);
        if (userId == null || appId == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "userId and appId are required.");
            return;
        }
        if (userRepository.findById(userId).isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such platform user.");
            return;
        }
        if (assign) {
            appAdminRepository.assign(appId, userId);
        } else {
            appAdminRepository.unassign(appId, userId);
        }
        OutputProcessor.send(res, HttpServletResponse.SC_OK, MAPPER.createObjectNode().put("status", "updated"));
    }
}
