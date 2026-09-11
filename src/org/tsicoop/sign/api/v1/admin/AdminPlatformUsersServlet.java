package org.tsicoop.sign.api.v1.admin;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.mindrot.jbcrypt.BCrypt;
import org.tsicoop.sign.admin.AdminAuthorizationService;
import org.tsicoop.sign.admin.AppAdminRepository;
import org.tsicoop.sign.admin.PlatformUserRepository;
import org.tsicoop.sign.security.ConsoleSessionAuthenticationFilter;

import java.io.IOException;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * §10.7 Platform Users & Roles — PLATFORM_ADMIN only (§10.9): platform_users
 * CRUD and app_admins assignment (which Apps an APP_MANAGER administers).
 */
public class AdminPlatformUsersServlet extends HttpServlet {

    private static final Pattern DEACTIVATE = Pattern.compile("^/([^/]+)/deactivate$");
    private static final Pattern ACTIVATE = Pattern.compile("^/([^/]+)/activate$");
    private static final Pattern APPS = Pattern.compile("^/([^/]+)/apps$");
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final PlatformUserRepository userRepository = new PlatformUserRepository();
    private final AppAdminRepository appAdminRepository = new AppAdminRepository();
    private final AdminAuthorizationService authorizationService = new AdminAuthorizationService();

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res) throws IOException {
        if (!authorizationService.canManagePlatformUsers(ConsoleSessionAuthenticationFilter.getRole(req))) {
            writeError(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "Platform Admin only.");
            return;
        }
        String pathInfo = req.getPathInfo();
        try {
            if (pathInfo == null || pathInfo.equals("/")) {
                listUsers(res);
                return;
            }
            Matcher appsMatcher = APPS.matcher(pathInfo);
            if (appsMatcher.matches()) {
                listAppsForUser(res, appsMatcher.group(1));
                return;
            }
            writeError(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such platform-users route.");
        } catch (Exception e) {
            writeError(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", e.getMessage());
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse res) throws IOException {
        if (!authorizationService.canManagePlatformUsers(ConsoleSessionAuthenticationFilter.getRole(req))) {
            writeError(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "Platform Admin only.");
            return;
        }
        String pathInfo = req.getPathInfo();
        try {
            if (pathInfo == null || pathInfo.equals("/")) {
                createUser(req, res);
                return;
            }
            Matcher deactivateMatcher = DEACTIVATE.matcher(pathInfo);
            if (deactivateMatcher.matches()) {
                userRepository.setActive(deactivateMatcher.group(1), false);
                writeJson(res, HttpServletResponse.SC_OK, MAPPER.createObjectNode().put("status", "deactivated"));
                return;
            }
            Matcher activateMatcher = ACTIVATE.matcher(pathInfo);
            if (activateMatcher.matches()) {
                userRepository.setActive(activateMatcher.group(1), true);
                writeJson(res, HttpServletResponse.SC_OK, MAPPER.createObjectNode().put("status", "activated"));
                return;
            }
            Matcher appsMatcher = APPS.matcher(pathInfo);
            if (appsMatcher.matches()) {
                updateAppAssignment(req, res, appsMatcher.group(1));
                return;
            }
            writeError(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such platform-users route.");
        } catch (Exception e) {
            writeError(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", e.getMessage());
        }
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
        res.setStatus(HttpServletResponse.SC_OK);
        res.setContentType("application/json");
        res.setCharacterEncoding("UTF-8");
        MAPPER.writeValue(res.getWriter(), array);
    }

    private void createUser(HttpServletRequest req, HttpServletResponse res) throws Exception {
        JsonNode body = MAPPER.readTree(req.getInputStream());
        String email = body.path("email").asText(null);
        String fullName = body.path("fullName").asText(null);
        String password = body.path("password").asText(null);
        String role = body.path("role").asText("APP_MANAGER");

        if (email == null || fullName == null || password == null || password.length() < 8) {
            writeError(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request",
                    "email, fullName, and a password of at least 8 characters are required.");
            return;
        }
        if (!role.equals("PLATFORM_ADMIN") && !role.equals("APP_MANAGER") && !role.equals("AUDITOR")) {
            writeError(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "Invalid role.");
            return;
        }

        String passwordHash = BCrypt.hashpw(password, BCrypt.gensalt());
        String userId = userRepository.create(email, fullName, passwordHash, role);

        ObjectNode json = MAPPER.createObjectNode();
        json.put("userId", userId);
        json.put("email", email);
        json.put("role", role);
        writeJson(res, HttpServletResponse.SC_CREATED, json);
    }

    private void listAppsForUser(HttpServletResponse res, String userId) throws Exception {
        Optional<PlatformUserRepository.PlatformUserRecord> userOpt = userRepository.findById(userId);
        if (userOpt.isEmpty()) {
            writeError(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such platform user.");
            return;
        }
        ArrayNode array = MAPPER.createArrayNode();
        for (String appId : appAdminRepository.listAppIdsForUser(userId)) {
            array.add(appId);
        }
        res.setStatus(HttpServletResponse.SC_OK);
        res.setContentType("application/json");
        res.setCharacterEncoding("UTF-8");
        MAPPER.writeValue(res.getWriter(), array);
    }

    private void updateAppAssignment(HttpServletRequest req, HttpServletResponse res, String userId) throws Exception {
        if (userRepository.findById(userId).isEmpty()) {
            writeError(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such platform user.");
            return;
        }
        JsonNode body = MAPPER.readTree(req.getInputStream());
        String appId = body.path("appId").asText(null);
        boolean assign = body.path("assign").asBoolean(true);
        if (appId == null) {
            writeError(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "appId is required.");
            return;
        }
        if (assign) {
            appAdminRepository.assign(appId, userId);
        } else {
            appAdminRepository.unassign(appId, userId);
        }
        writeJson(res, HttpServletResponse.SC_OK, MAPPER.createObjectNode().put("status", "updated"));
    }

    private void writeJson(HttpServletResponse res, int status, ObjectNode json) throws IOException {
        res.setStatus(status);
        res.setContentType("application/json");
        res.setCharacterEncoding("UTF-8");
        MAPPER.writeValue(res.getWriter(), json);
    }

    private void writeError(HttpServletResponse res, int status, String error, String message) throws IOException {
        ObjectNode json = MAPPER.createObjectNode();
        json.put("error", error);
        json.put("message", message);
        writeJson(res, status, json);
    }
}
