package org.tsicoop.sign.api.v1.admin;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.mindrot.jbcrypt.BCrypt;
import org.tsicoop.sign.admin.PlatformUserRepository;

import java.io.IOException;

/**
 * PUBLIC (§6, §12 resolved): one-time first-admin setup, mirroring TSI
 * Ledger's Setup.initial_setup pattern — works only while platform_users is
 * empty, 409s forever after the first PLATFORM_ADMIN is created.
 *
 * GET  /api/v1/admin/setup-status -> { initialized: boolean }
 * POST /api/v1/admin/setup        -> create the first PLATFORM_ADMIN
 */
public class AdminSetupServlet extends HttpServlet {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private final PlatformUserRepository userRepository = new PlatformUserRepository();

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res) throws IOException {
        try {
            ObjectNode json = MAPPER.createObjectNode();
            json.put("initialized", userRepository.anyExists());
            writeJson(res, HttpServletResponse.SC_OK, json);
        } catch (Exception e) {
            writeError(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", e.getMessage());
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse res) throws IOException {
        try {
            if (userRepository.anyExists()) {
                writeError(res, HttpServletResponse.SC_CONFLICT, "Conflict",
                        "Setup has already completed; log in instead.");
                return;
            }

            JsonNode body = MAPPER.readTree(req.getInputStream());
            String email = body.path("email").asText(null);
            String fullName = body.path("fullName").asText(null);
            String password = body.path("password").asText(null);
            if (email == null || fullName == null || password == null || password.length() < 8) {
                writeError(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request",
                        "email, fullName, and a password of at least 8 characters are required.");
                return;
            }

            String passwordHash = BCrypt.hashpw(password, BCrypt.gensalt());
            String userId = userRepository.create(email, fullName, passwordHash, "PLATFORM_ADMIN");

            ObjectNode json = MAPPER.createObjectNode();
            json.put("userId", userId);
            json.put("email", email);
            json.put("role", "PLATFORM_ADMIN");
            writeJson(res, HttpServletResponse.SC_CREATED, json);
        } catch (Exception e) {
            writeError(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", e.getMessage());
        }
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
