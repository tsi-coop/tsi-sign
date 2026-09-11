package org.tsicoop.sign.service.v1;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.mindrot.jbcrypt.BCrypt;
import org.tsicoop.sign.framework.Action;
import org.tsicoop.sign.framework.InputProcessor;
import org.tsicoop.sign.framework.OutputProcessor;

/**
 * PUBLIC (§6, §12 resolved): one-time first-admin setup, mirroring TSI
 * Ledger's Setup.initial_setup pattern — works only while platform_users is
 * empty, 409s forever after the first PLATFORM_ADMIN is created.
 * funcs: setup_status, setup.
 */
public class Setup implements Action {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private final PlatformUserRepository userRepository = new PlatformUserRepository();

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        return true;
    }

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        String func = InputProcessor.getInput(req).path("_func").asText("");
        try {
            switch (func) {
                case "setup_status":
                    setupStatus(res);
                    break;
                case "setup":
                    setup(req, res);
                    break;
                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Unknown _func: " + func);
            }
        } catch (Exception e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", e.getMessage());
        }
    }

    private void setupStatus(HttpServletResponse res) throws Exception {
        ObjectNode json = MAPPER.createObjectNode();
        json.put("initialized", userRepository.anyExists());
        OutputProcessor.send(res, HttpServletResponse.SC_OK, json);
    }

    private void setup(HttpServletRequest req, HttpServletResponse res) throws Exception {
        if (userRepository.anyExists()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict",
                    "Setup has already completed; log in instead.");
            return;
        }

        JsonNode body = InputProcessor.getInput(req);
        String email = body.path("email").asText(null);
        String fullName = body.path("fullName").asText(null);
        String password = body.path("password").asText(null);
        if (email == null || fullName == null || password == null || password.length() < 8) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request",
                    "email, fullName, and a password of at least 8 characters are required.");
            return;
        }

        String passwordHash = BCrypt.hashpw(password, BCrypt.gensalt());
        String userId = userRepository.create(email, fullName, passwordHash, "PLATFORM_ADMIN");

        ObjectNode json = MAPPER.createObjectNode();
        json.put("userId", userId);
        json.put("email", email);
        json.put("role", "PLATFORM_ADMIN");
        OutputProcessor.send(res, HttpServletResponse.SC_CREATED, json);
    }
}
