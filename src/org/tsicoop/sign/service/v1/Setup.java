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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Optional;

/**
 * PUBLIC (§6, §12 resolved): one-time first-admin setup, mirroring TSI
 * Ledger's Setup.initial_setup pattern — works only while platform_users is
 * empty, 409s forever after the first PLATFORM_ADMIN is created.
 * Because this is reachable without credentials, "setup" also requires the
 * operator-supplied TSI_BOOTSTRAP_TOKEN (no default: unset means the endpoint
 * refuses every request, 503, instead of falling back to open access).
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
        JsonNode body = InputProcessor.getInput(req);

        // Token first, before any DB access: a caller without it learns nothing, not even
        // whether the system is already configured.
        String expectedToken = System.getenv("TSI_BOOTSTRAP_TOKEN");
        if (expectedToken == null || expectedToken.isBlank()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_SERVICE_UNAVAILABLE, "Service Unavailable",
                    "First-run setup is disabled: TSI_BOOTSTRAP_TOKEN is not configured on the server.");
            return;
        }
        String suppliedToken = body.path("setupToken").asText("");
        if (!MessageDigest.isEqual(suppliedToken.getBytes(StandardCharsets.UTF_8),
                expectedToken.getBytes(StandardCharsets.UTF_8))) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized",
                    "Invalid setup token.");
            return;
        }

        if (userRepository.anyExists()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict",
                    "Setup has already completed; log in instead.");
            return;
        }

        String email = body.path("email").asText(null);
        String fullName = body.path("fullName").asText(null);
        String password = body.path("password").asText(null);
        if (email == null || fullName == null || password == null || password.length() < 8) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request",
                    "email, fullName, and a password of at least 8 characters are required.");
            return;
        }

        String passwordHash = BCrypt.hashpw(password, BCrypt.gensalt());
        Optional<String> created = userRepository.createIfNoneExist(email, fullName, passwordHash, "PLATFORM_ADMIN");
        if (created.isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict",
                    "Setup has already completed; log in instead.");
            return;
        }
        String userId = created.get();

        ObjectNode json = MAPPER.createObjectNode();
        json.put("userId", userId);
        json.put("email", email);
        json.put("role", "PLATFORM_ADMIN");
        OutputProcessor.send(res, HttpServletResponse.SC_CREATED, json);
    }
}
