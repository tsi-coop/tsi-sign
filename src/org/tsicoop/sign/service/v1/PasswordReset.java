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
import org.tsicoop.sign.framework.RecoveryKeyGenerator;

/**
 * PUBLIC (§6) — self-service "break glass" password reset via a recovery-key
 * passphrase a Platform Admin generated for this user (PlatformUsers.
 * set_recovery_key). Genuinely public/unauthenticated: this is exactly the
 * path a locked-out user needs when they have no session to present.
 * funcs: verify_recovery_key, reset_password_via_recovery.
 */
public class PasswordReset implements Action {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private final PlatformUserRepository userRepository = new PlatformUserRepository();

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
                case "verify_recovery_key":
                    verifyRecoveryKey(body, res);
                    break;
                case "reset_password_via_recovery":
                    resetPasswordViaRecovery(body, res);
                    break;
                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Unknown _func: " + func);
            }
        } catch (Exception e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", e.getMessage());
        }
    }

    private void verifyRecoveryKey(JsonNode body, HttpServletResponse res) throws Exception {
        String email = body.path("email").asText(null);
        String recoveryKey = body.path("recoveryKey").asText(null);
        if (email == null || recoveryKey == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "email and recoveryKey are required.");
            return;
        }
        boolean valid = userRepository.verifyRecoveryKey(email, RecoveryKeyGenerator.sha256Hex(recoveryKey));
        if (!valid) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Invalid email or recovery key.");
            return;
        }
        OutputProcessor.send(res, HttpServletResponse.SC_OK, MAPPER.createObjectNode().put("valid", true));
    }

    private void resetPasswordViaRecovery(JsonNode body, HttpServletResponse res) throws Exception {
        String email = body.path("email").asText(null);
        String recoveryKey = body.path("recoveryKey").asText(null);
        String newPassword = body.path("newPassword").asText(null);
        if (email == null || recoveryKey == null || newPassword == null || newPassword.length() < 8) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request",
                    "email, recoveryKey, and a newPassword of at least 8 characters are required.");
            return;
        }
        boolean valid = userRepository.verifyRecoveryKey(email, RecoveryKeyGenerator.sha256Hex(recoveryKey));
        if (!valid) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Invalid email or recovery key.");
            return;
        }
        userRepository.updatePasswordHash(email, BCrypt.hashpw(newPassword, BCrypt.gensalt()));
        ObjectNode json = MAPPER.createObjectNode();
        json.put("status", "reset");
        OutputProcessor.send(res, HttpServletResponse.SC_OK, json);
    }
}
