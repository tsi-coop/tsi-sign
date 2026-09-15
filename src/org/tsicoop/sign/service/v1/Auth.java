package org.tsicoop.sign.service.v1;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.mindrot.jbcrypt.BCrypt;
import org.tsicoop.sign.framework.Action;
import org.tsicoop.sign.framework.InputProcessor;
import org.tsicoop.sign.framework.JWTUtil;
import org.tsicoop.sign.framework.OutputProcessor;
import org.tsicoop.sign.framework.TokenBlocklist;

import java.util.Optional;

/**
 * PUBLIC at the filter (§6) — login is genuinely public; logout/me self-gate
 * on "is there a valid session token" internally, same as Ledger's Auth
 * service. funcs: login, logout, me.
 *
 * Console sessions are stateless JWTs (JWTUtil, matches tsi-compass), not a
 * server-side HttpSession - a server restart doesn't force every logged-in
 * user to sign in again, since nothing about the session lives in server
 * memory. Trade-off: logout revokes via an in-memory jti blocklist
 * (TokenBlocklist), which itself doesn't survive a restart either.
 */
public class Auth implements Action {

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
                case "login":
                    login(req, res);
                    break;
                case "logout":
                    logout(req, res);
                    break;
                case "me":
                    me(req, res);
                    break;
                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Unknown _func: " + func);
            }
        } catch (Exception e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", e.getMessage());
        }
    }

    private void login(HttpServletRequest req, HttpServletResponse res) {
        JsonNode body = InputProcessor.getInput(req);
        String email = body.path("email").asText(null);
        String password = body.path("password").asText(null);

        Optional<PlatformUserRepository.PlatformUserRecord> userOpt =
                email != null ? userRepository.findByEmail(email) : Optional.empty();
        if (userOpt.isEmpty() || !BCrypt.checkpw(password == null ? "" : password, userOpt.get().passwordHash())) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Invalid email or password.");
            return;
        }

        PlatformUserRepository.PlatformUserRecord user = userOpt.get();
        String token = JWTUtil.generateToken(user.userId(), user.email(), user.fullName(), user.role());

        ObjectNode json = userJson(user);
        json.put("token", token);
        OutputProcessor.send(res, HttpServletResponse.SC_OK, json);
    }

    /** Revokes the presented token's jti so it can't be reused, even though it hasn't naturally expired yet. */
    private void logout(HttpServletRequest req, HttpServletResponse res) {
        String token = InputProcessor.extractBearerToken(req);
        if (JWTUtil.isTokenValid(token)) {
            String jti = JWTUtil.getJtiFromToken(token);
            if (jti != null) {
                TokenBlocklist.revoke(jti, JWTUtil.getExpiryFromToken(token).getTime());
            }
        }
        OutputProcessor.send(res, HttpServletResponse.SC_OK, MAPPER.createObjectNode());
    }

    private void me(HttpServletRequest req, HttpServletResponse res) {
        if (!InputProcessor.resolveConsoleSession(req)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Not logged in.");
            return;
        }
        ObjectNode json = MAPPER.createObjectNode();
        json.put("userId", InputProcessor.getUserId(req));
        json.put("email", InputProcessor.getUserEmail(req));
        json.put("fullName", InputProcessor.getUserFullName(req));
        json.put("role", InputProcessor.getUserRole(req));
        OutputProcessor.send(res, HttpServletResponse.SC_OK, json);
    }

    private ObjectNode userJson(PlatformUserRepository.PlatformUserRecord user) {
        ObjectNode json = MAPPER.createObjectNode();
        json.put("userId", user.userId());
        json.put("email", user.email());
        json.put("fullName", user.fullName());
        json.put("role", user.role());
        return json;
    }
}
