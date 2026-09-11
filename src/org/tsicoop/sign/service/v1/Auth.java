package org.tsicoop.sign.service.v1;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.mindrot.jbcrypt.BCrypt;
import org.tsicoop.sign.framework.Action;
import org.tsicoop.sign.framework.InputProcessor;
import org.tsicoop.sign.framework.OutputProcessor;

import java.util.Optional;

/**
 * PUBLIC at the filter (§6) — login is genuinely public; logout/me self-gate
 * on "is there a session" internally, same as Ledger's Auth service.
 * funcs: login, logout, me.
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
        HttpSession session = req.getSession(true);
        session.setAttribute(InputProcessor.SESSION_USER_ID, user.userId());
        session.setAttribute(InputProcessor.SESSION_USER_ROLE, user.role());
        session.setAttribute(InputProcessor.SESSION_USER_EMAIL, user.email());
        session.setAttribute(InputProcessor.SESSION_USER_NAME, user.fullName());

        OutputProcessor.send(res, HttpServletResponse.SC_OK, userJson(user));
    }

    private void logout(HttpServletRequest req, HttpServletResponse res) {
        HttpSession session = req.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        OutputProcessor.send(res, HttpServletResponse.SC_OK, MAPPER.createObjectNode());
    }

    private void me(HttpServletRequest req, HttpServletResponse res) {
        if (!InputProcessor.resolveConsoleSession(req)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Not logged in.");
            return;
        }
        HttpSession session = req.getSession(false);
        ObjectNode json = MAPPER.createObjectNode();
        json.put("userId", (String) session.getAttribute(InputProcessor.SESSION_USER_ID));
        json.put("email", (String) session.getAttribute(InputProcessor.SESSION_USER_EMAIL));
        json.put("fullName", (String) session.getAttribute(InputProcessor.SESSION_USER_NAME));
        json.put("role", (String) session.getAttribute(InputProcessor.SESSION_USER_ROLE));
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
