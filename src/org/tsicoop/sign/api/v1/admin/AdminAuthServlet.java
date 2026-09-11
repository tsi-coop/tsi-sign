package org.tsicoop.sign.api.v1.admin;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.mindrot.jbcrypt.BCrypt;
import org.tsicoop.sign.admin.PlatformUserRepository;
import org.tsicoop.sign.security.ConsoleSessionAuthenticationFilter;

import java.io.IOException;
import java.util.Optional;

/**
 * POST /api/v1/admin/auth/login  (PUBLIC)
 * POST /api/v1/admin/auth/logout (CONSOLE)
 * GET  /api/v1/admin/auth/me     (CONSOLE)
 */
public class AdminAuthServlet extends HttpServlet {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private final PlatformUserRepository userRepository = new PlatformUserRepository();

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String pathInfo = req.getPathInfo();
        if ("/login".equals(pathInfo)) {
            login(req, res);
        } else if ("/logout".equals(pathInfo)) {
            logout(req, res);
        } else {
            writeError(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such auth route.");
        }
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res) throws IOException {
        if ("/me".equals(req.getPathInfo())) {
            me(req, res);
        } else {
            writeError(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such auth route.");
        }
    }

    private void login(HttpServletRequest req, HttpServletResponse res) throws IOException {
        JsonNode body = MAPPER.readTree(req.getInputStream());
        String email = body.path("email").asText(null);
        String password = body.path("password").asText(null);

        Optional<PlatformUserRepository.PlatformUserRecord> userOpt =
                email != null ? userRepository.findByEmail(email) : Optional.empty();
        if (userOpt.isEmpty() || !BCrypt.checkpw(password == null ? "" : password, userOpt.get().passwordHash())) {
            writeError(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", "Invalid email or password.");
            return;
        }

        PlatformUserRepository.PlatformUserRecord user = userOpt.get();
        HttpSession session = req.getSession(true);
        session.setAttribute(ConsoleSessionAuthenticationFilter.SESSION_USER_ID, user.userId());
        session.setAttribute(ConsoleSessionAuthenticationFilter.SESSION_USER_ROLE, user.role());
        session.setAttribute(ConsoleSessionAuthenticationFilter.SESSION_USER_EMAIL, user.email());
        session.setAttribute(ConsoleSessionAuthenticationFilter.SESSION_USER_NAME, user.fullName());

        writeUser(res, HttpServletResponse.SC_OK, user);
    }

    private void logout(HttpServletRequest req, HttpServletResponse res) throws IOException {
        HttpSession session = req.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        writeJson(res, HttpServletResponse.SC_OK, MAPPER.createObjectNode());
    }

    private void me(HttpServletRequest req, HttpServletResponse res) throws IOException {
        HttpSession session = req.getSession(false);
        ObjectNode json = MAPPER.createObjectNode();
        json.put("userId", (String) session.getAttribute(ConsoleSessionAuthenticationFilter.SESSION_USER_ID));
        json.put("email", (String) session.getAttribute(ConsoleSessionAuthenticationFilter.SESSION_USER_EMAIL));
        json.put("fullName", (String) session.getAttribute(ConsoleSessionAuthenticationFilter.SESSION_USER_NAME));
        json.put("role", (String) session.getAttribute(ConsoleSessionAuthenticationFilter.SESSION_USER_ROLE));
        writeJson(res, HttpServletResponse.SC_OK, json);
    }

    private void writeUser(HttpServletResponse res, int status, PlatformUserRepository.PlatformUserRecord user)
            throws IOException {
        ObjectNode json = MAPPER.createObjectNode();
        json.put("userId", user.userId());
        json.put("email", user.email());
        json.put("fullName", user.fullName());
        json.put("role", user.role());
        writeJson(res, status, json);
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
