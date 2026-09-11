package org.tsicoop.sign.framework;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

/**
 * Request plumbing shared by every Action (TSI framework standard pattern):
 * body -> JSON, and the two auth models TSI Sign uses —
 *  - TENANT: an App's X-API-Key, hashed and looked up against api_keys (§6).
 *  - CONSOLE: a platform_user's HttpSession, set by AdminAuth.login (§10).
 */
public class InputProcessor {

    public static final String REQUEST_JSON_ATTR = "org.tsicoop.sign.input";
    public static final String APP_CONTEXT_ATTR = "org.tsicoop.sign.AppContext";

    public static final String SESSION_USER_ID = "platformUserId";
    public static final String SESSION_USER_ROLE = "platformUserRole";
    public static final String SESSION_USER_EMAIL = "platformUserEmail";
    public static final String SESSION_USER_NAME = "platformUserName";

    private static final String API_KEY_HEADER = "X-API-Key";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static void processInput(HttpServletRequest req) {
        try {
            JsonNode json = MAPPER.readTree(req.getInputStream());
            req.setAttribute(REQUEST_JSON_ATTR, (json == null || json.isMissingNode() || json.isNull())
                    ? MAPPER.createObjectNode() : json);
        } catch (Exception e) {
            req.setAttribute(REQUEST_JSON_ATTR, MAPPER.createObjectNode());
        }
    }

    public static JsonNode getInput(HttpServletRequest req) {
        return (JsonNode) req.getAttribute(REQUEST_JSON_ATTR);
    }

    /** Hashes X-API-Key and resolves it to an active App (§6). Sets APP_CONTEXT_ATTR on success. */
    public static boolean resolveTenantApp(HttpServletRequest req) {
        String rawApiKey = req.getHeader(API_KEY_HEADER);
        if (rawApiKey == null || rawApiKey.isBlank()) {
            return false;
        }

        String keyHash = ApiKeyGenerator.sha256Hex(rawApiKey);
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = null;
        try {
            pool = new PoolDB();
            con = pool.getConnection();
            ps = con.prepareStatement("SELECT a.app_id, a.app_name, a.app_slug, a.rate_limit_rpm " +
                    "FROM api_keys k JOIN apps a ON a.app_id = k.app_id " +
                    "WHERE k.key_hash = ? AND k.is_active = TRUE AND a.is_active = TRUE");
            ps.setString(1, keyHash);
            rs = ps.executeQuery();
            if (rs.next()) {
                int rpm = rs.getInt("rate_limit_rpm");
                Integer rateLimitRpm = rs.wasNull() ? null : rpm;
                AppContext appContext = new AppContext(
                        rs.getString("app_id"), rs.getString("app_name"), rs.getString("app_slug"), rateLimitRpm);
                req.setAttribute(APP_CONTEXT_ATTR, appContext);
                return true;
            }
        } catch (Exception e) {
            System.err.println("InputProcessor.resolveTenantApp: " + e.getMessage());
        } finally {
            if (pool != null) pool.cleanup(rs, ps, con);
        }
        return false;
    }

    public static AppContext getAppContext(HttpServletRequest req) {
        return (AppContext) req.getAttribute(APP_CONTEXT_ATTR);
    }

    /** True if a platform_user session already exists (set by AdminAuth.login). Never creates one. */
    public static boolean resolveConsoleSession(HttpServletRequest req) {
        HttpSession session = req.getSession(false);
        return session != null && session.getAttribute(SESSION_USER_ID) != null;
    }

    public static String getUserId(HttpServletRequest req) {
        HttpSession session = req.getSession(false);
        return session != null ? (String) session.getAttribute(SESSION_USER_ID) : null;
    }

    public static String getUserRole(HttpServletRequest req) {
        HttpSession session = req.getSession(false);
        return session != null ? (String) session.getAttribute(SESSION_USER_ROLE) : null;
    }
}
