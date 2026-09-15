package org.tsicoop.sign.framework;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

/**
 * Request plumbing shared by every Action (TSI framework standard pattern):
 * body -> JSON, and the two auth models TSI Sign uses —
 *  - TENANT: an App's X-API-Key + X-API-Secret, looked up against api_keys (§6).
 *  - CONSOLE: a platform_user's JWT (Authorization: Bearer ...), set by
 *    Auth.login - matches tsi-compass's JWTUtil pattern. Stateless: the
 *    token itself carries userId/email/fullName/role, decoded fresh per
 *    request into request attributes below, so a server restart doesn't
 *    invalidate anyone's session the way a plain HttpSession would (§10).
 */
public class InputProcessor {

    public static final String REQUEST_JSON_ATTR = "org.tsicoop.sign.input";
    public static final String APP_CONTEXT_ATTR = "org.tsicoop.sign.AppContext";

    private static final String REQUEST_USER_ID = "org.tsicoop.sign.userId";
    private static final String REQUEST_USER_ROLE = "org.tsicoop.sign.userRole";
    private static final String REQUEST_USER_EMAIL = "org.tsicoop.sign.userEmail";
    private static final String REQUEST_USER_NAME = "org.tsicoop.sign.userName";

    private static final String API_KEY_HEADER = "X-API-Key";
    private static final String API_SECRET_HEADER = "X-API-Secret";
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
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

    /**
     * Resolves an App from its X-API-Key + X-API-Secret pair (§6) - the
     * shared TSI-stack tenant-credential model (tsi-ledger's
     * resolveTenantApp is the canonical reference): X-API-Key is a
     * non-secret identifier used for the row lookup, X-API-Secret is the
     * real credential, hashed and compared against the stored
     * api_secret_hash for that row. Sets APP_CONTEXT_ATTR on success.
     */
    public static boolean resolveTenantApp(HttpServletRequest req) {
        String apiKey = req.getHeader(API_KEY_HEADER);
        String apiSecret = req.getHeader(API_SECRET_HEADER);
        if (apiKey == null || apiKey.isBlank() || apiSecret == null || apiSecret.isBlank()) {
            return false;
        }

        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = null;
        try {
            pool = new PoolDB();
            con = pool.getConnection();
            ps = con.prepareStatement("SELECT a.app_id, a.app_name, a.app_slug, a.rate_limit_rpm, k.api_secret_hash " +
                    "FROM api_keys k JOIN apps a ON a.app_id = k.app_id " +
                    "WHERE k.api_key = ? AND k.is_active = TRUE AND a.is_active = TRUE");
            ps.setString(1, apiKey);
            rs = ps.executeQuery();
            if (rs.next()) {
                if (!ApiKeyGenerator.sha256Hex(apiSecret).equals(rs.getString("api_secret_hash"))) {
                    return false;
                }
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

    /**
     * Resolves a platform_user from the Authorization: Bearer JWT (set by
     * Auth.login). Decodes the token fresh on every call - nothing is
     * cached server-side - and stashes the claims as request attributes so
     * getUserId/getUserRole/getUserEmail/getUserFullName can read them back
     * for the rest of this request without re-parsing the token.
     */
    public static boolean resolveConsoleSession(HttpServletRequest req) {
        String token = extractBearerToken(req);
        if (!JWTUtil.isTokenValid(token)) {
            return false;
        }
        req.setAttribute(REQUEST_USER_ID, JWTUtil.getUserIdFromToken(token));
        req.setAttribute(REQUEST_USER_ROLE, JWTUtil.getRoleFromToken(token));
        req.setAttribute(REQUEST_USER_EMAIL, JWTUtil.getEmailFromToken(token));
        req.setAttribute(REQUEST_USER_NAME, JWTUtil.getNameFromToken(token));
        return true;
    }

    /** The raw bearer token, for callers (Auth.logout) that need to revoke it rather than just validate it. */
    public static String extractBearerToken(HttpServletRequest req) {
        String header = req.getHeader(AUTHORIZATION_HEADER);
        if (header == null || !header.startsWith(BEARER_PREFIX)) {
            return null;
        }
        return header.substring(BEARER_PREFIX.length()).trim();
    }

    public static String getUserId(HttpServletRequest req) {
        return (String) req.getAttribute(REQUEST_USER_ID);
    }

    public static String getUserRole(HttpServletRequest req) {
        return (String) req.getAttribute(REQUEST_USER_ROLE);
    }

    public static String getUserEmail(HttpServletRequest req) {
        return (String) req.getAttribute(REQUEST_USER_EMAIL);
    }

    public static String getUserFullName(HttpServletRequest req) {
        return (String) req.getAttribute(REQUEST_USER_NAME);
    }

    public record Page(int page, int pageSize) {
    }

    /**
     * Shared list-endpoint pagination convention (matches tsi-compass's
     * list_controls: 1-based page, default page=1/limit=20, limit capped at
     * 100). "page"/"limit" are absent from a body that doesn't paginate
     * (e.g. an unbounded selector-dropdown call) - callers of listX(appId)
     * repository overloads that don't take a Page are unaffected.
     */
    public static Page parsePaging(JsonNode body) {
        int page = body.path("page").asInt(1);
        int pageSize = body.path("limit").asInt(20);
        if (page < 1) page = 1;
        if (pageSize < 1) pageSize = 20;
        if (pageSize > 100) pageSize = 100;
        return new Page(page, pageSize);
    }
}
