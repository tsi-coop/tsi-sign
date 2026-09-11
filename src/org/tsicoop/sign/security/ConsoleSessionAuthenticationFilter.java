package org.tsicoop.sign.security;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.util.Set;

/**
 * Session-based auth for platform_users on /api/v1/admin/** (§6, §10, §12
 * resolved: local session auth only, no SSO/OIDC). Separate from
 * ApiKeyAuthenticationFilter, which explicitly skips this prefix.
 *
 * Fine-grained RBAC (app_admins scoping per the §10.9 visibility matrix,
 * Chunk 9) is enforced by AdminAuthorizationService in each admin servlet —
 * this filter only proves "a platform_user is logged in." getUserId/getRole
 * below are the shared way servlets pull session identity for those checks.
 */
public class ConsoleSessionAuthenticationFilter implements Filter {

    public static final String SESSION_USER_ID = "platformUserId";
    public static final String SESSION_USER_ROLE = "platformUserRole";
    public static final String SESSION_USER_EMAIL = "platformUserEmail";
    public static final String SESSION_USER_NAME = "platformUserName";

    public static String getUserId(HttpServletRequest req) {
        HttpSession session = req.getSession(false);
        return session != null ? (String) session.getAttribute(SESSION_USER_ID) : null;
    }

    public static String getRole(HttpServletRequest req) {
        HttpSession session = req.getSession(false);
        return session != null ? (String) session.getAttribute(SESSION_USER_ROLE) : null;
    }

    private static final Set<String> PUBLIC_PATHS = Set.of(
            "/api/v1/admin/setup",
            "/api/v1/admin/setup-status",
            "/api/v1/admin/auth/login"
    );

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        String path = req.getRequestURI().substring(req.getContextPath().length());
        if (PUBLIC_PATHS.contains(path)) {
            chain.doFilter(request, response);
            return;
        }

        HttpSession session = req.getSession(false);
        if (session == null || session.getAttribute(SESSION_USER_ID) == null) {
            res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            res.setContentType("application/json");
            res.setCharacterEncoding("UTF-8");
            res.getWriter().write("{\"error\":\"Unauthorized\",\"message\":\"Not logged in.\"}");
            return;
        }

        chain.doFilter(request, response);
    }
}
