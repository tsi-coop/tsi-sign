package org.tsicoop.sign.framework;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.Set;

/**
 * Server-side gate for the static admin console pages under /console/.
 *
 * The console's own login check is client-side JS (console.js reads the token
 * from localStorage and redirects), which runs only after the page has already
 * been delivered - any non-browser client received every page unauthenticated.
 * This filter runs before the default servlet dispatches the file and requires
 * a valid, non-revoked console JWT, carried in the HttpOnly session cookie that
 * Auth.login sets (a plain browser navigation can't send an Authorization
 * header; fetch/XHR calls can). Otherwise it redirects to the login page.
 *
 * Deny by default: every .html page is gated except the explicit allowlist
 * below, so a newly added page is protected without anyone remembering to
 * register it. Static assets (CSS/JS) stay public - the login page itself needs
 * them. The API is unaffected: every /api/v1/admin/* call is still
 * authenticated independently by InterceptingFilter.
 */
public class ConsoleAuthFilter implements Filter {

    private static final String LOGIN_PAGE = "/console/login.html";

    /** Pages that must be reachable without a session (login flow, signer-facing redirect). */
    private static final Set<String> PUBLIC_PAGES = Set.of(
            "/console/login.html",
            "/console/index.html",
            "/console/password-reset.html",
            "/console/esign-redirect.html");

    @Override
    public void init(FilterConfig filterConfig) {
    }

    @Override
    public void destroy() {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        if (!requiresSession(req)) {
            chain.doFilter(request, response);
            return;
        }

        String token = InputProcessor.readConsoleSessionCookie(req);
        if (token == null || !JWTUtil.isTokenValid(token)) {
            res.sendRedirect(LOGIN_PAGE);
            return;
        }
        // Pages carry per-user content; keep them out of shared/back-button caches.
        res.setHeader("Cache-Control", "no-store");
        chain.doFilter(request, response);
    }

    private static boolean requiresSession(HttpServletRequest req) {
        String path = normalize(req.getServletPath() + (req.getPathInfo() == null ? "" : req.getPathInfo()));
        if (path.startsWith("/console/assets/") || PUBLIC_PAGES.contains(path)) {
            return false;
        }
        // "/console/" and "/console" are welcome-file requests for the public index.html.
        if (path.equals("/console") || path.equals("/console/")) {
            return false;
        }
        return true;
    }

    /** Collapses "//" and "/./" so an odd-looking path can't slip past the allowlist comparison. */
    private static String normalize(String path) {
        String p = path.replaceAll("/{2,}", "/");
        while (p.contains("/./")) {
            p = p.replace("/./", "/");
        }
        return p;
    }
}
