package org.tsicoop.sign.security;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.tsicoop.sign.app.AppContext;

import java.io.IOException;
import java.util.Optional;

/**
 * Wraps every /api/v1/* route except /api/v1/admin/** (§6): hashes
 * X-API-Key, resolves it to an AppContext, and rejects with 401 before any
 * business logic runs if there is no match. On success, binds AppContext as
 * a request attribute for the remainder of the request lifecycle.
 *
 * Admin endpoints (Chunk 7) use ConsoleSessionAuthenticationFilter instead —
 * both filters map to overlapping url-patterns, so this one explicitly
 * passes admin requests through untouched rather than trying to narrow its
 * own web.xml mapping around them.
 */
public class ApiKeyAuthenticationFilter implements Filter {

    public static final String APP_CONTEXT_ATTRIBUTE = "org.tsicoop.sign.AppContext";
    private static final String ADMIN_PREFIX = "/api/v1/admin/";

    private final ApiKeyAuthenticator authenticator = new ApiKeyAuthenticatorImpl();
    private final RateLimiter rateLimiter = new RateLimiter();

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        String path = req.getRequestURI().substring(req.getContextPath().length());
        if (path.startsWith(ADMIN_PREFIX)) {
            chain.doFilter(request, response);
            return;
        }

        String rawApiKey = req.getHeader("X-API-Key");
        Optional<AppContext> appContext = authenticator.resolve(rawApiKey);

        if (appContext.isEmpty()) {
            res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            res.setContentType("application/json");
            res.setCharacterEncoding("UTF-8");
            res.getWriter().write("{\"error\":\"Unauthorized\",\"message\":\"Missing or invalid X-API-Key.\"}");
            return;
        }

        // Per-app rate limiting (§9, Chunk 9) — the same short-circuit point
        // as the 401 check above: rejected before touching business logic.
        Integer rpm = appContext.get().rateLimitRpm();
        if (rpm != null && !rateLimiter.tryAcquire(appContext.get().appId(), rpm)) {
            res.setStatus(429); // Too Many Requests
            res.setContentType("application/json");
            res.setCharacterEncoding("UTF-8");
            res.getWriter().write("{\"error\":\"Too Many Requests\",\"message\":\"Rate limit exceeded for this App.\"}");
            return;
        }

        request.setAttribute(APP_CONTEXT_ATTRIBUTE, appContext.get());
        chain.doFilter(request, response);
    }
}
