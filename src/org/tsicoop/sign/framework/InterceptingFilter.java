package org.tsicoop.sign.framework;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.Properties;

/**
 * Single filter for all of /api/v1/* — the TSI framework standard pattern
 * (matches tsi-ledger/tsi-dpdp-cms/tsi-privacy-vault's InterceptingFilter):
 * every request is POST with a JSON body carrying "_func"; the resource path
 * (e.g. /api/v1/documents) only selects an Action class via _processor.tsi,
 * and the specific operation/record-id travel in the body, never the URL.
 *
 * Each _processor.tsi entry is "class|AUTH_MODE":
 *  - PUBLIC: no auth check here — an Action that needs to self-gate (e.g.
 *    Setup, one-time) does so internally.
 *  - TENANT: requires a valid X-API-Key (InputProcessor.resolveTenantApp), §6.
 *  - CONSOLE: requires a valid platform_user session (InputProcessor.
 *    resolveConsoleSession), §10.
 *  - TENANT_OR_CONSOLE: either of the above; the Action itself branches on
 *    InputProcessor.getAppContext(req) vs getUserRole(req) to pick
 *    behavior/scope (matches tsi-ledger's Accounts.java) — used by
 *    Templates/Documents, where an App and the admin console both operate
 *    on the same resource and duplicating the logic per auth mode isn't
 *    worth it.
 */
public class InterceptingFilter implements Filter {

    private static final String API_PREFIX = "/api/v1/";

    private enum AuthMode { PUBLIC, CONSOLE, TENANT, TENANT_OR_CONSOLE }

    private final RateLimiter rateLimiter = new RateLimiter();

    @Override
    public void destroy() {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        String method = req.getMethod();
        String uri = req.getRequestURI();

        res.setCharacterEncoding("UTF-8");
        res.setContentType("application/json");

        if ("OPTIONS".equalsIgnoreCase(method)) {
            res.setStatus(HttpServletResponse.SC_OK);
            return;
        }

        if (!uri.startsWith(API_PREFIX)) {
            chain.doFilter(request, response);
            return;
        }

        if (!"POST".equalsIgnoreCase(method)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "Method Not Allowed",
                    "All API calls are POST with a _func body.");
            return;
        }

        Properties apiRegistry = SystemConfig.getProcessorConfig();
        String servletPath = uri.endsWith("/") ? uri.substring(0, uri.length() - 1) : uri;
        String registryValue = apiRegistry.getProperty(servletPath);
        if (registryValue == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found",
                    "API endpoint not found: " + uri);
            return;
        }
        String[] parts = registryValue.split("\\|", 2);
        String classname = parts[0];
        AuthMode authMode = parts.length > 1 ? AuthMode.valueOf(parts[1].trim()) : AuthMode.TENANT;

        try {
            InputProcessor.processInput(req);
            JsonNode inputJson = InputProcessor.getInput(req);
            String func = inputJson.path("_func").asText(null);

            if (func == null || func.isBlank()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request",
                        "Missing required '_func' attribute in input JSON.");
                return;
            }

            boolean authenticated;
            switch (authMode) {
                case PUBLIC:
                    authenticated = true;
                    break;
                case CONSOLE:
                    authenticated = InputProcessor.resolveConsoleSession(req);
                    break;
                case TENANT_OR_CONSOLE:
                    // Order matters: resolveTenantApp short-circuits resolveConsoleSession via ||,
                    // so a request carrying a valid X-API-Key is always treated as TENANT even if
                    // it also happens to carry a console session cookie.
                    authenticated = InputProcessor.resolveTenantApp(req) || InputProcessor.resolveConsoleSession(req);
                    break;
                case TENANT:
                default:
                    authenticated = InputProcessor.resolveTenantApp(req);
                    break;
            }

            if (!authenticated) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized",
                        "Missing or invalid credentials.");
                return;
            }

            // Per-app rate limiting (§9, Chunk 9) — same short-circuit point as the 401 check
            // above. Only applies when this specific request actually resolved as TENANT (an
            // AppContext got set) — a TENANT_OR_CONSOLE request authenticated via a console
            // session has no per-app budget to check.
            AppContext appContext = InputProcessor.getAppContext(req);
            if (appContext != null) {
                Integer rpm = appContext.rateLimitRpm();
                if (rpm != null && !rateLimiter.tryAcquire(appContext.appId(), rpm)) {
                    OutputProcessor.errorResponse(res, 429, "Too Many Requests", "Rate limit exceeded for this App.");
                    return;
                }
            }

            Action action = (Action) Class.forName(classname).getConstructor().newInstance();
            boolean validRequest = action.validate(method, req, res);
            if (validRequest) {
                action.post(req, res);
            }
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error",
                    "An unexpected error occurred: " + e.getMessage());
        }
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        SystemConfig.loadProcessorConfig(filterConfig.getServletContext());
        SystemConfig.loadAppConfig(filterConfig.getServletContext());
        System.out.println("TSI Sign: loaded _processor.tsi and app config; started in "
                + System.getenv("TSI_SIGN_ENV") + " environment");
    }
}
