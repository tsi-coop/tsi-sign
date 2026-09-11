package org.tsicoop.sign.api.v1;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.tsicoop.sign.app.AppContext;
import org.tsicoop.sign.security.ApiKeyAuthenticationFilter;

import java.io.IOException;

/**
 * Trivial protected endpoint (Chunk 2, §14): echoes back the AppContext the
 * ApiKeyAuthenticationFilter resolved, so auth can be verified end-to-end
 * with curl before any real business endpoint exists.
 */
public class PingServlet extends HttpServlet {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
        AppContext appContext = (AppContext) req.getAttribute(ApiKeyAuthenticationFilter.APP_CONTEXT_ATTRIBUTE);

        ObjectNode json = MAPPER.createObjectNode();
        json.put("status", "ok");
        json.put("appId", appContext.appId());
        json.put("appName", appContext.appName());
        json.put("appSlug", appContext.appSlug());

        res.setContentType("application/json");
        res.setCharacterEncoding("UTF-8");
        MAPPER.writeValue(res.getWriter(), json);
    }
}
