package org.tsicoop.sign.service.v1;

import org.tsicoop.sign.framework.AppContext;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.tsicoop.sign.framework.Action;
import org.tsicoop.sign.framework.InputProcessor;
import org.tsicoop.sign.framework.OutputProcessor;

/** Trivial protected endpoint (Chunk 2): echoes back the resolved AppContext. */
public class Ping implements Action {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        return true;
    }

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        AppContext appContext = InputProcessor.getAppContext(req);
        ObjectNode json = MAPPER.createObjectNode();
        json.put("status", "ok");
        json.put("appId", appContext.appId());
        json.put("appName", appContext.appName());
        json.put("appSlug", appContext.appSlug());
        OutputProcessor.send(res, HttpServletResponse.SC_OK, json);
    }
}
