package org.tsicoop.sign.framework;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

public class OutputProcessor {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** Sends a JSON response. Accepts a JsonNode, or any Jackson-serializable object. */
    public static void send(HttpServletResponse res, int status, Object data) {
        res.setStatus(status);
        res.setCharacterEncoding("UTF-8");
        res.setContentType("application/json");
        try {
            MAPPER.writeValue(res.getWriter(), data != null ? data : MAPPER.createObjectNode());
        } catch (IOException e) {
            System.err.println("OutputProcessor.send: " + e.getMessage());
        }
    }

    public static void errorResponse(HttpServletResponse res, int status, String error, String message) {
        ObjectNode json = MAPPER.createObjectNode();
        json.put("error", error);
        json.put("message", message);
        send(res, status, json);
    }
}
