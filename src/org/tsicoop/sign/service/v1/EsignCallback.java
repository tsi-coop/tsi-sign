package org.tsicoop.sign.service.v1;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.tsicoop.sign.esign.EsignSessionRepository;
import org.tsicoop.sign.framework.Action;
import org.tsicoop.sign.framework.InputProcessor;
import org.tsicoop.sign.framework.OutputProcessor;

import java.util.Optional;

/**
 * PUBLIC (see README "eSign providers"): called by the signer's browser, not an App or a
 * console session, so there is no X-API-Key/session to check - access is gated by knowledge of the
 * unguessable transaction id, and the payload is only a signed request that carries a document
 * hash (never the document).
 *
 * <p>Func {@code gateway_payload}: what {@code console/esign-redirect.html} needs to POST the
 * signer's browser on to the ESP ({@code {actionUrl, fields}}). The ESP's response does NOT come
 * through here - it returns to {@link EsignReturnServlet}.
 */
public class EsignCallback implements Action {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final EsignSessionRepository esignSessionRepository = new EsignSessionRepository();

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        return true;
    }

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JsonNode body = InputProcessor.getInput(req);
        String func = body.path("_func").asText("");
        try {
            if ("gateway_payload".equals(func)) {
                gatewayPayload(res, body);
            } else {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Unknown _func: " + func);
            }
        } catch (Exception e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", e.getMessage());
        }
    }

    private void gatewayPayload(HttpServletResponse res, JsonNode body) throws Exception {
        String providerId = body.path("provider").asText(null);
        String transactionId = body.path("transactionId").asText(null);
        if (providerId == null || transactionId == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "provider and transactionId are required.");
            return;
        }
        Optional<EsignSessionRepository.EsignSessionRecord> sessionOpt =
                esignSessionRepository.findByTransactionId(providerId, transactionId);
        if (sessionOpt.isEmpty() || sessionOpt.get().gatewayPayload() == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such eSign session.");
            return;
        }
        if (!"INITIATED".equals(sessionOpt.get().status())) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict",
                    "This eSign session is already " + sessionOpt.get().status() + ".");
            return;
        }
        OutputProcessor.send(res, HttpServletResponse.SC_OK, MAPPER.readTree(sessionOpt.get().gatewayPayload()));
    }
}
