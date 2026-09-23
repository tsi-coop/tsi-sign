package org.tsicoop.sign.service.v1;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.tsicoop.sign.esign.ESignAdapter;
import org.tsicoop.sign.esign.ESignAdapterRegistry;
import org.tsicoop.sign.esign.EsignSessionRepository;

import java.io.IOException;
import java.util.Optional;

/**
 * The return leg of the CCA eSign flow: the signer's browser is sent back here by the ESP with a
 * form-POSTed, signed {@code msg} ({@code POST /esign/return/{providerId}/{transactionId}}).
 * This is the one endpoint outside the {@code /api/v1} POST+{@code _func}+JSON convention on
 * purpose: the CA dictates a form-encoded browser POST, which {@code InterceptingFilter} can't
 * carry. It is unauthenticated by design - trust comes entirely from the adapter verifying the
 * ESP's XML signature, the signer certificate chain, and the signed hash
 * ({@link EsignCompletionService}) - so nothing here acts on an unverified message.
 */
public class EsignReturnServlet extends HttpServlet {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final EsignSessionRepository esignSessionRepository = new EsignSessionRepository();
    private final EsignCompletionService completionService = new EsignCompletionService();

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String[] parts = req.getPathInfo() == null ? new String[0] : req.getPathInfo().replaceFirst("^/", "").split("/");
        if (parts.length != 2) {
            page(res, 404, "Not found", "Unknown eSign return URL.");
            return;
        }
        String providerId = parts[0];
        String transactionId = parts[1];
        try {
            ESignAdapter adapter;
            try {
                adapter = ESignAdapterRegistry.resolve(providerId);
            } catch (IllegalArgumentException e) {
                page(res, 404, "Not found", "Unknown eSign provider.");
                return;
            }
            Optional<EsignSessionRepository.EsignSessionRecord> sessionOpt =
                    esignSessionRepository.findByTransactionId(providerId, transactionId);
            if (sessionOpt.isEmpty()) {
                page(res, 404, "Not found", "No such eSign session.");
                return;
            }
            ObjectNode payload = MAPPER.createObjectNode();
            payload.put("msg", req.getParameter("msg"));

            EsignCompletionService.Outcome outcome = completionService.handleCallback(
                    adapter, sessionOpt.get(), payload, req.getRemoteAddr(), req.getHeader("User-Agent"));
            switch (outcome.kind()) {
                case COMPLETED -> page(res, 200, "Signed", "Your signature has been applied. You can close this window and return to the application.");
                case FAILED -> page(res, 200, "Signing not completed", "The signing service reported: " + outcome.message()
                        + ". You can return to the application and try again.");
                case CONFLICT -> page(res, 409, "Already processed", outcome.message());
                default -> page(res, 400, "Response rejected", "The signing response could not be verified and was ignored.");
            }
        } catch (Exception e) {
            System.err.println("EsignReturnServlet: " + e);
            page(res, 500, "Error", "Could not process the signing response.");
        }
    }

    private static void page(HttpServletResponse res, int status, String title, String message) throws IOException {
        res.setStatus(status);
        res.setContentType("text/html;charset=UTF-8");
        res.getWriter().write("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
                + "<title>" + h(title) + " - TSI Sign</title></head><body style=\"font-family:system-ui,sans-serif;max-width:520px;margin:64px auto;padding:0 16px\">"
                + "<h2>" + h(title) + "</h2><p>" + h(message) + "</p></body></html>");
    }

    private static String h(String s) {
        return s == null ? "" : s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }
}
