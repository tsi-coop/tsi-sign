package org.tsicoop.sign.esign;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Decouples the core engine from any specific CCA-licensed Certifying
 * Authority (docs/architecture.md §6.3). Every real
 * implementation (eMudhra, C-DAC, NSDL, ...) is a redirect + callback
 * round-trip: {@link #initiateSigning} never blocks waiting for the signer -
 * it just hands back where to send them. Adapters are registered in
 * {@link ESignAdapterRegistry}; the callback/splice/webhook machinery in
 * {@code EsignReturnServlet}/{@code EsignCompletionService} never changes per CA.
 */
public interface ESignAdapter {

    String getProviderId();

    /** Label shown in the visible signature stamp, e.g. "Aadhaar eSign (eMudhra)". */
    String getDisplayName();

    SigningSessionResponse initiateSigning(SigningSessionRequest request) throws Exception;

    /**
     * Authenticates and parses a provider's callback into a typed result - never throws on a
     * malformed payload (returns {@link SigningResult#rejected}).
     *
     * @param expectedHashHex SHA-256 (hex) of the exact bytes we asked the CA to sign; a signature
     *                        over anything else must be rejected.
     */
    SigningResult processCallback(JsonNode callbackPayload, String expectedHashHex);
}
