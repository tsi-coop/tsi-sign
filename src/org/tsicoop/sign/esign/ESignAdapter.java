package org.tsicoop.sign.esign;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Decouples the core engine from any specific CCA-licensed Certifying
 * Authority (prep/TSI-Sign-Apps-Implementation-Plan.md §7). Every real
 * implementation (eMudhra, C-DAC, NSDL, ...) is a redirect + callback
 * round-trip: {@link #initiateSigning} never blocks waiting for the signer -
 * it just hands back where to send them. {@link MockAadhaarEsignAdapter} is
 * the only implementation that ships today; a real one is a drop-in later
 * that never touches the callback/splice/webhook machinery in
 * {@code EsignCallback}.
 */
public interface ESignAdapter {

    String getProviderId();

    SigningSessionResponse initiateSigning(SigningSessionRequest request) throws Exception;

    /** Parses/verifies a provider's callback payload into a typed result - never throws on a malformed payload. */
    SigningResult processCallback(JsonNode callbackPayload);
}
