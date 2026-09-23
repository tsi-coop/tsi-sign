package org.tsicoop.sign.esign;

/**
 * What the calling App gets back from {@code initiate_esign}: a transaction
 * id to track the session, and a URL to redirect its own end-user to so
 * they can complete Aadhaar OTP/biometric authentication on the ESP's own
 * site (never on tsi-sign - we never see the signer's Aadhaar number).
 *
 * @param gatewayPayload nullable JSON ({@code {"actionUrl":..., "fields":{...}}}): when the ESP
 *                       must be reached by a browser form POST (the CCA eSign API's model), the
 *                       gatewayUrl points at a page that submits this on the signer's behalf.
 */
public record SigningSessionResponse(
        String transactionId,
        String gatewayUrl,
        String gatewayPayload
) {
    public SigningSessionResponse(String transactionId, String gatewayUrl) {
        this(transactionId, gatewayUrl, null);
    }
}
