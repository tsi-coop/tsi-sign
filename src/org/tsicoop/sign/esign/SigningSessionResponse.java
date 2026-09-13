package org.tsicoop.sign.esign;

/**
 * What the calling App gets back from {@code initiate_esign}: a transaction
 * id to track the session, and a URL to redirect its own end-user to so
 * they can complete Aadhaar OTP/biometric authentication on the ESP's own
 * site (never on tsi-sign - we never see the signer's Aadhaar number).
 */
public record SigningSessionResponse(
        String transactionId,
        String gatewayUrl
) {
}
