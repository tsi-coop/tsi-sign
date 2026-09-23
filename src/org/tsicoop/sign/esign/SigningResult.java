package org.tsicoop.sign.esign;

/**
 * The outcome of {@link ESignAdapter#processCallback}. {@code trusted} separates an
 * authenticated answer from the CA ("the signer cancelled", "OTP failed" - safe to act on,
 * i.e. fail the session) from a callback that could not be authenticated at all (bad or
 * untrusted response signature, wrong hash, malformed) - the callback endpoint is public, so
 * an unauthenticated message must never be able to fail or complete a session.
 */
public record SigningResult(
        boolean success,
        boolean trusted,
        String transactionId,
        byte[] pkcs7Signature,
        String signerCommonName,
        String caIssuer,
        String authType,
        String failureReason
) {

    public static SigningResult signed(String transactionId, byte[] pkcs7, String signerCommonName, String caIssuer,
            String authType) {
        return new SigningResult(true, true, transactionId, pkcs7, signerCommonName, caIssuer, authType, null);
    }

    /** An authenticated failure reported by the CA itself. */
    public static SigningResult caFailure(String transactionId, String reason) {
        return new SigningResult(false, true, transactionId, null, null, null, null, reason);
    }

    /** A callback that could not be authenticated or validated - never acted on. */
    public static SigningResult rejected(String reason) {
        return new SigningResult(false, false, null, null, null, null, null, reason);
    }
}
