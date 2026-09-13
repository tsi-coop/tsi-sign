package org.tsicoop.sign.esign;

/**
 * The outcome of {@link ESignAdapter#processCallback}, once the ESP has
 * (or hasn't) successfully authenticated the signer and produced a CMS
 * signature over the document hash we sent in {@link SigningSessionRequest}.
 */
public record SigningResult(
        boolean success,
        String transactionId,
        byte[] pkcs7Signature,
        String signerCommonName,
        String caIssuer,
        String authType,
        String failureReason
) {
}
