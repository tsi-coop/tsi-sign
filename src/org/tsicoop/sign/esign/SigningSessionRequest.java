package org.tsicoop.sign.esign;

/**
 * What {@link ESignAdapter#initiateSigning} needs to start an Aadhaar eSign
 * session - the document's hash (never the raw PDF; the ESP only ever sees
 * a hash), and enough about the signer/document for the ESP's consent
 * screen and for our own audit trail.
 */
public record SigningSessionRequest(
        String documentId,
        String appId,
        String signerName,
        String signerEmail,
        String signerPhone,
        String documentHash,
        String reason
) {
}
