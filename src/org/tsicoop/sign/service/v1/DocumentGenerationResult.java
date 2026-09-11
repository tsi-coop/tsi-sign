package org.tsicoop.sign.service.v1;

public record DocumentGenerationResult(
        byte[] pdfBytes,
        String sha256Hash
) {
}
