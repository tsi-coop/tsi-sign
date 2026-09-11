package org.tsicoop.sign.template;

public record DocumentGenerationResult(
        byte[] pdfBytes,
        String sha256Hash
) {
}
