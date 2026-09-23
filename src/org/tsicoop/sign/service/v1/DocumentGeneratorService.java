package org.tsicoop.sign.service.v1;

import java.util.Map;

/**
 * Merges dynamic data into an HTML template and compiles a rendered PDF.
 *
 * Takes the template's HTML directly rather than a templateId (as the
 * original Technical Architecture doc (removed; see git history)'s illustrative interface does) - fetching a
 * template by id/App scope is a repository concern (TemplateRepository),
 * kept separate from rendering so this service stays pure and testable
 * without a DB.
 */
public interface DocumentGeneratorService {

    /**
     * @param htmlTemplate raw HTML/CSS source containing {{field}} placeholders
     * @param payloadData  key-value pairs to populate inside the template
     */
    DocumentGenerationResult generatePdf(String htmlTemplate, Map<String, Object> payloadData) throws TemplateRenderException;
}
