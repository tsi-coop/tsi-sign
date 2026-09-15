package org.tsicoop.sign.service.v1;

import com.openhtmltopdf.pdfboxout.PdfRendererBuilder;
import com.samskivert.mustache.Mustache;
import org.tsicoop.sign.framework.HashUtil;

import java.io.ByteArrayOutputStream;
import java.util.Map;

/**
 * Renders HTML+CSS to PDF/A via OpenHTMLtoPDF (backed by Apache PDFBox),
 * per the Technical Architecture doc's engine pipeline: Mustache merge ->
 * OpenHTMLtoPDF render -> SHA-256 hash.
 */
public class OpenHtmlToPdfGeneratorServiceImpl implements DocumentGeneratorService {

    @Override
    public DocumentGenerationResult generatePdf(String htmlTemplate, Map<String, Object> payloadData)
            throws TemplateRenderException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            String renderedHtml = Mustache.compiler().compile(htmlTemplate).execute(payloadData);
            PdfRendererBuilder builder = new PdfRendererBuilder();
            builder.useFastMode();
            builder.withHtmlContent(renderedHtml, "");
            builder.toStream(outputStream);
            builder.run();
        } catch (Exception e) {
            throw new TemplateRenderException("Template HTML is invalid: " + rootCauseMessage(e), e);
        }

        byte[] pdfBytes = outputStream.toByteArray();
        return new DocumentGenerationResult(pdfBytes, HashUtil.sha256Hex(pdfBytes));
    }

    /** openhtmltopdf/Mustache wrap the actual parse failure several layers deep - the innermost message is the one worth showing a template author. */
    private static String rootCauseMessage(Throwable e) {
        Throwable t = e;
        while (t.getCause() != null) {
            t = t.getCause();
        }
        return t.getMessage() != null ? t.getMessage() : t.toString();
    }
}
