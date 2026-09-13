package org.tsicoop.sign.service.v1;

import org.tsicoop.sign.framework.AppContext;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.tsicoop.sign.framework.EngineInfo;
import org.tsicoop.sign.pki.LocalPkiSigningService;
import org.tsicoop.sign.storage.DocumentStorageProvider;
import org.tsicoop.sign.storage.StorageObjectRef;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Assembles and seals a BSA §63 Part A/B legal certificate (§9) for an
 * already-sealed document, reusing the same rendering (§4) and Local PKI
 * sealing (§7) machinery documents themselves use.
 *
 * §9.3's "certifying_officer-designated key alias" presumes the admin
 * console's Certifying Officers screen (§10.5), which doesn't exist until
 * Chunk 8 — until then, the caller supplies certifyingKeyAlias directly
 * (falling back to the App's default_key_alias, same as seal-local).
 */
public class LegalCertificateService {

    private static final String CERTIFICATE_HTML_TEMPLATE = """
            <!DOCTYPE html>
            <html>
            <head><style>
                body { font-family: sans-serif; font-size: 12px; }
                h1 { font-size: 16px; } h2 { font-size: 13px; margin-top: 1.5em; }
                table { border-collapse: collapse; width: 100%; }
                td, th { border: 1px solid #999; padding: 4px 8px; text-align: left; }
            </style></head>
            <body>
                <h1>Legal Evidence Certificate - Bharatiya Sakshya Adhiniyam, 2023, Section 63(4)</h1>
                <p>Document: {{documentTitle}} ({{documentId}})</p>

                <h2>Part A: System Identification &amp; Operating Status</h2>
                <table>
                    <tr><th>Hostname</th><td>{{hostname}}</td></tr>
                    <tr><th>Container ID</th><td>{{containerId}}</td></tr>
                    <tr><th>Engine Version</th><td>{{engineVersion}}</td></tr>
                    <tr><th>Calling App</th><td>{{appSlug}} ({{appId}})</td></tr>
                    <tr><th>Operating Status</th><td>{{operatingStatus}}</td></tr>
                    <tr><th>Captured At</th><td>{{capturedAt}}</td></tr>
                </table>

                <h2>Part B: Last-Edit Tracking &amp; Output Particulars</h2>
                <table>
                    <tr><th>Template ID</th><td>{{templateId}}</td></tr>
                    <tr><th>Template Version</th><td>{{templateVersion}}</td></tr>
                    <tr><th>Last Modified</th><td>{{lastModifiedTimestamp}}</td></tr>
                    <tr><th>Original Hash (SHA-256)</th><td>{{linkedHash}}</td></tr>
                    <tr><th>PDF Generator</th><td>{{pdfGenerator}}</td></tr>
                    <tr><th>Sealed Hash (SHA-256)</th><td>{{sealedHash}}</td></tr>
                </table>

                <p style="margin-top:2em; font-size: 10px; color:#555;">
                    Scope: this certificate attests only to what TSI Sign itself did
                    (render, hash, seal). Any downstream event after the document
                    left TSI Sign's custody is outside this certificate's scope.
                </p>
            </body>
            </html>
            """;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final DocumentGeneratorService generatorService = new OpenHtmlToPdfGeneratorServiceImpl();
    private final TemplateRepository templateRepository = new TemplateRepository();
    private final LegalCertificateRepository certificateRepository = new LegalCertificateRepository();
    private final LocalPkiSigningService signingService;
    private final DocumentStorageProvider storageProvider;

    public LegalCertificateService(LocalPkiSigningService signingService, DocumentStorageProvider storageProvider) {
        this.signingService = signingService;
        this.storageProvider = storageProvider;
    }

    public record GeneratedCertificate(
            String certificateId, int version, ObjectNode partA, ObjectNode partB, String sha256Checksum
    ) {
    }

    public GeneratedCertificate generate(AppContext appContext, DocumentRepository.DocumentRecord document,
                                          String certifyingKeyAlias) throws Exception {
        Integer templateVersion = null;
        if (document.templateId() != null) {
            templateVersion = templateRepository.findByIdForApp(appContext.appId(), document.templateId())
                    .map(TemplateRepository.TemplateRecord::version)
                    .orElse(null);
        }

        String hostname = envOrDefault("HOSTNAME", "tsi-sign");
        String capturedAt = Instant.now().toString();

        ObjectNode partA = MAPPER.createObjectNode();
        ObjectNode generatingSystem = partA.putObject("generatingSystem");
        generatingSystem.put("hostname", hostname);
        generatingSystem.put("containerId", hostname);
        generatingSystem.put("engineVersion", EngineInfo.ENGINE_VERSION);
        ObjectNode callingApp = partA.putObject("callingApp");
        callingApp.put("appId", appContext.appId());
        callingApp.put("appSlug", appContext.appSlug());
        partA.put("operatingStatus", "HEALTHY");
        partA.put("capturedAt", capturedAt);

        ObjectNode partB = MAPPER.createObjectNode();
        partB.put("templateId", document.templateId());
        if (templateVersion != null) {
            partB.put("templateVersion", templateVersion);
        } else {
            partB.putNull("templateVersion");
        }
        ObjectNode lastModified = partB.putObject("lastModified");
        lastModified.put("timestamp", capturedAt);
        lastModified.put("linkedHash", document.originalHash());
        ObjectNode outputParticulars = partB.putObject("outputParticulars");
        outputParticulars.put("pdfGenerator", EngineInfo.PDF_GENERATOR_VERSION);
        outputParticulars.put("sealedHash", document.sealedHash());

        Map<String, Object> renderContext = new HashMap<>();
        renderContext.put("documentTitle", document.title());
        renderContext.put("documentId", document.documentId());
        renderContext.put("hostname", hostname);
        renderContext.put("containerId", hostname);
        renderContext.put("engineVersion", EngineInfo.ENGINE_VERSION);
        renderContext.put("appSlug", appContext.appSlug());
        renderContext.put("appId", appContext.appId());
        renderContext.put("operatingStatus", "HEALTHY");
        renderContext.put("capturedAt", capturedAt);
        renderContext.put("templateId", document.templateId());
        renderContext.put("templateVersion", templateVersion != null ? templateVersion : "-");
        renderContext.put("lastModifiedTimestamp", capturedAt);
        renderContext.put("linkedHash", document.originalHash());
        renderContext.put("pdfGenerator", EngineInfo.PDF_GENERATOR_VERSION);
        renderContext.put("sealedHash", document.sealedHash());

        DocumentGenerationResult rendered = generatorService.generatePdf(CERTIFICATE_HTML_TEMPLATE, renderContext);
        LocalPkiSigningService.SealResult sealed = signingService.seal(
                rendered.pdfBytes(), certifyingKeyAlias, "BSA Section 63(4) Legal Evidence Certificate", null, null);

        int version = certificateRepository.nextVersion(document.documentId());
        StorageObjectRef ref = storageProvider.store(
                appContext.appSlug(), document.documentId(), "legal-certificate-v" + version, sealed.sealedPdfBytes());

        String certificateId = certificateRepository.insert(
                document.documentId(), appContext.appId(), version,
                partA.toString(), partB.toString(), sealed.sha256Hash(),
                ref.providerId(), ref.storageKey());

        return new GeneratedCertificate(certificateId, version, partA, partB, sealed.sha256Hash());
    }

    private static String envOrDefault(String name, String defaultValue) {
        String value = System.getenv(name);
        return value != null ? value : defaultValue;
    }
}
