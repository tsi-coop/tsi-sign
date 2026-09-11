package org.tsicoop.sign.api.v1;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.tsicoop.sign.app.AppContext;
import org.tsicoop.sign.app.AppRepository;
import org.tsicoop.sign.audit.AuditLogRepository;
import org.tsicoop.sign.document.DocumentRepository;
import org.tsicoop.sign.legal.LegalCertificateRepository;
import org.tsicoop.sign.legal.LegalCertificateService;
import org.tsicoop.sign.pki.LocalKeyStoreProvider;
import org.tsicoop.sign.pki.LocalPkiSigningService;
import org.tsicoop.sign.security.ApiKeyAuthenticationFilter;
import org.tsicoop.sign.storage.DocumentStorageProvider;
import org.tsicoop.sign.storage.LocalFilesystemStorageProvider;
import org.tsicoop.sign.storage.StorageException;
import org.tsicoop.sign.storage.StorageObjectRef;

import java.io.IOException;
import java.time.Instant;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * §8: POST /api/v1/documents/{documentId}/seal-local (§7 Local PKI flow).
 * §9.4: POST/GET /api/v1/documents/{documentId}/legal-certificate (Chunk 6).
 * POST /api/v1/documents/{documentId}/sign (external CA) is Chunk 10.
 */
public class DocumentsServlet extends HttpServlet {

    private static final Pattern SEAL_LOCAL_PATH = Pattern.compile("^/([^/]+)/seal-local$");
    private static final Pattern LEGAL_CERTIFICATE_PATH = Pattern.compile("^/([^/]+)/legal-certificate$");
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private DocumentRepository documentRepository;
    private AppRepository appRepository;
    private AuditLogRepository auditLogRepository;
    private LegalCertificateRepository legalCertificateRepository;
    private DocumentStorageProvider storageProvider;
    private LocalPkiSigningService signingService;
    private LegalCertificateService legalCertificateService;

    @Override
    public void init() throws ServletException {
        documentRepository = new DocumentRepository();
        appRepository = new AppRepository();
        auditLogRepository = new AuditLogRepository();
        legalCertificateRepository = new LegalCertificateRepository();
        storageProvider = new LocalFilesystemStorageProvider();
        try {
            signingService = new LocalPkiSigningService(new LocalKeyStoreProvider());
        } catch (Exception e) {
            throw new ServletException("Failed to initialize Local PKI signing service", e);
        }
        legalCertificateService = new LegalCertificateService(signingService, storageProvider);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
        String pathInfo = req.getPathInfo();
        AppContext appContext = (AppContext) req.getAttribute(ApiKeyAuthenticationFilter.APP_CONTEXT_ATTRIBUTE);

        try {
            Matcher sealMatcher = pathInfo != null ? SEAL_LOCAL_PATH.matcher(pathInfo) : null;
            if (sealMatcher != null && sealMatcher.matches()) {
                sealLocal(req, res, appContext, sealMatcher.group(1));
                return;
            }
            Matcher certMatcher = pathInfo != null ? LEGAL_CERTIFICATE_PATH.matcher(pathInfo) : null;
            if (certMatcher != null && certMatcher.matches()) {
                generateLegalCertificate(req, res, appContext, certMatcher.group(1));
                return;
            }
            writeError(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such documents route.");
        } catch (Exception e) {
            writeError(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", e.getMessage());
        }
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
        String pathInfo = req.getPathInfo();
        AppContext appContext = (AppContext) req.getAttribute(ApiKeyAuthenticationFilter.APP_CONTEXT_ATTRIBUTE);

        try {
            Matcher certMatcher = pathInfo != null ? LEGAL_CERTIFICATE_PATH.matcher(pathInfo) : null;
            if (certMatcher != null && certMatcher.matches()) {
                downloadLegalCertificate(res, appContext, certMatcher.group(1));
                return;
            }
            writeError(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such documents route.");
        } catch (Exception e) {
            writeError(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", e.getMessage());
        }
    }

    private void sealLocal(HttpServletRequest req, HttpServletResponse res, AppContext appContext, String documentId)
            throws Exception {
        Optional<DocumentRepository.DocumentRecord> documentOpt =
                documentRepository.findByIdForApp(appContext.appId(), documentId);
        if (documentOpt.isEmpty()) {
            writeError(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such document.");
            return;
        }
        DocumentRepository.DocumentRecord document = documentOpt.get();
        if (!"DRAFT".equals(document.status()) && !"PENDING".equals(document.status())) {
            writeError(res, HttpServletResponse.SC_CONFLICT, "Conflict",
                    "Document is already " + document.status() + "; cannot seal again.");
            return;
        }
        if (!LocalFilesystemStorageProvider.PROVIDER_ID.equals(document.storageProviderId())) {
            writeError(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error",
                    "Unsupported storage provider for this document: " + document.storageProviderId());
            return;
        }

        JsonNode body = req.getContentLengthLong() > 0 ? MAPPER.readTree(req.getInputStream()) : MAPPER.createObjectNode();
        String keyAlias = body.path("keyAlias").asText(null);
        if (keyAlias == null) {
            keyAlias = appRepository.findDefaultKeyAlias(appContext.appId()).orElse(null);
        }
        if (keyAlias == null) {
            writeError(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request",
                    "keyAlias is required: no default_key_alias is configured for this App.");
            return;
        }
        String reason = body.path("reason").asText(null);
        String location = body.path("location").asText(null);

        StorageObjectRef originalRef = new StorageObjectRef(
                document.storageProviderId(), document.originalStorageKey(), document.originalHash());
        byte[] originalBytes = storageProvider.retrieve(originalRef);

        LocalPkiSigningService.SealResult sealed = signingService.seal(originalBytes, keyAlias, reason, location);

        StorageObjectRef sealedRef = storageProvider.store(
                appContext.appSlug(), documentId, "sealed", sealed.sealedPdfBytes());

        documentRepository.markSealed(documentId, sealedRef.storageKey(), sealed.sha256Hash());
        documentRepository.insertSeal(documentId, null, "local_pki", keyAlias, null, null, "PAdES-B-B", null, null);
        auditLogRepository.log(appContext.appId(), documentId, "SEALED", "APP", appContext.appId(),
                req.getRemoteAddr(), req.getHeader("User-Agent"));

        ObjectNode json = MAPPER.createObjectNode();
        json.put("status", "SIGNED");
        json.put("signatureStandard", "PAdES-B-B");
        json.put("sealedAt", Instant.now().toString());
        json.put("sha256Checksum", sealed.sha256Hash());
        writeJson(res, HttpServletResponse.SC_OK, json);
    }

    private void generateLegalCertificate(HttpServletRequest req, HttpServletResponse res, AppContext appContext,
                                           String documentId) throws Exception {
        Optional<DocumentRepository.DocumentRecord> documentOpt =
                documentRepository.findByIdForApp(appContext.appId(), documentId);
        if (documentOpt.isEmpty()) {
            writeError(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such document.");
            return;
        }
        DocumentRepository.DocumentRecord document = documentOpt.get();
        if (!"SIGNED".equals(document.status())) {
            writeError(res, HttpServletResponse.SC_CONFLICT, "Conflict",
                    "Document must be sealed (SIGNED) before a legal certificate can be generated.");
            return;
        }

        JsonNode body = req.getContentLengthLong() > 0 ? MAPPER.readTree(req.getInputStream()) : MAPPER.createObjectNode();
        String certifyingKeyAlias = body.path("certifyingKeyAlias").asText(null);
        if (certifyingKeyAlias == null) {
            certifyingKeyAlias = appRepository.findDefaultKeyAlias(appContext.appId()).orElse(null);
        }
        if (certifyingKeyAlias == null) {
            writeError(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request",
                    "certifyingKeyAlias is required: no default_key_alias is configured for this App.");
            return;
        }

        LegalCertificateService.GeneratedCertificate certificate =
                legalCertificateService.generate(appContext, document, certifyingKeyAlias);

        auditLogRepository.log(appContext.appId(), documentId, "LEGAL_CERTIFICATE_GENERATED", "APP", appContext.appId(),
                req.getRemoteAddr(), req.getHeader("User-Agent"));

        ObjectNode json = MAPPER.createObjectNode();
        json.put("certificateId", certificate.certificateId());
        json.put("version", certificate.version());
        json.set("partA", certificate.partA());
        json.set("partB", certificate.partB());
        json.put("sha256Checksum", certificate.sha256Checksum());
        json.put("sealedAt", Instant.now().toString());
        writeJson(res, HttpServletResponse.SC_CREATED, json);
    }

    private void downloadLegalCertificate(HttpServletResponse res, AppContext appContext, String documentId)
            throws Exception {
        Optional<LegalCertificateRepository.CertificateRecord> certificateOpt =
                legalCertificateRepository.findLatestForApp(appContext.appId(), documentId);
        if (certificateOpt.isEmpty()) {
            writeError(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No legal certificate for this document.");
            return;
        }
        LegalCertificateRepository.CertificateRecord certificate = certificateOpt.get();
        if (!LocalFilesystemStorageProvider.PROVIDER_ID.equals(certificate.storageProviderId())) {
            writeError(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error",
                    "Unsupported storage provider for this certificate: " + certificate.storageProviderId());
            return;
        }

        byte[] pdfBytes;
        try {
            pdfBytes = storageProvider.retrieve(new StorageObjectRef(
                    certificate.storageProviderId(), certificate.certificateStorageKey(), certificate.certificateHash()));
        } catch (StorageException e) {
            writeError(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", e.getMessage());
            return;
        }

        res.setStatus(HttpServletResponse.SC_OK);
        res.setContentType("application/pdf");
        res.setHeader("Content-Disposition", "attachment; filename=\"legal-certificate-v" + certificate.version() + ".pdf\"");
        res.getOutputStream().write(pdfBytes);
    }

    private void writeJson(HttpServletResponse res, int status, ObjectNode json) throws IOException {
        res.setStatus(status);
        res.setContentType("application/json");
        res.setCharacterEncoding("UTF-8");
        MAPPER.writeValue(res.getWriter(), json);
    }

    private void writeError(HttpServletResponse res, int status, String error, String message) throws IOException {
        ObjectNode json = MAPPER.createObjectNode();
        json.put("error", error);
        json.put("message", message);
        writeJson(res, status, json);
    }
}
