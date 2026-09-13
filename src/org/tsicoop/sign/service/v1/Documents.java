package org.tsicoop.sign.service.v1;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.tsicoop.sign.framework.Action;
import org.tsicoop.sign.framework.AppContext;
import org.tsicoop.sign.framework.InputProcessor;
import org.tsicoop.sign.framework.OutputProcessor;
import org.tsicoop.sign.pki.LocalKeyStoreProvider;
import org.tsicoop.sign.pki.LocalPkiSigningService;
import org.tsicoop.sign.storage.DocumentStorageProvider;
import org.tsicoop.sign.storage.LocalFilesystemStorageProvider;
import org.tsicoop.sign.storage.StorageObjectRef;

import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

import org.tsicoop.sign.framework.HashUtil;

/**
 * TENANT_OR_CONSOLE (matches tsi-ledger's Accounts.java): an App and the
 * admin console both touch documents/legal certificates, so this is one
 * Action branching on which identity resolved. funcs:
 *  - get_legal_certificate: TENANT only (§9.4).
 *  - seal_local, generate_legal_certificate, upload_document: BOTH — tenant
 *    acts under its own App; console acts under a body-supplied appId
 *    (RBAC-checked, §10.9). generate_legal_certificate is the real
 *    duplication this merge fixes (PKI signing + Part A/B assembly is not
 *    cheap logic to keep in sync across two classes). upload_document is
 *    the raw-file counterpart to Templates.generate_document — same DRAFT
 *    document row, just with a null template_id and caller-supplied bytes.
 *  - list_documents, get_document, download_document: CONSOLE only (§10.4).
 *    A bare API-key caller has no role, so AuthorizationService naturally
 *    403s these rather than needing a separate guard.
 */
public class Documents implements Action {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final AppRepository appRepository = new AppRepository();
    private final DocumentRepository documentRepository = new DocumentRepository();
    private final AuditLogRepository auditLogRepository = new AuditLogRepository();
    private final PlatformUserRepository platformUserRepository = new PlatformUserRepository();
    private final LegalCertificateRepository legalCertificateRepository = new LegalCertificateRepository();
    private final DocumentStorageProvider storageProvider = new LocalFilesystemStorageProvider();
    private final AuthorizationService authorizationService = new AuthorizationService();
    private final LocalPkiSigningService signingService;
    private final LegalCertificateService legalCertificateService;

    public Documents() {
        try {
            signingService = new LocalPkiSigningService(new LocalKeyStoreProvider());
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize Local PKI signing service", e);
        }
        legalCertificateService = new LegalCertificateService(signingService, storageProvider);
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        return true;
    }

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JsonNode body = InputProcessor.getInput(req);
        String func = body.path("_func").asText("");
        AppContext appContext = InputProcessor.getAppContext(req);

        try {
            switch (func) {
                case "seal_local":
                    sealLocal(req, res, body, appContext);
                    break;
                case "upload_document":
                    uploadDocument(req, res, body, appContext);
                    break;
                case "get_legal_certificate":
                    if (appContext == null) {
                        OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request",
                                "This operation requires an App API key.");
                        return;
                    }
                    getLegalCertificate(res, body, appContext);
                    break;
                case "generate_legal_certificate":
                    generateLegalCertificate(req, res, body, appContext);
                    break;
                case "list_documents":
                    listDocuments(req, res, body);
                    break;
                case "get_document":
                    getDocument(req, res, body);
                    break;
                case "download_document":
                    downloadDocument(req, res, body);
                    break;
                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Unknown _func: " + func);
            }
        } catch (Exception e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", e.getMessage());
        }
    }

    private void sealLocal(HttpServletRequest req, HttpServletResponse res, JsonNode body, AppContext appContext)
            throws Exception {
        String documentId = body.path("documentId").asText(null);
        if (documentId == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "documentId is required.");
            return;
        }

        String appId;
        String appSlug;
        if (appContext != null) {
            appId = appContext.appId();
            appSlug = appContext.appSlug();
        } else {
            appId = body.path("appId").asText(null);
            if (appId == null) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "appId is required.");
                return;
            }
            if (!authorizationService.canWrite(InputProcessor.getUserRole(req), InputProcessor.getUserId(req), appId)) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "You do not have write access to this App.");
                return;
            }
            Optional<AppRepository.AppRecord> appOpt = appRepository.findById(appId);
            if (appOpt.isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such App.");
                return;
            }
            appSlug = appOpt.get().appSlug();
        }

        Optional<DocumentRepository.DocumentRecord> documentOpt =
                documentRepository.findByIdForApp(appId, documentId);
        if (documentOpt.isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such document.");
            return;
        }
        DocumentRepository.DocumentRecord document = documentOpt.get();
        if (!"DRAFT".equals(document.status()) && !"PENDING".equals(document.status())) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict",
                    "Document is already " + document.status() + "; cannot seal again.");
            return;
        }
        if (!LocalFilesystemStorageProvider.PROVIDER_ID.equals(document.storageProviderId())) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error",
                    "Unsupported storage provider for this document: " + document.storageProviderId());
            return;
        }

        String keyAlias = body.path("keyAlias").asText(null);
        if (keyAlias == null) {
            keyAlias = appRepository.findDefaultKeyAlias(appId).orElse(null);
        }
        if (keyAlias == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request",
                    "keyAlias is required: no default_key_alias is configured for this App.");
            return;
        }
        String reason = body.path("reason").asText(null);
        String location = body.path("location").asText(null);

        StorageObjectRef originalRef = new StorageObjectRef(
                document.storageProviderId(), document.originalStorageKey(), document.originalHash());
        byte[] originalBytes = storageProvider.retrieve(originalRef);

        String signerIdentity = resolveSignerIdentity(req, appContext, appSlug);
        LocalPkiSigningService.SealResult sealed = signingService.seal(
                originalBytes, keyAlias, reason, location, signerIdentity);

        StorageObjectRef sealedRef = storageProvider.store(appSlug, documentId, "sealed", sealed.sealedPdfBytes());

        documentRepository.markSealed(documentId, sealedRef.storageKey(), sealed.sha256Hash());
        documentRepository.insertSeal(documentId, null, "local_pki", keyAlias, null, null, "PAdES-B-B", null, null);

        String actorType = appContext != null ? "APP" : "PLATFORM_USER";
        String actorId = appContext != null ? appContext.appId() : InputProcessor.getUserId(req);
        auditLogRepository.log(appId, documentId, "SEALED", actorType, actorId,
                req.getRemoteAddr(), req.getHeader("User-Agent"));

        ObjectNode json = MAPPER.createObjectNode();
        json.put("status", "SIGNED");
        json.put("signatureStandard", "PAdES-B-B");
        json.put("sealedAt", Instant.now().toString());
        json.put("sha256Checksum", sealed.sha256Hash());
        OutputProcessor.send(res, HttpServletResponse.SC_OK, json);
    }

    /**
     * Who to show on the visible Corporate Seal stamp's "Signed by" line: the
     * console user's email when a platform_user triggered the seal, or the
     * App's slug when an App triggered it via its own API key (no individual
     * human is involved in that case).
     */
    private String resolveSignerIdentity(HttpServletRequest req, AppContext appContext, String appSlug) {
        if (appContext != null) {
            return "App: " + appSlug;
        }
        return platformUserRepository.findById(InputProcessor.getUserId(req))
                .map(PlatformUserRepository.PlatformUserRecord::email)
                .orElse("App: " + appSlug);
    }

    /** Raw-file counterpart to Templates.generateDocument: no template, caller supplies the PDF bytes directly. */
    private void uploadDocument(HttpServletRequest req, HttpServletResponse res, JsonNode body, AppContext appContext)
            throws Exception {
        String documentTitle = body.path("documentTitle").asText(null);
        String fileContentBase64 = body.path("fileContentBase64").asText(null);
        if (documentTitle == null || fileContentBase64 == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request",
                    "documentTitle and fileContentBase64 are required.");
            return;
        }

        String appId;
        String appSlug;
        if (appContext != null) {
            appId = appContext.appId();
            appSlug = appContext.appSlug();
        } else {
            appId = body.path("appId").asText(null);
            if (appId == null) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "appId is required.");
                return;
            }
            if (!authorizationService.canWrite(InputProcessor.getUserRole(req), InputProcessor.getUserId(req), appId)) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "You do not have write access to this App.");
                return;
            }
            Optional<AppRepository.AppRecord> appOpt = appRepository.findById(appId);
            if (appOpt.isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such App.");
                return;
            }
            appSlug = appOpt.get().appSlug();
        }

        byte[] fileBytes;
        try {
            fileBytes = Base64.getDecoder().decode(fileContentBase64);
        } catch (IllegalArgumentException e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "fileContentBase64 is not valid base64.");
            return;
        }

        String documentId = UUID.randomUUID().toString();
        StorageObjectRef ref = storageProvider.store(appSlug, documentId, "original", fileBytes);
        String originalHash = HashUtil.sha256Hex(fileBytes);

        documentRepository.createDraftWithId(documentId, appId, null, documentTitle,
                ref.providerId(), ref.storageKey(), originalHash);

        String uploadActorType = appContext != null ? "APP" : "PLATFORM_USER";
        String uploadActorId = appContext != null ? appContext.appId() : InputProcessor.getUserId(req);
        auditLogRepository.log(appId, documentId, "DOCUMENT_UPLOADED", uploadActorType, uploadActorId,
                req.getRemoteAddr(), req.getHeader("User-Agent"));

        ObjectNode json = MAPPER.createObjectNode();
        json.put("documentId", documentId);
        json.put("status", "DRAFT");
        json.put("originalHashSha256", originalHash);
        json.put("storageKey", ref.storageKey());
        OutputProcessor.send(res, HttpServletResponse.SC_CREATED, json);
    }

    /** §9.4 GET — retrieves the latest sealed certificate PDF. TENANT only. */
    private void getLegalCertificate(HttpServletResponse res, JsonNode body, AppContext appContext) throws Exception {
        String documentId = body.path("documentId").asText(null);
        if (documentId == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "documentId is required.");
            return;
        }
        Optional<LegalCertificateRepository.CertificateRecord> certOpt =
                legalCertificateRepository.findLatestForApp(appContext.appId(), documentId);
        if (certOpt.isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No legal certificate for this document.");
            return;
        }
        LegalCertificateRepository.CertificateRecord cert = certOpt.get();
        byte[] pdfBytes = storageProvider.retrieve(new StorageObjectRef(
                cert.storageProviderId(), cert.certificateStorageKey(), cert.certificateHash()));
        writePdf(res, pdfBytes, "legal-certificate-v" + cert.version() + ".pdf");
    }

    /** §9.4/§10.4 "shortcut into Legal Evidence" — BOTH tenant (own App) and console (RBAC-checked). */
    private void generateLegalCertificate(HttpServletRequest req, HttpServletResponse res, JsonNode body, AppContext appContext)
            throws Exception {
        String documentId = body.path("documentId").asText(null);
        if (documentId == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "documentId is required.");
            return;
        }

        String appId;
        AppRepository.AppRecord app = null;
        if (appContext != null) {
            appId = appContext.appId();
        } else {
            appId = body.path("appId").asText(null);
            if (appId == null) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "appId is required.");
                return;
            }
            if (!authorizationService.canWrite(InputProcessor.getUserRole(req), InputProcessor.getUserId(req), appId)) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "You do not have write access to this App.");
                return;
            }
            Optional<AppRepository.AppRecord> appOpt = appRepository.findById(appId);
            if (appOpt.isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such App.");
                return;
            }
            app = appOpt.get();
        }

        Optional<DocumentRepository.DocumentRecord> documentOpt = documentRepository.findByIdForApp(appId, documentId);
        if (documentOpt.isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such document.");
            return;
        }
        DocumentRepository.DocumentRecord document = documentOpt.get();
        if (!"SIGNED".equals(document.status())) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict",
                    "Document must be sealed (SIGNED) before a legal certificate can be generated.");
            return;
        }

        String certifyingKeyAlias = body.path("certifyingKeyAlias").asText(null);
        AppContext certContext;
        if (appContext != null) {
            certContext = appContext;
            if (certifyingKeyAlias == null) {
                certifyingKeyAlias = appRepository.findDefaultKeyAlias(appId).orElse(null);
            }
        } else {
            certContext = new AppContext(app.appId(), app.appName(), app.appSlug(), app.rateLimitRpm());
            if (certifyingKeyAlias == null) {
                certifyingKeyAlias = app.defaultKeyAlias();
            }
        }
        if (certifyingKeyAlias == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request",
                    "certifyingKeyAlias is required: no default_key_alias is configured for this App.");
            return;
        }

        LegalCertificateService.GeneratedCertificate certificate =
                legalCertificateService.generate(certContext, document, certifyingKeyAlias);

        String actorType = appContext != null ? "APP" : "PLATFORM_USER";
        String actorId = appContext != null ? appContext.appId() : InputProcessor.getUserId(req);
        auditLogRepository.log(appId, documentId, "LEGAL_CERTIFICATE_GENERATED", actorType, actorId,
                req.getRemoteAddr(), req.getHeader("User-Agent"));

        ObjectNode json = MAPPER.createObjectNode();
        json.put("certificateId", certificate.certificateId());
        json.put("version", certificate.version());
        json.set("partA", certificate.partA());
        json.set("partB", certificate.partB());
        json.put("sha256Checksum", certificate.sha256Checksum());
        json.put("sealedAt", Instant.now().toString());
        OutputProcessor.send(res, HttpServletResponse.SC_CREATED, json);
    }

    /** §10.4 Documents & Audit Trail list. CONSOLE only. */
    private void listDocuments(HttpServletRequest req, HttpServletResponse res, JsonNode body) throws Exception {
        String appId = body.path("appId").asText(null);
        if (appId == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "appId is required.");
            return;
        }
        if (!authorizationService.canRead(InputProcessor.getUserRole(req), InputProcessor.getUserId(req), appId)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "You do not have access to this App.");
            return;
        }
        if (appRepository.findById(appId).isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such App.");
            return;
        }
        ArrayNode array = MAPPER.createArrayNode();
        for (DocumentRepository.DocumentSummary doc : documentRepository.listForApp(appId)) {
            ObjectNode node = array.addObject();
            node.put("documentId", doc.documentId());
            node.put("title", doc.title());
            node.put("templateName", doc.templateName());
            node.put("status", doc.status());
            node.put("createdAt", doc.createdAt());
        }
        OutputProcessor.send(res, HttpServletResponse.SC_OK, array);
    }

    /** §10.4 Document Detail: fields + seal(s) + full audit_logs timeline. CONSOLE only. */
    private void getDocument(HttpServletRequest req, HttpServletResponse res, JsonNode body) throws Exception {
        String appId = body.path("appId").asText(null);
        String documentId = body.path("documentId").asText(null);
        if (appId == null || documentId == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "appId and documentId are required.");
            return;
        }
        if (!authorizationService.canRead(InputProcessor.getUserRole(req), InputProcessor.getUserId(req), appId)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "You do not have access to this App.");
            return;
        }
        Optional<DocumentRepository.DocumentRecord> documentOpt = documentRepository.findByIdForApp(appId, documentId);
        if (documentOpt.isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such document.");
            return;
        }
        DocumentRepository.DocumentRecord document = documentOpt.get();

        ObjectNode json = MAPPER.createObjectNode();
        json.put("documentId", document.documentId());
        json.put("title", document.title());
        json.put("status", document.status());
        json.put("originalHash", document.originalHash());
        json.put("sealedHash", document.sealedHash());
        json.put("hasSealed", document.sealedStorageKey() != null);

        ArrayNode seals = json.putArray("seals");
        for (DocumentRepository.SealSummary seal : documentRepository.listSealsForDocument(documentId)) {
            ObjectNode node = seals.addObject();
            node.put("providerId", seal.providerId());
            node.put("keyAlias", seal.keyAlias());
            node.put("signatureStandard", seal.signatureStandard());
            node.put("sealedAt", seal.sealedAt());
        }

        ArrayNode timeline = json.putArray("auditTimeline");
        for (AuditLogRepository.AuditLogEntry entry : auditLogRepository.listForDocument(documentId)) {
            ObjectNode node = timeline.addObject();
            node.put("eventType", entry.eventType());
            node.put("actorType", entry.actorType());
            node.put("ipAddress", entry.ipAddress());
            node.put("createdAt", entry.createdAt());
        }

        legalCertificateRepository.findLatestForApp(appId, documentId).ifPresent(cert -> {
            ObjectNode certNode = json.putObject("latestLegalCertificate");
            certNode.put("certificateId", cert.certificateId());
            certNode.put("version", cert.version());
        });

        OutputProcessor.send(res, HttpServletResponse.SC_OK, json);
    }

    /** §10.4 "download the signed PDF" — falls back to the original render if not yet sealed. CONSOLE only. */
    private void downloadDocument(HttpServletRequest req, HttpServletResponse res, JsonNode body) throws Exception {
        String appId = body.path("appId").asText(null);
        String documentId = body.path("documentId").asText(null);
        if (appId == null || documentId == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "appId and documentId are required.");
            return;
        }
        if (!authorizationService.canRead(InputProcessor.getUserRole(req), InputProcessor.getUserId(req), appId)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "You do not have access to this App.");
            return;
        }
        Optional<DocumentRepository.DocumentRecord> documentOpt = documentRepository.findByIdForApp(appId, documentId);
        if (documentOpt.isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such document.");
            return;
        }
        DocumentRepository.DocumentRecord document = documentOpt.get();
        boolean sealed = document.sealedStorageKey() != null;
        String storageKey = sealed ? document.sealedStorageKey() : document.originalStorageKey();
        String hash = sealed ? document.sealedHash() : document.originalHash();

        byte[] pdfBytes = storageProvider.retrieve(new StorageObjectRef(document.storageProviderId(), storageKey, hash));
        writePdf(res, pdfBytes, (sealed ? "sealed" : "original") + ".pdf");
    }

    private void writePdf(HttpServletResponse res, byte[] pdfBytes, String filename) throws Exception {
        res.setStatus(HttpServletResponse.SC_OK);
        res.setContentType("application/pdf");
        res.setHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");
        res.getOutputStream().write(pdfBytes);
    }
}
