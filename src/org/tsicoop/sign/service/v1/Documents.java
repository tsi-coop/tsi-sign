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
import org.tsicoop.sign.esign.EsignSessionRepository;
import org.tsicoop.sign.esign.ExternalCmsSpliceService;
import org.tsicoop.sign.esign.MockAadhaarEsignAdapter;
import org.tsicoop.sign.esign.SigningSessionRequest;
import org.tsicoop.sign.esign.SigningSessionResponse;
import org.tsicoop.sign.pki.LocalKeyStoreProvider;
import org.tsicoop.sign.pki.LocalPkiSigningService;
import org.tsicoop.sign.pki.SignaturePlaceholderLocator;
import org.tsicoop.sign.storage.DocumentStorageProvider;
import org.tsicoop.sign.storage.StorageException;
import org.tsicoop.sign.storage.StorageObjectRef;
import org.tsicoop.sign.storage.StorageProviderRegistry;
import org.apache.pdfbox.pdmodel.PDDocument;

import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
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
 *  - list_documents, get_document, download_document, archive_document,
 *    unarchive_document: CONSOLE only (§10.4). Archiving is independent of
 *    signing-lifecycle status - it hides a document from the default list
 *    and freezes seal/eSign activity on it without changing its status.
 *    A bare API-key caller has no role, so AuthorizationService naturally
 *    403s these rather than needing a separate guard.
 */
public class Documents implements Action {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final AppRepository appRepository = new AppRepository();
    private final DocumentRepository documentRepository = new DocumentRepository();
    private final DocumentSignerRepository documentSignerRepository = new DocumentSignerRepository();
    private final SignerDiscoveryService signerDiscoveryService = new SignerDiscoveryService(documentSignerRepository);
    private final AuditLogRepository auditLogRepository = new AuditLogRepository();
    private final PlatformUserRepository platformUserRepository = new PlatformUserRepository();
    private final LegalCertificateRepository legalCertificateRepository = new LegalCertificateRepository();
    private final AuthorizationService authorizationService = new AuthorizationService();
    private final LocalPkiSigningService signingService;
    private final LegalCertificateService legalCertificateService;
    private final EsignSessionRepository esignSessionRepository = new EsignSessionRepository();
    private final ExternalCmsSpliceService externalCmsSpliceService = new ExternalCmsSpliceService();
    private final MockAadhaarEsignAdapter mockAadhaarEsignAdapter;

    public Documents() {
        try {
            signingService = new LocalPkiSigningService(new LocalKeyStoreProvider());
            mockAadhaarEsignAdapter = new MockAadhaarEsignAdapter(new LocalKeyStoreProvider(), consoleBaseUrl());
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize Local PKI signing service", e);
        }
        legalCertificateService = new LegalCertificateService(signingService);
    }

    /** Base URL the mock ESP's gatewayUrl is built against - overridable for non-default deployments. */
    private static String consoleBaseUrl() {
        String configured = System.getenv("CONSOLE_BASE_URL");
        return configured != null ? configured : "http://localhost:8088/console";
    }

    /**
     * Last-resort fallback when neither the request nor the App carries a
     * keyAlias - matches the Dockerfile's baked-in "tsi_corporate_seal" dev
     * key, so a fresh install can seal-local with zero per-App setup, per
     * that Dockerfile comment's own stated intent. A deployment that wants
     * to require every App to configure its own key explicitly (e.g.
     * production, once the dev keystore has been replaced) can disable
     * this by setting DEFAULT_KEY_ALIAS to an empty string.
     */
    private static String systemDefaultKeyAlias() {
        String configured = System.getenv("DEFAULT_KEY_ALIAS");
        if (configured != null) {
            return configured.isBlank() ? null : configured;
        }
        return "tsi_corporate_seal";
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
                case "initiate_esign":
                    initiateEsign(req, res, body, appContext);
                    break;
                case "get_esign_status":
                    getEsignStatus(req, res, body, appContext);
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
                case "archive_document":
                    setDocumentArchived(req, res, body, true);
                    break;
                case "unarchive_document":
                    setDocumentArchived(req, res, body, false);
                    break;
                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Unknown _func: " + func);
            }
        } catch (Exception e) {
            e.printStackTrace();
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
        if (document.archivedAt() != null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict",
                    "Document is archived; unarchive it first before sealing.");
            return;
        }
        if (!"DRAFT".equals(document.status()) && !"PARTIALLY_SIGNED".equals(document.status())) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict",
                    "Document is " + document.status() + "; cannot seal (must be DRAFT or PARTIALLY_SIGNED - " +
                    "PENDING means an Aadhaar eSign session is already in progress - deny or complete it first).");
            return;
        }

        String signerName = body.path("signerName").asText(null);
        if ("PARTIALLY_SIGNED".equals(document.status()) && (signerName == null || signerName.isBlank())) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request",
                    "signerName is required once a document is PARTIALLY_SIGNED - target the specific signer whose turn it is.");
            return;
        }
        if (signerName != null) {
            Optional<DocumentSignerRepository.DocumentSignerRecord> existing =
                    documentSignerRepository.findByAnchor(documentId, signerName);
            if (existing.isPresent() && "SIGNED".equals(existing.get().status())) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict",
                        "Signer '" + signerName + "' has already signed this document.");
                return;
            }
        }
        if (esignSessionRepository.findActiveForDocument(documentId).isPresent()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict",
                    "Another signer's Aadhaar eSign session is currently in progress on this document - " +
                    "complete or deny it first.");
            return;
        }

        DocumentStorageProvider storageProvider;
        try {
            storageProvider = StorageProviderRegistry.resolve(document.storageProviderId());
        } catch (StorageException e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error",
                    "Unsupported storage provider for this document: " + document.storageProviderId());
            return;
        }

        String keyAlias = body.path("keyAlias").asText(null);
        if (keyAlias == null) {
            keyAlias = appRepository.findDefaultKeyAlias(appId).orElse(null);
        }
        if (keyAlias == null) {
            keyAlias = systemDefaultKeyAlias();
        }
        if (keyAlias == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request",
                    "keyAlias is required: no default_key_alias is configured for this App.");
            return;
        }
        String reason = body.path("reason").asText(null);
        String location = body.path("location").asText(null);

        StorageObjectRef currentRef = currentVariantRef(document);
        byte[] currentBytes = storageProvider.retrieve(currentRef);

        String signerId;
        try {
            signerId = resolveSignerRow(documentId, currentBytes, signerName, "LOCAL_PKI", null, null);
        } catch (IllegalArgumentException e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", e.getMessage());
            return;
        }

        String signerIdentity = resolveSignerIdentity(req, appContext, appSlug);
        LocalPkiSigningService.SealResult sealed = signingService.seal(
                currentBytes, keyAlias, reason, location, signerIdentity, signerName);

        StorageObjectRef sealedRef = storageProvider.store(appSlug, documentId, "sealed", sealed.sealedPdfBytes());

        String newStatus = "SIGNED";
        if (signerId != null) {
            documentSignerRepository.markStatus(signerId, "SIGNED");
            newStatus = anyOtherSignerPending(documentId) ? "PARTIALLY_SIGNED" : "SIGNED";
        }

        boolean updated = documentRepository.markSealedIfHashMatches(
                documentId, sealedRef.storageKey(), sealed.sha256Hash(), document.sealedHash(), newStatus);
        if (!updated) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict",
                    "Another signature was just applied to this document - retry against the current version.");
            return;
        }
        documentRepository.insertSeal(documentId, signerId, "local_pki", keyAlias, null, null, "PAdES-B-B", null, null);

        String actorType = appContext != null ? "APP" : "PLATFORM_USER";
        String actorId = appContext != null ? appContext.appId() : InputProcessor.getUserId(req);
        auditLogRepository.log(appId, documentId, "SEALED", actorType, actorId,
                req.getRemoteAddr(), req.getHeader("User-Agent"));

        ObjectNode json = MAPPER.createObjectNode();
        json.put("status", newStatus);
        json.put("signatureStandard", "PAdES-B-B");
        json.put("sealedAt", Instant.now().toString());
        json.put("sha256Checksum", sealed.sha256Hash());
        OutputProcessor.send(res, HttpServletResponse.SC_OK, json);
    }

    /** sealedStorageKey if the document was already partially sealed, else the original render - "latest bytes". */
    private StorageObjectRef currentVariantRef(DocumentRepository.DocumentRecord document) {
        return document.sealedStorageKey() != null
                ? new StorageObjectRef(document.storageProviderId(), document.sealedStorageKey(), document.sealedHash())
                : new StorageObjectRef(document.storageProviderId(), document.originalStorageKey(), document.originalHash());
    }

    /**
     * Multi-signature documents (prep/TSI-Sign-Multi-Signature-Documents-Plan.md):
     * resolves the document_signers row for signerName, opportunistically
     * registering a PENDING placeholder row for every *other* still-blank
     * [[TSI_SIGNATURE:name]] marker found in the current bytes, so later
     * signers' turns and the PARTIALLY_SIGNED/SIGNED transition can be
     * tracked without needing the full signer set known up front.
     *
     * @return null when signerName is null (legacy "stamp everything in one
     *         shot" path - no per-signer bookkeeping at all); the resolved
     *         signerId otherwise.
     * @throws IllegalArgumentException if signerName doesn't match any
     *         marker in a document that does have markers.
     */
    private String resolveSignerRow(String documentId, byte[] currentBytes, String signerName, String signatureType,
                                     String signerEmail, String signerPhone) throws Exception {
        if (signerName == null) {
            return null;
        }
        Map<String, SignaturePlaceholderLocator.Placement> markers;
        try (PDDocument doc = PDDocument.load(currentBytes)) {
            markers = SignaturePlaceholderLocator.locate(doc);
        }
        if (markers.isEmpty()) {
            return documentSignerRepository.create(documentId, signerName, signerEmail, signerPhone, signatureType, null);
        }
        if (!markers.containsKey(signerName)) {
            throw new IllegalArgumentException("No [[TSI_SIGNATURE:" + signerName + "]] marker found in this document.");
        }
        for (String otherName : markers.keySet()) {
            if (!otherName.equals(signerName) && documentSignerRepository.findByAnchor(documentId, otherName).isEmpty()) {
                documentSignerRepository.create(documentId, otherName, null, null, "UNASSIGNED", otherName);
            }
        }
        Optional<DocumentSignerRepository.DocumentSignerRecord> existing =
                documentSignerRepository.findByAnchor(documentId, signerName);
        if (existing.isPresent()) {
            documentSignerRepository.updateSignatureType(existing.get().signerId(), signatureType);
            return existing.get().signerId();
        }
        return documentSignerRepository.create(documentId, signerName, signerEmail, signerPhone, signatureType, signerName);
    }

    private boolean anyOtherSignerPending(String documentId) throws Exception {
        for (DocumentSignerRepository.DocumentSignerRecord signer : documentSignerRepository.listForDocument(documentId)) {
            if ("PENDING".equals(signer.status())) {
                return true;
            }
        }
        return false;
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

    /**
     * Starts an Aadhaar eSign session (prep/TSI-Sign-Aadhaar-eSign-Plan.md):
     * reserves signature space in the PDF, persists just the bytes/offsets
     * needed to finish later (never a live PDFBox object - see
     * ExternalCmsSpliceService), and hands back a gatewayUrl for the
     * calling App to redirect its own end-user to for OTP/biometric auth.
     * Only the mock adapter is wired up in this deployment (Phase 1).
     */
    private void initiateEsign(HttpServletRequest req, HttpServletResponse res, JsonNode body, AppContext appContext)
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

        Optional<DocumentRepository.DocumentRecord> documentOpt = documentRepository.findByIdForApp(appId, documentId);
        if (documentOpt.isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such document.");
            return;
        }
        DocumentRepository.DocumentRecord document = documentOpt.get();
        if (document.archivedAt() != null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict",
                    "Document is archived; unarchive it first before initiating eSign.");
            return;
        }
        if (!"DRAFT".equals(document.status()) && !"PARTIALLY_SIGNED".equals(document.status())) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict",
                    "Document is " + document.status() + "; cannot initiate eSign (must be DRAFT or " +
                    "PARTIALLY_SIGNED - PENDING means an eSign session is already in progress).");
            return;
        }

        String signerName = body.path("signerName").asText(null);
        if (signerName == null || signerName.isBlank()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "signerName is required.");
            return;
        }
        Optional<DocumentSignerRepository.DocumentSignerRecord> existingSigner =
                documentSignerRepository.findByAnchor(documentId, signerName);
        if (existingSigner.isPresent() && "SIGNED".equals(existingSigner.get().status())) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict",
                    "Signer '" + signerName + "' has already signed this document.");
            return;
        }
        if (esignSessionRepository.findActiveForDocument(documentId).isPresent()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict",
                    "Another signer's Aadhaar eSign session is currently in progress on this document - " +
                    "complete or deny it first.");
            return;
        }
        String signerEmail = body.path("signerEmail").asText(null);
        String signerPhone = body.path("signerPhone").asText(null);
        String reason = body.path("reason").asText(null);

        DocumentStorageProvider storageProvider;
        try {
            storageProvider = StorageProviderRegistry.resolve(document.storageProviderId());
        } catch (StorageException e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error",
                    "Unsupported storage provider for this document: " + document.storageProviderId());
            return;
        }

        StorageObjectRef currentRef = currentVariantRef(document);
        byte[] currentBytes = storageProvider.retrieve(currentRef);

        ExternalCmsSpliceService.PreparedSigning prepared = externalCmsSpliceService.prepare(
                currentBytes, "Aadhaar eSign (Mock ESP)", signerName, reason, signerName);

        String signerId;
        try {
            signerId = resolveSignerRow(documentId, currentBytes, signerName, "AADHAAR_OTP", signerEmail, signerPhone);
        } catch (IllegalArgumentException e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", e.getMessage());
            return;
        }
        StorageObjectRef preparedRef = storageProvider.store(appSlug, documentId, "pending-esign", prepared.contentToHash());

        SigningSessionRequest sessionRequest = new SigningSessionRequest(documentId, appId, signerName, signerEmail,
                signerPhone, HashUtil.sha256Hex(currentBytes), reason);
        SigningSessionResponse sessionResponse = mockAadhaarEsignAdapter.initiateSigning(sessionRequest);

        esignSessionRepository.create(documentId, signerId, MockAadhaarEsignAdapter.PROVIDER_ID,
                sessionResponse.transactionId(), preparedRef.storageKey(), prepared.byteRange(),
                prepared.signatureFieldName(), sessionResponse.gatewayUrl());

        documentRepository.markPending(documentId);

        String actorType = appContext != null ? "APP" : "PLATFORM_USER";
        String actorId = appContext != null ? appContext.appId() : InputProcessor.getUserId(req);
        auditLogRepository.log(appId, documentId, "ESIGN_INITIATED", actorType, actorId,
                req.getRemoteAddr(), req.getHeader("User-Agent"));

        ObjectNode json = MAPPER.createObjectNode();
        json.put("status", "INITIATED");
        json.put("transactionId", sessionResponse.transactionId());
        json.put("gatewayUrl", sessionResponse.gatewayUrl());
        OutputProcessor.send(res, HttpServletResponse.SC_OK, json);
    }

    /** Lets the calling App (or the console) poll an in-flight eSign session instead of holding a connection open. */
    private void getEsignStatus(HttpServletRequest req, HttpServletResponse res, JsonNode body, AppContext appContext)
            throws Exception {
        String documentId = body.path("documentId").asText(null);
        if (documentId == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "documentId is required.");
            return;
        }

        String appId;
        if (appContext != null) {
            appId = appContext.appId();
        } else {
            appId = body.path("appId").asText(null);
            if (appId == null) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "appId is required.");
                return;
            }
            if (!authorizationService.canRead(InputProcessor.getUserRole(req), InputProcessor.getUserId(req), appId)) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "You do not have access to this App.");
                return;
            }
        }

        Optional<DocumentRepository.DocumentRecord> documentOpt = documentRepository.findByIdForApp(appId, documentId);
        if (documentOpt.isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such document.");
            return;
        }
        List<DocumentSignerRepository.DocumentSignerRecord> signers = documentSignerRepository.listForDocument(documentId);

        ObjectNode json = MAPPER.createObjectNode();
        json.put("documentStatus", documentOpt.get().status());
        ArrayNode signersArray = json.putArray("signers");
        for (DocumentSignerRepository.DocumentSignerRecord signer : signers) {
            ObjectNode node = signersArray.addObject();
            node.put("signerId", signer.signerId());
            node.put("signerName", signer.signerName());
            node.put("signatureType", signer.signatureType());
            node.put("anchorElementId", signer.anchorElementId());
            node.put("status", signer.status());
            node.put("signedAt", signer.signedAt());
        }
        OutputProcessor.send(res, HttpServletResponse.SC_OK, json);
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
        String appStorageProviderId;
        if (appContext != null) {
            appId = appContext.appId();
            appSlug = appContext.appSlug();
            appStorageProviderId = appRepository.findById(appId).map(AppRepository.AppRecord::storageProviderId).orElse(null);
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
            appStorageProviderId = appOpt.get().storageProviderId();
        }

        byte[] fileBytes;
        try {
            fileBytes = Base64.getDecoder().decode(fileContentBase64);
        } catch (IllegalArgumentException e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "fileContentBase64 is not valid base64.");
            return;
        }

        String documentId = UUID.randomUUID().toString();
        DocumentStorageProvider storageProvider = StorageProviderRegistry.resolveForWrite(appStorageProviderId);
        StorageObjectRef ref = storageProvider.store(appSlug, documentId, "original", fileBytes);
        String originalHash = HashUtil.sha256Hex(fileBytes);

        documentRepository.createDraftWithId(documentId, appId, null, documentTitle,
                ref.providerId(), ref.storageKey(), originalHash);
        signerDiscoveryService.discoverMarkers(documentId, fileBytes);

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
        byte[] pdfBytes = StorageProviderRegistry.resolve(cert.storageProviderId()).retrieve(new StorageObjectRef(
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
            certifyingKeyAlias = systemDefaultKeyAlias();
        }
        if (certifyingKeyAlias == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request",
                    "certifyingKeyAlias is required: no default_key_alias is configured for this App.");
            return;
        }

        DocumentStorageProvider storageProvider;
        try {
            storageProvider = StorageProviderRegistry.resolve(document.storageProviderId());
        } catch (StorageException e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error",
                    "Unsupported storage provider for this document: " + document.storageProviderId());
            return;
        }
        LegalCertificateService.GeneratedCertificate certificate =
                legalCertificateService.generate(certContext, document, certifyingKeyAlias, storageProvider);

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
        boolean includeArchived = body.path("includeArchived").asBoolean(false);
        String search = body.path("search").asText(null);
        InputProcessor.Page paging = InputProcessor.parsePaging(body);
        ArrayNode array = MAPPER.createArrayNode();
        for (DocumentRepository.DocumentSummary doc :
                documentRepository.listForApp(appId, includeArchived, search, paging.page(), paging.pageSize())) {
            ObjectNode node = array.addObject();
            node.put("documentId", doc.documentId());
            node.put("title", doc.title());
            node.put("templateName", doc.templateName());
            node.put("status", doc.status());
            node.put("createdAt", doc.createdAt());
            node.put("archivedAt", doc.archivedAt());
        }
        int totalCount = documentRepository.countForApp(appId, includeArchived, search);
        ObjectNode json = MAPPER.createObjectNode();
        json.set("documents", array);
        json.put("totalCount", totalCount);
        json.put("page", paging.page());
        json.put("pageSize", paging.pageSize());
        json.put("totalPages", Math.max(1, (totalCount + paging.pageSize() - 1) / paging.pageSize()));
        OutputProcessor.send(res, HttpServletResponse.SC_OK, json);
    }

    /** Archive/unarchive a document. CONSOLE only - freezes it against further seal/eSign activity until unarchived. */
    private void setDocumentArchived(HttpServletRequest req, HttpServletResponse res, JsonNode body, boolean archived)
            throws Exception {
        String appId = body.path("appId").asText(null);
        String documentId = body.path("documentId").asText(null);
        if (appId == null || documentId == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "appId and documentId are required.");
            return;
        }
        if (!authorizationService.canWrite(InputProcessor.getUserRole(req), InputProcessor.getUserId(req), appId)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "You do not have write access to this App.");
            return;
        }
        boolean updated = archived
                ? documentRepository.archive(appId, documentId)
                : documentRepository.unarchive(appId, documentId);
        if (!updated) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such document.");
            return;
        }
        auditLogRepository.log(appId, documentId, archived ? "DOCUMENT_ARCHIVED" : "DOCUMENT_UNARCHIVED",
                "PLATFORM_USER", InputProcessor.getUserId(req), req.getRemoteAddr(), req.getHeader("User-Agent"));
        ObjectNode json = MAPPER.createObjectNode();
        json.put("documentId", documentId);
        json.put("archived", archived);
        OutputProcessor.send(res, HttpServletResponse.SC_OK, json);
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
        json.put("archivedAt", document.archivedAt());

        ArrayNode seals = json.putArray("seals");
        for (DocumentRepository.SealSummary seal : documentRepository.listSealsForDocument(documentId)) {
            ObjectNode node = seals.addObject();
            node.put("providerId", seal.providerId());
            node.put("keyAlias", seal.keyAlias());
            node.put("signatureStandard", seal.signatureStandard());
            node.put("sealedAt", seal.sealedAt());
        }

        ArrayNode signers = json.putArray("signers");
        for (DocumentSignerRepository.DocumentSignerRecord signer : documentSignerRepository.listForDocument(documentId)) {
            ObjectNode node = signers.addObject();
            node.put("signerId", signer.signerId());
            node.put("signerName", signer.signerName());
            node.put("signatureType", signer.signatureType());
            node.put("anchorElementId", signer.anchorElementId());
            node.put("status", signer.status());
            node.put("signedAt", signer.signedAt());
            if ("PENDING".equals(signer.status())) {
                Optional<EsignSessionRepository.EsignSessionRecord> activeSession =
                        esignSessionRepository.findActiveForSigner(signer.signerId());
                if (activeSession.isPresent()) {
                    node.put("gatewayUrl", activeSession.get().gatewayUrl());
                }
            }
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

        byte[] pdfBytes = StorageProviderRegistry.resolve(document.storageProviderId())
                .retrieve(new StorageObjectRef(document.storageProviderId(), storageKey, hash));
        writePdf(res, pdfBytes, (sealed ? "sealed" : "original") + ".pdf");
    }

    private void writePdf(HttpServletResponse res, byte[] pdfBytes, String filename) throws Exception {
        res.setStatus(HttpServletResponse.SC_OK);
        res.setContentType("application/pdf");
        res.setHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");
        res.getOutputStream().write(pdfBytes);
    }
}
