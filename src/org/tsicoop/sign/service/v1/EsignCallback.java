package org.tsicoop.sign.service.v1;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.tsicoop.sign.esign.EsignSessionRepository;
import org.tsicoop.sign.esign.ExternalCmsSpliceService;
import org.tsicoop.sign.esign.MockAadhaarEsignAdapter;
import org.tsicoop.sign.esign.SigningResult;
import org.tsicoop.sign.framework.Action;
import org.tsicoop.sign.framework.HashUtil;
import org.tsicoop.sign.framework.InputProcessor;
import org.tsicoop.sign.framework.OutputProcessor;
import org.tsicoop.sign.pki.LocalKeyStoreProvider;
import org.tsicoop.sign.storage.DocumentStorageProvider;
import org.tsicoop.sign.storage.StorageObjectRef;
import org.tsicoop.sign.storage.StorageProviderRegistry;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;

/**
 * PUBLIC (prep/TSI-Sign-Aadhaar-eSign-Plan.md): the ESP itself calls this,
 * not an App or a console session, so there is no X-API-Key/session to
 * check here. Today only the mock consent page's own funcs exist -
 * {@code mock_session_info}/{@code mock_preview_document} (read-only, let
 * the page show what/who it's asking to sign without exposing any real
 * API), {@code mock_approve}/{@code mock_deny} (its Approve/Deny actions,
 * standing in for a real ESP's callback). A real adapter's callback
 * ({@code process_callback}, verified against that provider's own signing
 * certificate) is not wired up in this deployment, since no CCA-licensed
 * ESP credentials exist here (see the plan's explicit scope limits).
 */
public class EsignCallback implements Action {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final EsignSessionRepository esignSessionRepository = new EsignSessionRepository();
    private final DocumentSignerRepository documentSignerRepository = new DocumentSignerRepository();
    private final DocumentRepository documentRepository = new DocumentRepository();
    private final AppRepository appRepository = new AppRepository();
    private final AuditLogRepository auditLogRepository = new AuditLogRepository();
    private final ExternalCmsSpliceService spliceService = new ExternalCmsSpliceService();
    private final MockAadhaarEsignAdapter mockAdapter;

    public EsignCallback() {
        try {
            // consoleBaseUrl is irrelevant here - only initiateSigning() (called from Documents.java) uses it.
            mockAdapter = new MockAadhaarEsignAdapter(new LocalKeyStoreProvider(), null);
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize mock Aadhaar eSign adapter", e);
        }
    }

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        return true;
    }

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JsonNode body = InputProcessor.getInput(req);
        String func = body.path("_func").asText("");
        try {
            switch (func) {
                case "mock_session_info":
                    mockSessionInfo(res, body);
                    break;
                case "mock_preview_document":
                    mockPreviewDocument(res, body);
                    break;
                case "mock_approve":
                    mockApprove(req, res, body);
                    break;
                case "mock_deny":
                    mockDeny(req, res, body);
                    break;
                case "process_callback":
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_IMPLEMENTED, "Not Implemented",
                            "No real ESP adapter is configured in this deployment - only the mock adapter (mock_approve) is wired up.");
                    break;
                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Unknown _func: " + func);
            }
        } catch (Exception e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", e.getMessage());
        }
    }

    /** Lets the mock consent page show who/what it's approving on behalf of, without exposing any real API. */
    private void mockSessionInfo(HttpServletResponse res, JsonNode body) throws Exception {
        String transactionId = body.path("transactionId").asText(null);
        if (transactionId == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "transactionId is required.");
            return;
        }
        Optional<EsignSessionRepository.EsignSessionRecord> sessionOpt =
                esignSessionRepository.findByTransactionId(MockAadhaarEsignAdapter.PROVIDER_ID, transactionId);
        if (sessionOpt.isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such eSign session.");
            return;
        }
        EsignSessionRepository.EsignSessionRecord session = sessionOpt.get();
        Optional<DocumentSignerRepository.DocumentSignerRecord> signerOpt = documentSignerRepository.findById(session.signerId());
        Optional<DocumentRepository.DocumentRecord> documentOpt = documentRepository.findById(session.documentId());

        ObjectNode json = MAPPER.createObjectNode();
        json.put("status", session.status());
        json.put("signerName", signerOpt.map(DocumentSignerRepository.DocumentSignerRecord::signerName).orElse(null));
        json.put("documentTitle", documentOpt.map(DocumentRepository.DocumentRecord::title).orElse(null));
        OutputProcessor.send(res, HttpServletResponse.SC_OK, json);
    }

    /**
     * Lets the mock consent page show the actual PDF bytes about to be
     * signed (the same reserved-signature-space content that gets hashed
     * and sent for OTP consent), so a signer isn't asked to approve a
     * document they can't see. Same trust boundary as mockSessionInfo -
     * gated purely by knowledge of transactionId, no session/API key.
     */
    private void mockPreviewDocument(HttpServletResponse res, JsonNode body) throws Exception {
        String transactionId = body.path("transactionId").asText(null);
        if (transactionId == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "transactionId is required.");
            return;
        }
        Optional<EsignSessionRepository.EsignSessionRecord> sessionOpt =
                esignSessionRepository.findByTransactionId(MockAadhaarEsignAdapter.PROVIDER_ID, transactionId);
        if (sessionOpt.isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such eSign session.");
            return;
        }
        EsignSessionRepository.EsignSessionRecord session = sessionOpt.get();
        Optional<DocumentRepository.DocumentRecord> documentOpt = documentRepository.findById(session.documentId());
        if (documentOpt.isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Document no longer exists.");
            return;
        }
        DocumentRepository.DocumentRecord document = documentOpt.get();

        DocumentStorageProvider storageProvider;
        try {
            storageProvider = StorageProviderRegistry.resolve(document.storageProviderId());
        } catch (Exception e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error",
                    "Unsupported storage provider for this document: " + document.storageProviderId());
            return;
        }
        StorageObjectRef preparedRef = new StorageObjectRef(document.storageProviderId(), session.preparedStorageKey(), null);
        byte[] pdfBytes = storageProvider.retrieve(preparedRef);

        res.setStatus(HttpServletResponse.SC_OK);
        res.setContentType("application/pdf");
        res.setHeader("Content-Disposition", "inline; filename=\"preview.pdf\"");
        res.getOutputStream().write(pdfBytes);
    }

    private void mockDeny(HttpServletRequest req, HttpServletResponse res, JsonNode body) throws Exception {
        String transactionId = body.path("transactionId").asText(null);
        if (transactionId == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "transactionId is required.");
            return;
        }
        Optional<EsignSessionRepository.EsignSessionRecord> sessionOpt =
                esignSessionRepository.findByTransactionId(MockAadhaarEsignAdapter.PROVIDER_ID, transactionId);
        if (sessionOpt.isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such eSign session.");
            return;
        }
        EsignSessionRepository.EsignSessionRecord session = sessionOpt.get();
        if (!"INITIATED".equals(session.status())) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict",
                    "This eSign session is already " + session.status() + ".");
            return;
        }
        esignSessionRepository.markStatus(session.sessionId(), "FAILED");
        documentSignerRepository.markStatus(session.signerId(), "FAILED");

        // Revert PENDING back to whatever it was before this in-flight session: PARTIALLY_SIGNED
        // if another signer already completed their turn on this document, else DRAFT.
        boolean anySignerAlreadySigned = documentSignerRepository.listForDocument(session.documentId()).stream()
                .anyMatch(s -> "SIGNED".equals(s.status()));
        documentRepository.markStatus(session.documentId(), anySignerAlreadySigned ? "PARTIALLY_SIGNED" : "DRAFT");

        Optional<DocumentRepository.DocumentRecord> documentOpt = documentRepository.findById(session.documentId());
        if (documentOpt.isPresent()) {
            DocumentRepository.DocumentRecord document = documentOpt.get();
            auditLogRepository.log(document.appId(), document.documentId(), "ESIGN_DENIED", "SYSTEM",
                    session.signerId(), req.getRemoteAddr(), req.getHeader("User-Agent"));
        }

        ObjectNode json = MAPPER.createObjectNode();
        json.put("status", "DENIED");
        OutputProcessor.send(res, HttpServletResponse.SC_OK, json);
    }

    private void mockApprove(HttpServletRequest req, HttpServletResponse res, JsonNode body) throws Exception {
        String transactionId = body.path("transactionId").asText(null);
        if (transactionId == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "transactionId is required.");
            return;
        }

        Optional<EsignSessionRepository.EsignSessionRecord> sessionOpt =
                esignSessionRepository.findByTransactionId(MockAadhaarEsignAdapter.PROVIDER_ID, transactionId);
        if (sessionOpt.isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such eSign session.");
            return;
        }
        EsignSessionRepository.EsignSessionRecord session = sessionOpt.get();
        if (!"INITIATED".equals(session.status())) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict",
                    "This eSign session is already " + session.status() + ".");
            return;
        }

        Optional<DocumentSignerRepository.DocumentSignerRecord> signerOpt =
                documentSignerRepository.findById(session.signerId());
        Optional<DocumentRepository.DocumentRecord> documentOpt = documentRepository.findById(session.documentId());
        if (signerOpt.isEmpty() || documentOpt.isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Signer or document no longer exists.");
            return;
        }
        DocumentSignerRepository.DocumentSignerRecord signer = signerOpt.get();
        DocumentRepository.DocumentRecord document = documentOpt.get();

        DocumentStorageProvider storageProvider;
        try {
            storageProvider = StorageProviderRegistry.resolve(document.storageProviderId());
        } catch (Exception e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error",
                    "Unsupported storage provider for this document: " + document.storageProviderId());
            return;
        }

        StorageObjectRef preparedRef = new StorageObjectRef(
                document.storageProviderId(), session.preparedStorageKey(), null);
        byte[] contentToHash = storageProvider.retrieve(preparedRef);

        SigningResult result = mockAdapter.signApproved(transactionId, contentToHash, signer.signerName());
        if (!result.success()) {
            esignSessionRepository.markStatus(session.sessionId(), "FAILED");
            documentSignerRepository.markStatus(signer.signerId(), "FAILED");
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error",
                    result.failureReason());
            return;
        }

        byte[] sealedBytes = spliceService.finalizeSignature(contentToHash, session.byteRange(), result.pkcs7Signature());

        Optional<AppRepository.AppRecord> appOpt = appRepository.findById(document.appId());
        String appSlug = appOpt.map(AppRepository.AppRecord::appSlug).orElse("app");

        StorageObjectRef sealedRef = storageProvider.store(appSlug, document.documentId(), "sealed", sealedBytes);

        documentSignerRepository.markStatus(signer.signerId(), "SIGNED");
        boolean anyStillPending = documentSignerRepository.listForDocument(document.documentId()).stream()
                .anyMatch(s -> "PENDING".equals(s.status()));
        String newStatus = anyStillPending ? "PARTIALLY_SIGNED" : "SIGNED";

        boolean updated = documentRepository.markSealedIfHashMatches(document.documentId(), sealedRef.storageKey(),
                HashUtil.sha256Hex(sealedBytes), document.sealedHash(), newStatus);
        if (!updated) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_CONFLICT, "Conflict",
                    "Another signature was just applied to this document - retry.");
            return;
        }
        documentRepository.insertSeal(document.documentId(), signer.signerId(), MockAadhaarEsignAdapter.PROVIDER_ID,
                null, transactionId, Base64.getEncoder().encodeToString(result.pkcs7Signature()), "PAdES-B-B",
                result.caIssuer(), result.authType());
        esignSessionRepository.markStatus(session.sessionId(), "COMPLETED");

        auditLogRepository.log(document.appId(), document.documentId(), "ESIGN_COMPLETED", "SYSTEM",
                signer.signerId(), req.getRemoteAddr(), req.getHeader("User-Agent"));

        dispatchWebhook(appOpt.orElse(null), document.documentId());

        ObjectNode json = MAPPER.createObjectNode();
        json.put("status", newStatus);
        OutputProcessor.send(res, HttpServletResponse.SC_OK, json);
    }

    /** Best-effort - a slow/broken webhook must never fail the signing transaction itself. */
    private void dispatchWebhook(AppRepository.AppRecord app, String documentId) {
        if (app == null || app.webhookUrl() == null || app.webhookUrl().isBlank()) {
            return;
        }
        try {
            ObjectNode payload = MAPPER.createObjectNode();
            payload.put("event", "esign.completed");
            payload.put("documentId", documentId);
            payload.put("appId", app.appId());

            HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(app.webhookUrl()))
                    .timeout(Duration.ofSeconds(5))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(payload.toString()))
                    .build();
            HttpResponse<Void> ignored = client.send(request, HttpResponse.BodyHandlers.discarding());
        } catch (Exception e) {
            System.err.println("EsignCallback: webhook dispatch to " + app.webhookUrl() + " failed: " +
                    e.getClass().getSimpleName() + (e.getMessage() != null ? ": " + e.getMessage() : ""));
        }
    }
}
