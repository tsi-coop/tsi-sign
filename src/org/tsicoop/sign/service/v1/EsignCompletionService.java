package org.tsicoop.sign.service.v1;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.tsicoop.sign.esign.ESignAdapter;
import org.tsicoop.sign.esign.EsignSessionRepository;
import org.tsicoop.sign.esign.ExternalCmsSpliceService;
import org.tsicoop.sign.esign.SigningResult;
import org.tsicoop.sign.framework.HashUtil;
import org.tsicoop.sign.pki.SignatureTimestamper;
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
 * Finishes (or fails) an in-flight eSign session from a CA callback - provider-independent: the
 * adapter authenticates/parses the callback, everything after that (splice the CMS into the
 * prepared PDF, store, mark signer/document status, seal row, audit, webhook) is identical for
 * every CA.
 */
public class EsignCompletionService {

    public enum Kind {
        /** Signature spliced into the PDF and recorded. */
        COMPLETED,
        /** The CA reported (authentically) that signing did not happen - session and signer marked FAILED. */
        FAILED,
        /** The callback could not be authenticated/validated - nothing changed. */
        REJECTED,
        /** Session already finished, or a concurrent signature won the race. */
        CONFLICT
    }

    public record Outcome(Kind kind, String message, String documentStatus) {
    }

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final EsignSessionRepository esignSessionRepository = new EsignSessionRepository();
    private final DocumentSignerRepository documentSignerRepository = new DocumentSignerRepository();
    private final DocumentRepository documentRepository = new DocumentRepository();
    private final AppRepository appRepository = new AppRepository();
    private final AuditLogRepository auditLogRepository = new AuditLogRepository();
    private final ExternalCmsSpliceService spliceService = new ExternalCmsSpliceService();

    public Outcome handleCallback(ESignAdapter adapter, EsignSessionRepository.EsignSessionRecord session,
            JsonNode callbackPayload, String ip, String userAgent) throws Exception {
        if (!"INITIATED".equals(session.status())) {
            return new Outcome(Kind.CONFLICT, "This eSign session is already " + session.status() + ".", null);
        }
        Optional<DocumentSignerRepository.DocumentSignerRecord> signerOpt = documentSignerRepository.findById(session.signerId());
        Optional<DocumentRepository.DocumentRecord> documentOpt = documentRepository.findById(session.documentId());
        if (signerOpt.isEmpty() || documentOpt.isEmpty()) {
            return new Outcome(Kind.REJECTED, "Signer or document no longer exists.", null);
        }
        DocumentSignerRepository.DocumentSignerRecord signer = signerOpt.get();
        DocumentRepository.DocumentRecord document = documentOpt.get();

        DocumentStorageProvider storageProvider = StorageProviderRegistry.resolve(document.storageProviderId());
        byte[] contentToHash = storageProvider.retrieve(
                new StorageObjectRef(document.storageProviderId(), session.preparedStorageKey(), null));

        SigningResult result = adapter.processCallback(callbackPayload, HashUtil.sha256Hex(contentToHash));
        if (!result.trusted() || (result.transactionId() != null && !result.transactionId().equals(session.transactionId()))) {
            auditLogRepository.log(document.appId(), document.documentId(), "ESIGN_CALLBACK_REJECTED", "SYSTEM", null, ip, userAgent);
            return new Outcome(Kind.REJECTED, result.failureReason() != null ? result.failureReason()
                    : "Callback transaction does not match the session.", null);
        }
        if (!result.success()) {
            fail(session, document, signer.signerId(), ip, userAgent);
            return new Outcome(Kind.FAILED, result.failureReason(), null);
        }

        SignatureTimestamper.Result stamped = SignatureTimestamper.fromEnv().apply(result.pkcs7Signature());
        byte[] sealedBytes = spliceService.finalizeSignature(contentToHash, session.byteRange(), stamped.cms());
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
            return new Outcome(Kind.CONFLICT, "Another signature was just applied to this document - retry.", null);
        }
        documentRepository.insertSeal(document.documentId(), signer.signerId(), session.providerId(),
                null, session.transactionId(), Base64.getEncoder().encodeToString(stamped.cms()), stamped.signatureStandard(),
                result.caIssuer(), result.authType());
        esignSessionRepository.markStatus(session.sessionId(), "COMPLETED");
        auditLogRepository.log(document.appId(), document.documentId(), "ESIGN_COMPLETED", "SYSTEM",
                signer.signerId(), ip, userAgent);
        dispatchWebhook(appOpt.orElse(null), document.documentId());
        return new Outcome(Kind.COMPLETED, "Signed.", newStatus);
    }

    private void fail(EsignSessionRepository.EsignSessionRecord session, DocumentRepository.DocumentRecord document,
            String signerId, String ip, String userAgent) throws Exception {
        esignSessionRepository.markStatus(session.sessionId(), "FAILED");
        documentSignerRepository.markStatus(signerId, "FAILED");
        // Revert PENDING to what it was before this in-flight session: PARTIALLY_SIGNED if another
        // signer already completed their turn, else DRAFT.
        boolean anySignerAlreadySigned = documentSignerRepository.listForDocument(document.documentId()).stream()
                .anyMatch(s -> "SIGNED".equals(s.status()));
        documentRepository.markStatus(document.documentId(), anySignerAlreadySigned ? "PARTIALLY_SIGNED" : "DRAFT");
        auditLogRepository.log(document.appId(), document.documentId(), "ESIGN_DENIED", "SYSTEM", signerId, ip, userAgent);
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
            client.send(request, HttpResponse.BodyHandlers.discarding());
        } catch (Exception e) {
            System.err.println("EsignCompletionService: webhook dispatch to " + app.webhookUrl() + " failed: " +
                    e.getClass().getSimpleName() + (e.getMessage() != null ? ": " + e.getMessage() : ""));
        }
    }
}
