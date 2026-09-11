package org.tsicoop.sign.service.v1;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.tsicoop.sign.framework.Action;
import org.tsicoop.sign.framework.InputProcessor;
import org.tsicoop.sign.framework.OutputProcessor;
import org.tsicoop.sign.storage.DocumentStorageProvider;
import org.tsicoop.sign.storage.LocalFilesystemStorageProvider;
import org.tsicoop.sign.storage.StorageObjectRef;

import java.util.Optional;

/**
 * §10.5 Legal Evidence registry + Certificate Detail, RBAC-scoped per §10.9:
 * PLATFORM_ADMIN/AUDITOR see everything, APP_MANAGER only their assigned
 * Apps. Certifying Officers assignment and the counsel-approval flag are
 * left for a later chunk — both depend on open decisions §12.4/§12.5 the
 * plan has not resolved yet.
 * funcs: list_registry, get_certificate, download_certificate.
 */
public class LegalCertificates implements Action {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final LegalCertificateRepository certificateRepository = new LegalCertificateRepository();
    private final DocumentRepository documentRepository = new DocumentRepository();
    private final DocumentStorageProvider storageProvider = new LocalFilesystemStorageProvider();
    private final AuthorizationService authorizationService = new AuthorizationService();

    @Override
    public boolean validate(String method, HttpServletRequest req, HttpServletResponse res) {
        return true;
    }

    @Override
    public void post(HttpServletRequest req, HttpServletResponse res) {
        JsonNode body = InputProcessor.getInput(req);
        String func = body.path("_func").asText("");
        String role = InputProcessor.getUserRole(req);
        String userId = InputProcessor.getUserId(req);

        try {
            switch (func) {
                case "list_registry":
                    listRegistry(res, role, userId);
                    break;
                case "get_certificate":
                    getCertificate(body, res, role, userId);
                    break;
                case "download_certificate":
                    downloadCertificate(body, res, role, userId);
                    break;
                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Unknown _func: " + func);
            }
        } catch (Exception e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", e.getMessage());
        }
    }

    private void listRegistry(HttpServletResponse res, String role, String userId) throws Exception {
        ArrayNode array = MAPPER.createArrayNode();
        for (LegalCertificateRepository.RegistryEntry entry : certificateRepository.listAll()) {
            if (!authorizationService.canRead(role, userId, entry.appId())) {
                continue;
            }
            ObjectNode node = array.addObject();
            node.put("certificateId", entry.certificateId());
            node.put("documentId", entry.documentId());
            node.put("documentTitle", entry.documentTitle());
            node.put("appId", entry.appId());
            node.put("appName", entry.appName());
            node.put("version", entry.version());
            node.put("certificateHash", entry.certificateHash());
            node.put("createdAt", entry.createdAt());
        }
        OutputProcessor.send(res, HttpServletResponse.SC_OK, array);
    }

    private void getCertificate(JsonNode body, HttpServletResponse res, String role, String userId) throws Exception {
        String certificateId = body.path("certificateId").asText(null);
        if (certificateId == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "certificateId is required.");
            return;
        }
        Optional<LegalCertificateRepository.CertificateRecord> certOpt = certificateRepository.findById(certificateId);
        if (certOpt.isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such legal certificate.");
            return;
        }
        LegalCertificateRepository.CertificateRecord cert = certOpt.get();
        if (!authorizationService.canRead(role, userId, cert.appId())) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "You do not have access to this certificate.");
            return;
        }
        Optional<DocumentRepository.DocumentRecord> documentOpt =
                documentRepository.findByIdForApp(cert.appId(), cert.documentId());

        ObjectNode json = MAPPER.createObjectNode();
        json.put("certificateId", cert.certificateId());
        json.put("appId", cert.appId());
        json.put("version", cert.version());
        json.set("partA", MAPPER.readTree(cert.partAJson()));
        json.set("partB", MAPPER.readTree(cert.partBJson()));
        json.put("certificateHash", cert.certificateHash());
        documentOpt.ifPresent(document -> {
            json.put("documentId", document.documentId());
            json.put("documentTitle", document.title());
            json.put("documentStatus", document.status());
            json.put("documentOriginalHash", document.originalHash());
            json.put("documentSealedHash", document.sealedHash());
        });
        OutputProcessor.send(res, HttpServletResponse.SC_OK, json);
    }

    private void downloadCertificate(JsonNode body, HttpServletResponse res, String role, String userId) throws Exception {
        String certificateId = body.path("certificateId").asText(null);
        if (certificateId == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "certificateId is required.");
            return;
        }
        Optional<LegalCertificateRepository.CertificateRecord> certOpt = certificateRepository.findById(certificateId);
        if (certOpt.isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such legal certificate.");
            return;
        }
        LegalCertificateRepository.CertificateRecord cert = certOpt.get();
        if (!authorizationService.canRead(role, userId, cert.appId())) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "You do not have access to this certificate.");
            return;
        }
        byte[] pdfBytes = storageProvider.retrieve(new StorageObjectRef(
                cert.storageProviderId(), cert.certificateStorageKey(), cert.certificateHash()));

        res.setStatus(HttpServletResponse.SC_OK);
        res.setContentType("application/pdf");
        res.setHeader("Content-Disposition", "attachment; filename=\"legal-certificate-v" + cert.version() + ".pdf\"");
        res.getOutputStream().write(pdfBytes);
    }
}
