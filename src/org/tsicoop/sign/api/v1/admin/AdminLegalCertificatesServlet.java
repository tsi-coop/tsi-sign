package org.tsicoop.sign.api.v1.admin;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.tsicoop.sign.admin.AdminAuthorizationService;
import org.tsicoop.sign.document.DocumentRepository;
import org.tsicoop.sign.legal.LegalCertificateRepository;
import org.tsicoop.sign.security.ConsoleSessionAuthenticationFilter;
import org.tsicoop.sign.storage.DocumentStorageProvider;
import org.tsicoop.sign.storage.LocalFilesystemStorageProvider;
import org.tsicoop.sign.storage.StorageObjectRef;

import java.io.IOException;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * §10.5 Legal Evidence registry + Certificate Detail, RBAC-scoped per §10.9
 * (Chunk 9): PLATFORM_ADMIN/AUDITOR see everything, APP_MANAGER only their
 * assigned Apps. Certifying Officers assignment and the counsel-approval
 * flag are left for a later chunk — both depend on open decisions §12.4/
 * §12.5 the plan has not resolved yet.
 */
public class AdminLegalCertificatesServlet extends HttpServlet {

    private static final Pattern CERTIFICATE_DETAIL = Pattern.compile("^/([^/]+)$");
    private static final Pattern CERTIFICATE_DOWNLOAD = Pattern.compile("^/([^/]+)/download$");
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final LegalCertificateRepository certificateRepository = new LegalCertificateRepository();
    private final DocumentRepository documentRepository = new DocumentRepository();
    private final DocumentStorageProvider storageProvider = new LocalFilesystemStorageProvider();
    private final AdminAuthorizationService authorizationService = new AdminAuthorizationService();

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res) throws IOException {
        String pathInfo = req.getPathInfo();
        try {
            if (pathInfo == null || pathInfo.equals("/")) {
                listRegistry(req, res);
                return;
            }
            Matcher downloadMatcher = CERTIFICATE_DOWNLOAD.matcher(pathInfo);
            if (downloadMatcher.matches()) {
                downloadCertificate(req, res, downloadMatcher.group(1));
                return;
            }
            Matcher detailMatcher = CERTIFICATE_DETAIL.matcher(pathInfo);
            if (detailMatcher.matches()) {
                getCertificateDetail(req, res, detailMatcher.group(1));
                return;
            }
            writeError(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such legal-certificates route.");
        } catch (Exception e) {
            writeError(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", e.getMessage());
        }
    }

    private void listRegistry(HttpServletRequest req, HttpServletResponse res) throws Exception {
        String role = ConsoleSessionAuthenticationFilter.getRole(req);
        String userId = ConsoleSessionAuthenticationFilter.getUserId(req);

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
        res.setStatus(HttpServletResponse.SC_OK);
        res.setContentType("application/json");
        res.setCharacterEncoding("UTF-8");
        MAPPER.writeValue(res.getWriter(), array);
    }

    private void getCertificateDetail(HttpServletRequest req, HttpServletResponse res, String certificateId)
            throws Exception {
        Optional<LegalCertificateRepository.CertificateRecord> certOpt = certificateRepository.findById(certificateId);
        if (certOpt.isEmpty()) {
            writeError(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such legal certificate.");
            return;
        }
        LegalCertificateRepository.CertificateRecord cert = certOpt.get();
        if (!authorizationService.canRead(ConsoleSessionAuthenticationFilter.getRole(req),
                ConsoleSessionAuthenticationFilter.getUserId(req), cert.appId())) {
            writeError(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "You do not have access to this certificate.");
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
        writeJson(res, HttpServletResponse.SC_OK, json);
    }

    private void downloadCertificate(HttpServletRequest req, HttpServletResponse res, String certificateId)
            throws Exception {
        Optional<LegalCertificateRepository.CertificateRecord> certOpt = certificateRepository.findById(certificateId);
        if (certOpt.isEmpty()) {
            writeError(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such legal certificate.");
            return;
        }
        LegalCertificateRepository.CertificateRecord cert = certOpt.get();
        if (!authorizationService.canRead(ConsoleSessionAuthenticationFilter.getRole(req),
                ConsoleSessionAuthenticationFilter.getUserId(req), cert.appId())) {
            writeError(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "You do not have access to this certificate.");
            return;
        }
        byte[] pdfBytes = storageProvider.retrieve(new StorageObjectRef(
                cert.storageProviderId(), cert.certificateStorageKey(), cert.certificateHash()));

        res.setStatus(HttpServletResponse.SC_OK);
        res.setContentType("application/pdf");
        res.setHeader("Content-Disposition", "attachment; filename=\"legal-certificate-v" + cert.version() + ".pdf\"");
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
