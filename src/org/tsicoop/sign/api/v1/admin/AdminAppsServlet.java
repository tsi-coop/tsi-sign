package org.tsicoop.sign.api.v1.admin;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.tsicoop.sign.admin.AdminAuthorizationService;
import org.tsicoop.sign.admin.AppAdminRepository;
import org.tsicoop.sign.admin.PlatformUserRepository;
import org.tsicoop.sign.app.AppContext;
import org.tsicoop.sign.app.ApiKeyRepository;
import org.tsicoop.sign.app.AppRepository;
import org.tsicoop.sign.audit.AuditLogRepository;
import org.tsicoop.sign.document.DocumentRepository;
import org.tsicoop.sign.framework.ApiKeyGenerator;
import org.tsicoop.sign.generator.OpenHtmlToPdfGeneratorServiceImpl;
import org.tsicoop.sign.legal.LegalCertificateRepository;
import org.tsicoop.sign.legal.LegalCertificateService;
import org.tsicoop.sign.pki.LocalKeyStoreProvider;
import org.tsicoop.sign.pki.LocalPkiSigningService;
import org.tsicoop.sign.security.ConsoleSessionAuthenticationFilter;
import org.tsicoop.sign.storage.DocumentStorageProvider;
import org.tsicoop.sign.storage.LocalFilesystemStorageProvider;
import org.tsicoop.sign.storage.StorageObjectRef;
import org.tsicoop.sign.template.DocumentGenerationResult;
import org.tsicoop.sign.template.DocumentGeneratorService;
import org.tsicoop.sign.template.TemplateRepository;

import java.io.IOException;
import java.sql.SQLException;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * §10.2 Apps / API Keys / Signing Defaults, §10.3 Templates (list/create
 * + "Generate Test Document"), and §10.4 Documents & Audit Trail, all under
 * session auth (Chunks 7-8).
 */
public class AdminAppsServlet extends HttpServlet {

    private static final Pattern APP_DETAIL = Pattern.compile("^/([^/]+)$");
    private static final Pattern SIGNING_DEFAULTS = Pattern.compile("^/([^/]+)/signing-defaults$");
    private static final Pattern KEYS = Pattern.compile("^/([^/]+)/keys$");
    private static final Pattern KEY_REVOKE = Pattern.compile("^/([^/]+)/keys/([^/]+)/revoke$");
    private static final Pattern TEMPLATES = Pattern.compile("^/([^/]+)/templates$");
    private static final Pattern TEMPLATE_PREVIEW = Pattern.compile("^/([^/]+)/templates/([^/]+)/preview$");
    private static final Pattern DOCUMENTS = Pattern.compile("^/([^/]+)/documents$");
    private static final Pattern DOCUMENT_DETAIL = Pattern.compile("^/([^/]+)/documents/([^/]+)$");
    private static final Pattern DOCUMENT_DOWNLOAD = Pattern.compile("^/([^/]+)/documents/([^/]+)/download$");
    private static final Pattern DOCUMENT_LEGAL_CERTIFICATE = Pattern.compile("^/([^/]+)/documents/([^/]+)/legal-certificate$");
    private static final Pattern RATE_LIMIT = Pattern.compile("^/([^/]+)/rate-limit$");
    private static final Pattern ADMINS = Pattern.compile("^/([^/]+)/admins$");
    private static final Pattern ADMIN_REMOVE = Pattern.compile("^/([^/]+)/admins/([^/]+)/remove$");

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final AppRepository appRepository = new AppRepository();
    private final ApiKeyRepository apiKeyRepository = new ApiKeyRepository();
    private final TemplateRepository templateRepository = new TemplateRepository();
    private final DocumentRepository documentRepository = new DocumentRepository();
    private final AuditLogRepository auditLogRepository = new AuditLogRepository();
    private final LegalCertificateRepository legalCertificateRepository = new LegalCertificateRepository();
    private final DocumentGeneratorService generatorService = new OpenHtmlToPdfGeneratorServiceImpl();
    private final DocumentStorageProvider storageProvider = new LocalFilesystemStorageProvider();
    private final AdminAuthorizationService authorizationService = new AdminAuthorizationService();
    private final AppAdminRepository appAdminRepository = new AppAdminRepository();
    private final PlatformUserRepository platformUserRepository = new PlatformUserRepository();
    private LegalCertificateService legalCertificateService;

    @Override
    public void init() throws ServletException {
        try {
            LocalPkiSigningService signingService = new LocalPkiSigningService(new LocalKeyStoreProvider());
            legalCertificateService = new LegalCertificateService(signingService, storageProvider);
        } catch (Exception e) {
            throw new ServletException("Failed to initialize Local PKI signing service", e);
        }
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
        String pathInfo = req.getPathInfo();
        try {
            if (pathInfo == null || pathInfo.equals("/")) {
                listApps(req, res);
                return;
            }
            Matcher keysMatcher = KEYS.matcher(pathInfo);
            if (keysMatcher.matches()) {
                if (!requireRead(req, res, keysMatcher.group(1))) return;
                listKeys(res, keysMatcher.group(1));
                return;
            }
            Matcher adminsMatcher = ADMINS.matcher(pathInfo);
            if (adminsMatcher.matches()) {
                if (!requireRead(req, res, adminsMatcher.group(1))) return;
                listAdmins(res, adminsMatcher.group(1));
                return;
            }
            Matcher templatesMatcher = TEMPLATES.matcher(pathInfo);
            if (templatesMatcher.matches()) {
                if (!requireRead(req, res, templatesMatcher.group(1))) return;
                listTemplates(res, templatesMatcher.group(1));
                return;
            }
            Matcher downloadMatcher = DOCUMENT_DOWNLOAD.matcher(pathInfo);
            if (downloadMatcher.matches()) {
                if (!requireRead(req, res, downloadMatcher.group(1))) return;
                downloadDocument(res, downloadMatcher.group(1), downloadMatcher.group(2));
                return;
            }
            Matcher documentDetailMatcher = DOCUMENT_DETAIL.matcher(pathInfo);
            if (documentDetailMatcher.matches()) {
                if (!requireRead(req, res, documentDetailMatcher.group(1))) return;
                getDocumentDetail(res, documentDetailMatcher.group(1), documentDetailMatcher.group(2));
                return;
            }
            Matcher documentsMatcher = DOCUMENTS.matcher(pathInfo);
            if (documentsMatcher.matches()) {
                if (!requireRead(req, res, documentsMatcher.group(1))) return;
                listDocuments(res, documentsMatcher.group(1));
                return;
            }
            Matcher detailMatcher = APP_DETAIL.matcher(pathInfo);
            if (detailMatcher.matches()) {
                if (!requireRead(req, res, detailMatcher.group(1))) return;
                getAppDetail(res, detailMatcher.group(1));
                return;
            }
            writeError(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such admin apps route.");
        } catch (Exception e) {
            writeError(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", e.getMessage());
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
        String pathInfo = req.getPathInfo();
        try {
            if (pathInfo == null || pathInfo.equals("/")) {
                if (!authorizationService.canCreateApp(ConsoleSessionAuthenticationFilter.getRole(req))) {
                    writeError(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "Only a Platform Admin can create Apps.");
                    return;
                }
                createApp(req, res);
                return;
            }
            Matcher previewMatcher = TEMPLATE_PREVIEW.matcher(pathInfo);
            if (previewMatcher.matches()) {
                if (!requireRead(req, res, previewMatcher.group(1))) return;
                previewTemplate(req, res, previewMatcher.group(1), previewMatcher.group(2));
                return;
            }
            Matcher legalCertMatcher = DOCUMENT_LEGAL_CERTIFICATE.matcher(pathInfo);
            if (legalCertMatcher.matches()) {
                if (!requireWrite(req, res, legalCertMatcher.group(1))) return;
                generateLegalCertificate(req, res, legalCertMatcher.group(1), legalCertMatcher.group(2));
                return;
            }
            Matcher adminRemoveMatcher = ADMIN_REMOVE.matcher(pathInfo);
            if (adminRemoveMatcher.matches()) {
                if (!requireWrite(req, res, adminRemoveMatcher.group(1))) return;
                removeAdmin(res, adminRemoveMatcher.group(1), adminRemoveMatcher.group(2));
                return;
            }
            Matcher adminsMatcher = ADMINS.matcher(pathInfo);
            if (adminsMatcher.matches()) {
                if (!requireWrite(req, res, adminsMatcher.group(1))) return;
                addAdmin(req, res, adminsMatcher.group(1));
                return;
            }
            Matcher templatesMatcher = TEMPLATES.matcher(pathInfo);
            if (templatesMatcher.matches()) {
                if (!requireWrite(req, res, templatesMatcher.group(1))) return;
                createTemplate(req, res, templatesMatcher.group(1));
                return;
            }
            Matcher revokeMatcher = KEY_REVOKE.matcher(pathInfo);
            if (revokeMatcher.matches()) {
                if (!requireWrite(req, res, revokeMatcher.group(1))) return;
                revokeKey(res, revokeMatcher.group(1), revokeMatcher.group(2));
                return;
            }
            Matcher keysMatcher = KEYS.matcher(pathInfo);
            if (keysMatcher.matches()) {
                if (!requireWrite(req, res, keysMatcher.group(1))) return;
                issueKey(res, keysMatcher.group(1));
                return;
            }
            Matcher rateLimitMatcher = RATE_LIMIT.matcher(pathInfo);
            if (rateLimitMatcher.matches()) {
                if (!requireWrite(req, res, rateLimitMatcher.group(1))) return;
                updateRateLimit(req, res, rateLimitMatcher.group(1));
                return;
            }
            Matcher signingDefaultsMatcher = SIGNING_DEFAULTS.matcher(pathInfo);
            if (signingDefaultsMatcher.matches()) {
                if (!requireWrite(req, res, signingDefaultsMatcher.group(1))) return;
                updateSigningDefaults(req, res, signingDefaultsMatcher.group(1));
                return;
            }
            writeError(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such admin apps route.");
        } catch (Exception e) {
            writeError(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", e.getMessage());
        }
    }

    /** §10.9: PLATFORM_ADMIN/AUDITOR read anything; APP_MANAGER only their assigned Apps. */
    private boolean requireRead(HttpServletRequest req, HttpServletResponse res, String appId) throws Exception {
        String role = ConsoleSessionAuthenticationFilter.getRole(req);
        String userId = ConsoleSessionAuthenticationFilter.getUserId(req);
        if (!authorizationService.canRead(role, userId, appId)) {
            writeError(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "You do not have access to this App.");
            return false;
        }
        return true;
    }

    /** §10.9: PLATFORM_ADMIN writes anything; APP_MANAGER only their assigned Apps; AUDITOR never. */
    private boolean requireWrite(HttpServletRequest req, HttpServletResponse res, String appId) throws Exception {
        String role = ConsoleSessionAuthenticationFilter.getRole(req);
        String userId = ConsoleSessionAuthenticationFilter.getUserId(req);
        if (!authorizationService.canWrite(role, userId, appId)) {
            writeError(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "You do not have write access to this App.");
            return false;
        }
        return true;
    }

    /** Dashboard/Apps list row (§10.1, §10.9): APP_MANAGER sees only their scoped Apps. */
    private void listApps(HttpServletRequest req, HttpServletResponse res) throws Exception {
        String role = ConsoleSessionAuthenticationFilter.getRole(req);
        String userId = ConsoleSessionAuthenticationFilter.getUserId(req);
        java.util.Set<String> scopedAppIds = "APP_MANAGER".equals(role)
                ? appAdminRepository.listAppIdsForUser(userId) : null;

        ArrayNode array = MAPPER.createArrayNode();
        for (AppRepository.AppRecord app : appRepository.list()) {
            if (scopedAppIds != null && !scopedAppIds.contains(app.appId())) {
                continue;
            }
            array.add(toJson(app));
        }
        res.setStatus(HttpServletResponse.SC_OK);
        res.setContentType("application/json");
        res.setCharacterEncoding("UTF-8");
        MAPPER.writeValue(res.getWriter(), array);
    }

    private void getAppDetail(HttpServletResponse res, String appId) throws Exception {
        Optional<AppRepository.AppRecord> appOpt = appRepository.findById(appId);
        if (appOpt.isEmpty()) {
            writeError(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such App.");
            return;
        }
        writeJson(res, HttpServletResponse.SC_OK, toJson(appOpt.get()));
    }

    private void createApp(HttpServletRequest req, HttpServletResponse res) throws Exception {
        JsonNode body = MAPPER.readTree(req.getInputStream());
        String appName = body.path("appName").asText(null);
        String appSlug = body.path("appSlug").asText(null);
        String defaultProviderId = body.path("defaultProviderId").asText(null);
        String defaultKeyAlias = body.path("defaultKeyAlias").asText(null);
        String webhookUrl = body.path("webhookUrl").asText(null);

        if (appName == null || appSlug == null) {
            writeError(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "appName and appSlug are required.");
            return;
        }

        String appId;
        try {
            appId = appRepository.create(appName, appSlug, defaultProviderId, defaultKeyAlias, webhookUrl);
        } catch (SQLException e) {
            if ("23505".equals(e.getSQLState())) {
                writeError(res, HttpServletResponse.SC_CONFLICT, "Conflict", "appSlug is already in use.");
                return;
            }
            throw e;
        }

        ApiKeyGenerator.GeneratedKey key = apiKeyRepository.issue(appId);

        ObjectNode json = MAPPER.createObjectNode();
        json.put("appId", appId);
        json.put("appName", appName);
        json.put("appSlug", appSlug);
        json.put("apiKey", key.rawKey());
        writeJson(res, HttpServletResponse.SC_CREATED, json);
    }

    private void updateSigningDefaults(HttpServletRequest req, HttpServletResponse res, String appId)
            throws Exception {
        if (appRepository.findById(appId).isEmpty()) {
            writeError(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such App.");
            return;
        }
        JsonNode body = MAPPER.readTree(req.getInputStream());
        appRepository.updateSigningDefaults(appId,
                body.path("defaultProviderId").asText(null),
                body.path("defaultKeyAlias").asText(null),
                body.path("webhookUrl").asText(null));
        writeJson(res, HttpServletResponse.SC_OK, MAPPER.createObjectNode().put("status", "updated"));
    }

    private void listKeys(HttpServletResponse res, String appId) throws Exception {
        if (appRepository.findById(appId).isEmpty()) {
            writeError(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such App.");
            return;
        }
        ArrayNode array = MAPPER.createArrayNode();
        for (ApiKeyRepository.ApiKeyRecord key : apiKeyRepository.listForApp(appId)) {
            ObjectNode node = array.addObject();
            node.put("keyId", key.keyId());
            node.put("keyPrefix", key.keyPrefix());
            node.put("isActive", key.isActive());
            node.put("createdAt", key.createdAt());
            node.put("revokedAt", key.revokedAt());
        }
        res.setStatus(HttpServletResponse.SC_OK);
        res.setContentType("application/json");
        res.setCharacterEncoding("UTF-8");
        MAPPER.writeValue(res.getWriter(), array);
    }

    private void issueKey(HttpServletResponse res, String appId) throws Exception {
        if (appRepository.findById(appId).isEmpty()) {
            writeError(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such App.");
            return;
        }
        ApiKeyGenerator.GeneratedKey key = apiKeyRepository.issue(appId);
        ObjectNode json = MAPPER.createObjectNode();
        json.put("apiKey", key.rawKey());
        json.put("keyPrefix", key.keyPrefix());
        writeJson(res, HttpServletResponse.SC_CREATED, json);
    }

    private void revokeKey(HttpServletResponse res, String appId, String keyId) throws Exception {
        boolean revoked = apiKeyRepository.revoke(appId, keyId);
        if (!revoked) {
            writeError(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such active key for this App.");
            return;
        }
        writeJson(res, HttpServletResponse.SC_OK, MAPPER.createObjectNode().put("status", "revoked"));
    }

    private void listTemplates(HttpServletResponse res, String appId) throws Exception {
        if (appRepository.findById(appId).isEmpty()) {
            writeError(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such App.");
            return;
        }
        ArrayNode array = MAPPER.createArrayNode();
        for (TemplateRepository.TemplateRecord template : templateRepository.listForApp(appId)) {
            ObjectNode node = array.addObject();
            node.put("templateId", template.templateId());
            node.put("templateName", template.templateName());
            node.put("category", template.category());
            node.put("htmlContent", template.htmlContent());
            node.put("version", template.version());
        }
        res.setStatus(HttpServletResponse.SC_OK);
        res.setContentType("application/json");
        res.setCharacterEncoding("UTF-8");
        MAPPER.writeValue(res.getWriter(), array);
    }

    private void createTemplate(HttpServletRequest req, HttpServletResponse res, String appId) throws Exception {
        if (appRepository.findById(appId).isEmpty()) {
            writeError(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such App.");
            return;
        }
        JsonNode body = MAPPER.readTree(req.getInputStream());
        String templateName = body.path("templateName").asText(null);
        String category = body.path("category").asText(null);
        String htmlContent = body.path("htmlContent").asText(null);
        if (templateName == null || htmlContent == null) {
            writeError(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request",
                    "templateName and htmlContent are required.");
            return;
        }
        String templateId = templateRepository.create(appId, templateName, category, htmlContent);
        ObjectNode json = MAPPER.createObjectNode();
        json.put("templateId", templateId);
        writeJson(res, HttpServletResponse.SC_CREATED, json);
    }

    /** §10.3 "Generate Test Document" — renders a sample PDF, persists nothing. */
    private void previewTemplate(HttpServletRequest req, HttpServletResponse res, String appId, String templateId)
            throws Exception {
        Optional<TemplateRepository.TemplateRecord> templateOpt =
                templateRepository.findByIdForApp(appId, templateId);
        if (templateOpt.isEmpty()) {
            writeError(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such template.");
            return;
        }
        JsonNode body = req.getContentLengthLong() > 0 ? MAPPER.readTree(req.getInputStream()) : MAPPER.createObjectNode();
        @SuppressWarnings("unchecked")
        Map<String, Object> payloadData = body.has("payloadData")
                ? MAPPER.convertValue(body.get("payloadData"), Map.class)
                : Map.of();

        DocumentGenerationResult result = generatorService.generatePdf(templateOpt.get().htmlContent(), payloadData);

        res.setStatus(HttpServletResponse.SC_OK);
        res.setContentType("application/pdf");
        res.setHeader("Content-Disposition", "inline; filename=\"preview.pdf\"");
        res.getOutputStream().write(result.pdfBytes());
    }

    private void listDocuments(HttpServletResponse res, String appId) throws Exception {
        if (appRepository.findById(appId).isEmpty()) {
            writeError(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such App.");
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
        res.setStatus(HttpServletResponse.SC_OK);
        res.setContentType("application/json");
        res.setCharacterEncoding("UTF-8");
        MAPPER.writeValue(res.getWriter(), array);
    }

    /** §10.4 Document Detail: fields + seal(s) + full audit_logs timeline. */
    private void getDocumentDetail(HttpServletResponse res, String appId, String documentId) throws Exception {
        Optional<DocumentRepository.DocumentRecord> documentOpt =
                documentRepository.findByIdForApp(appId, documentId);
        if (documentOpt.isEmpty()) {
            writeError(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such document.");
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

        writeJson(res, HttpServletResponse.SC_OK, json);
    }

    /** §10.4 "shortcut into Legal Evidence to generate ... this document's BSA §63 certificate." */
    private void generateLegalCertificate(HttpServletRequest req, HttpServletResponse res, String appId,
                                           String documentId) throws Exception {
        Optional<AppRepository.AppRecord> appOpt = appRepository.findById(appId);
        if (appOpt.isEmpty()) {
            writeError(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such App.");
            return;
        }
        Optional<DocumentRepository.DocumentRecord> documentOpt = documentRepository.findByIdForApp(appId, documentId);
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

        AppRepository.AppRecord app = appOpt.get();
        JsonNode body = req.getContentLengthLong() > 0 ? MAPPER.readTree(req.getInputStream()) : MAPPER.createObjectNode();
        String certifyingKeyAlias = body.path("certifyingKeyAlias").asText(null);
        if (certifyingKeyAlias == null) {
            certifyingKeyAlias = app.defaultKeyAlias();
        }
        if (certifyingKeyAlias == null) {
            writeError(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request",
                    "certifyingKeyAlias is required: no default_key_alias is configured for this App.");
            return;
        }

        AppContext appContext = new AppContext(app.appId(), app.appName(), app.appSlug(), app.rateLimitRpm());
        LegalCertificateService.GeneratedCertificate certificate =
                legalCertificateService.generate(appContext, document, certifyingKeyAlias);

        HttpSession session = req.getSession(false);
        String actorId = session != null
                ? (String) session.getAttribute(ConsoleSessionAuthenticationFilter.SESSION_USER_ID) : null;
        auditLogRepository.log(appId, documentId, "LEGAL_CERTIFICATE_GENERATED", "PLATFORM_USER", actorId,
                req.getRemoteAddr(), req.getHeader("User-Agent"));

        ObjectNode json = MAPPER.createObjectNode();
        json.put("certificateId", certificate.certificateId());
        json.put("version", certificate.version());
        writeJson(res, HttpServletResponse.SC_CREATED, json);
    }

    /** §10.4 "download the signed PDF" — falls back to the original render if not yet sealed. */
    private void downloadDocument(HttpServletResponse res, String appId, String documentId) throws Exception {
        Optional<DocumentRepository.DocumentRecord> documentOpt =
                documentRepository.findByIdForApp(appId, documentId);
        if (documentOpt.isEmpty()) {
            writeError(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such document.");
            return;
        }
        DocumentRepository.DocumentRecord document = documentOpt.get();
        boolean sealed = document.sealedStorageKey() != null;
        String storageKey = sealed ? document.sealedStorageKey() : document.originalStorageKey();
        String hash = sealed ? document.sealedHash() : document.originalHash();

        byte[] pdfBytes = storageProvider.retrieve(new StorageObjectRef(document.storageProviderId(), storageKey, hash));

        res.setStatus(HttpServletResponse.SC_OK);
        res.setContentType("application/pdf");
        res.setHeader("Content-Disposition", "attachment; filename=\"" + (sealed ? "sealed" : "original") + ".pdf\"");
        res.getOutputStream().write(pdfBytes);
    }

    /** §10.2 Admins tab: platform_users assigned to administer this App. */
    private void listAdmins(HttpServletResponse res, String appId) throws Exception {
        if (appRepository.findById(appId).isEmpty()) {
            writeError(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such App.");
            return;
        }
        ArrayNode array = MAPPER.createArrayNode();
        for (AppAdminRepository.AssignedUser user : appAdminRepository.listUsersForApp(appId)) {
            ObjectNode node = array.addObject();
            node.put("userId", user.userId());
            node.put("email", user.email());
            node.put("fullName", user.fullName());
        }
        res.setStatus(HttpServletResponse.SC_OK);
        res.setContentType("application/json");
        res.setCharacterEncoding("UTF-8");
        MAPPER.writeValue(res.getWriter(), array);
    }

    private void addAdmin(HttpServletRequest req, HttpServletResponse res, String appId) throws Exception {
        if (appRepository.findById(appId).isEmpty()) {
            writeError(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such App.");
            return;
        }
        JsonNode body = MAPPER.readTree(req.getInputStream());
        String userId = body.path("userId").asText(null);
        if (userId == null || platformUserRepository.findById(userId).isEmpty()) {
            writeError(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "A valid userId is required.");
            return;
        }
        appAdminRepository.assign(appId, userId);
        writeJson(res, HttpServletResponse.SC_OK, MAPPER.createObjectNode().put("status", "assigned"));
    }

    private void removeAdmin(HttpServletResponse res, String appId, String userId) throws Exception {
        appAdminRepository.unassign(appId, userId);
        writeJson(res, HttpServletResponse.SC_OK, MAPPER.createObjectNode().put("status", "removed"));
    }

    /** §10.2 Overview tab, §9 Chunk 9: editable rate_limit_rpm (null = unlimited). */
    private void updateRateLimit(HttpServletRequest req, HttpServletResponse res, String appId) throws Exception {
        if (appRepository.findById(appId).isEmpty()) {
            writeError(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such App.");
            return;
        }
        JsonNode body = MAPPER.readTree(req.getInputStream());
        Integer rateLimitRpm = body.hasNonNull("rateLimitRpm") ? body.get("rateLimitRpm").asInt() : null;
        appRepository.updateRateLimit(appId, rateLimitRpm);
        writeJson(res, HttpServletResponse.SC_OK, MAPPER.createObjectNode().put("status", "updated"));
    }

    private ObjectNode toJson(AppRepository.AppRecord app) {
        ObjectNode node = MAPPER.createObjectNode();
        node.put("appId", app.appId());
        node.put("appName", app.appName());
        node.put("appSlug", app.appSlug());
        node.put("isActive", app.isActive());
        node.put("defaultProviderId", app.defaultProviderId());
        node.put("defaultKeyAlias", app.defaultKeyAlias());
        node.put("webhookUrl", app.webhookUrl());
        if (app.rateLimitRpm() != null) {
            node.put("rateLimitRpm", app.rateLimitRpm());
        } else {
            node.putNull("rateLimitRpm");
        }
        node.put("createdAt", app.createdAt());
        return node;
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
