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
import org.tsicoop.sign.storage.DocumentStorageProvider;
import org.tsicoop.sign.storage.StorageObjectRef;
import org.tsicoop.sign.storage.StorageProviderRegistry;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * TENANT_OR_CONSOLE (matches tsi-ledger's Accounts.java): an App and the
 * admin console both operate on templates, so this is one Action branching
 * on which identity resolved rather than two classes duplicating the same
 * SQL. funcs:
 *  - create_template, generate_document: BOTH — tenant acts under its own
 *    App; console acts under a body-supplied appId (RBAC-checked, §10.9).
 *  - list_templates, preview_template: CONSOLE only (§10.3; "Generate Test
 *    Document" persists nothing). A bare API-key caller has no role, so
 *    AuthorizationService naturally 403s these rather than needing a
 *    separate guard.
 */
public class Templates implements Action {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final TemplateRepository templateRepository = new TemplateRepository();
    private final DocumentRepository documentRepository = new DocumentRepository();
    private final DocumentSignerRepository documentSignerRepository = new DocumentSignerRepository();
    private final SignerDiscoveryService signerDiscoveryService = new SignerDiscoveryService(documentSignerRepository);
    private final AppRepository appRepository = new AppRepository();
    private final DocumentGeneratorService generatorService = new OpenHtmlToPdfGeneratorServiceImpl();
    private final AuditLogRepository auditLogRepository = new AuditLogRepository();
    private final AuthorizationService authorizationService = new AuthorizationService();

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
                case "create_template":
                    createTemplate(req, res, body, appContext);
                    break;
                case "generate_document":
                    generateDocument(req, res, body, appContext);
                    break;
                case "list_templates":
                    listTemplates(req, res, body);
                    break;
                case "preview_template":
                    previewTemplate(req, res, body);
                    break;
                default:
                    OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "Unknown _func: " + func);
            }
        } catch (Exception e) {
            e.printStackTrace();
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", e.getMessage());
        }
    }

    private void createTemplate(HttpServletRequest req, HttpServletResponse res, JsonNode body, AppContext appContext)
            throws Exception {
        String appId;
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
            if (appRepository.findById(appId).isEmpty()) {
                OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such App.");
                return;
            }
        }

        String templateName = body.path("templateName").asText(null);
        String category = body.path("category").asText(null);
        String htmlContent = body.path("htmlContent").asText(null);
        if (templateName == null || htmlContent == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request",
                    "templateName and htmlContent are required.");
            return;
        }

        String templateId = templateRepository.create(appId, templateName, category, htmlContent);

        ObjectNode json = MAPPER.createObjectNode();
        json.put("templateId", templateId);
        json.put("templateName", templateName);
        json.put("version", 1);
        OutputProcessor.send(res, HttpServletResponse.SC_CREATED, json);
    }

    private void generateDocument(HttpServletRequest req, HttpServletResponse res, JsonNode body, AppContext appContext)
            throws Exception {
        String templateId = body.path("templateId").asText(null);
        if (templateId == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "templateId is required.");
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

        Optional<TemplateRepository.TemplateRecord> template =
                templateRepository.findByIdForApp(appId, templateId);
        if (template.isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such template.");
            return;
        }

        String documentTitle = body.path("documentTitle").asText(null);
        if (documentTitle == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "documentTitle is required.");
            return;
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> payloadData = body.has("payloadData")
                ? MAPPER.convertValue(body.get("payloadData"), Map.class)
                : Map.of();

        DocumentGenerationResult generated;
        try {
            generated = generatorService.generatePdf(template.get().htmlContent(), payloadData);
        } catch (TemplateRenderException e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", e.getMessage());
            return;
        }

        String documentId = UUID.randomUUID().toString();
        DocumentStorageProvider storageProvider = StorageProviderRegistry.resolveForWrite(appStorageProviderId);
        StorageObjectRef ref = storageProvider.store(appSlug, documentId, "original", generated.pdfBytes());

        documentRepository.createDraftWithId(documentId, appId, templateId, documentTitle,
                ref.providerId(), ref.storageKey(), generated.sha256Hash());
        signerDiscoveryService.discoverMarkers(documentId, generated.pdfBytes());

        String actorType = appContext != null ? "APP" : "PLATFORM_USER";
        String actorId = appContext != null ? appContext.appId() : InputProcessor.getUserId(req);
        auditLogRepository.log(appId, documentId, "DOCUMENT_CREATED", actorType, actorId,
                req.getRemoteAddr(), req.getHeader("User-Agent"));

        ObjectNode json = MAPPER.createObjectNode();
        json.put("documentId", documentId);
        json.put("status", "DRAFT");
        json.put("originalHashSha256", generated.sha256Hash());
        json.put("storageKey", ref.storageKey());
        OutputProcessor.send(res, HttpServletResponse.SC_CREATED, json);
    }

    /** §10.3 Templates list, CONSOLE only. */
    private void listTemplates(HttpServletRequest req, HttpServletResponse res, JsonNode body) throws Exception {
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
        for (TemplateRepository.TemplateRecord template : templateRepository.listForApp(appId)) {
            ObjectNode node = array.addObject();
            node.put("templateId", template.templateId());
            node.put("templateName", template.templateName());
            node.put("category", template.category());
            node.put("htmlContent", template.htmlContent());
            node.put("version", template.version());
        }
        OutputProcessor.send(res, HttpServletResponse.SC_OK, array);
    }

    /** §10.3 "Generate Test Document" — renders a sample PDF, persists nothing. CONSOLE only. */
    private void previewTemplate(HttpServletRequest req, HttpServletResponse res, JsonNode body) throws Exception {
        String appId = body.path("appId").asText(null);
        String templateId = body.path("templateId").asText(null);
        if (appId == null || templateId == null) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "appId and templateId are required.");
            return;
        }
        if (!authorizationService.canRead(InputProcessor.getUserRole(req), InputProcessor.getUserId(req), appId)) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_FORBIDDEN, "Forbidden", "You do not have access to this App.");
            return;
        }
        Optional<TemplateRepository.TemplateRecord> templateOpt = templateRepository.findByIdForApp(appId, templateId);
        if (templateOpt.isEmpty()) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such template.");
            return;
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> payloadData = body.has("payloadData")
                ? MAPPER.convertValue(body.get("payloadData"), Map.class)
                : Map.of();

        DocumentGenerationResult result;
        try {
            result = generatorService.generatePdf(templateOpt.get().htmlContent(), payloadData);
        } catch (TemplateRenderException e) {
            OutputProcessor.errorResponse(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", e.getMessage());
            return;
        }

        res.setStatus(HttpServletResponse.SC_OK);
        res.setContentType("application/pdf");
        res.setHeader("Content-Disposition", "inline; filename=\"preview.pdf\"");
        res.getOutputStream().write(result.pdfBytes());
    }
}
