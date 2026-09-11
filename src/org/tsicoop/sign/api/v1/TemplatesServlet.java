package org.tsicoop.sign.api.v1;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.tsicoop.sign.app.AppContext;
import org.tsicoop.sign.audit.AuditLogRepository;
import org.tsicoop.sign.document.DocumentRepository;
import org.tsicoop.sign.generator.OpenHtmlToPdfGeneratorServiceImpl;
import org.tsicoop.sign.security.ApiKeyAuthenticationFilter;
import org.tsicoop.sign.storage.DocumentStorageProvider;
import org.tsicoop.sign.storage.LocalFilesystemStorageProvider;
import org.tsicoop.sign.storage.StorageObjectRef;
import org.tsicoop.sign.template.DocumentGenerationResult;
import org.tsicoop.sign.template.DocumentGeneratorService;
import org.tsicoop.sign.template.TemplateRepository;

import java.io.IOException;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * §8: POST /api/v1/templates (create) and POST /api/v1/templates/{templateId}/generate.
 * One servlet dispatches on PathInfo since both routes share the
 * "/api/v1/templates/*" prefix and a plain Jakarta Servlet mapping can't
 * capture a path variable on its own.
 */
public class TemplatesServlet extends HttpServlet {

    private static final Pattern GENERATE_PATH = Pattern.compile("^/([^/]+)/generate$");
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final TemplateRepository templateRepository = new TemplateRepository();
    private final DocumentRepository documentRepository = new DocumentRepository();
    private final DocumentGeneratorService generatorService = new OpenHtmlToPdfGeneratorServiceImpl();
    private final DocumentStorageProvider storageProvider = new LocalFilesystemStorageProvider();
    private final AuditLogRepository auditLogRepository = new AuditLogRepository();

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
        String pathInfo = req.getPathInfo();
        AppContext appContext = (AppContext) req.getAttribute(ApiKeyAuthenticationFilter.APP_CONTEXT_ATTRIBUTE);

        try {
            if (pathInfo == null || pathInfo.equals("/")) {
                createTemplate(req, res, appContext);
                return;
            }
            Matcher matcher = GENERATE_PATH.matcher(pathInfo);
            if (matcher.matches()) {
                generateDocument(req, res, appContext, matcher.group(1));
                return;
            }
            writeError(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such templates route.");
        } catch (Exception e) {
            writeError(res, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal Server Error", e.getMessage());
        }
    }

    private void createTemplate(HttpServletRequest req, HttpServletResponse res, AppContext appContext)
            throws Exception {
        JsonNode body = MAPPER.readTree(req.getInputStream());
        String templateName = body.path("templateName").asText(null);
        String category = body.path("category").asText(null);
        String htmlContent = body.path("htmlContent").asText(null);

        if (templateName == null || htmlContent == null) {
            writeError(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request",
                    "templateName and htmlContent are required.");
            return;
        }

        String templateId = templateRepository.create(appContext.appId(), templateName, category, htmlContent);

        ObjectNode json = MAPPER.createObjectNode();
        json.put("templateId", templateId);
        json.put("templateName", templateName);
        json.put("version", 1);
        writeJson(res, HttpServletResponse.SC_CREATED, json);
    }

    private void generateDocument(HttpServletRequest req, HttpServletResponse res, AppContext appContext,
                                   String templateId) throws Exception {
        Optional<TemplateRepository.TemplateRecord> template =
                templateRepository.findByIdForApp(appContext.appId(), templateId);
        if (template.isEmpty()) {
            writeError(res, HttpServletResponse.SC_NOT_FOUND, "Not Found", "No such template.");
            return;
        }

        JsonNode body = MAPPER.readTree(req.getInputStream());
        String documentTitle = body.path("documentTitle").asText(null);
        if (documentTitle == null) {
            writeError(res, HttpServletResponse.SC_BAD_REQUEST, "Bad Request", "documentTitle is required.");
            return;
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> payloadData = body.has("payloadData")
                ? MAPPER.convertValue(body.get("payloadData"), Map.class)
                : Map.of();

        DocumentGenerationResult generated = generatorService.generatePdf(template.get().htmlContent(), payloadData);

        String documentId = UUID.randomUUID().toString();
        StorageObjectRef ref = storageProvider.store(appContext.appSlug(), documentId, "original", generated.pdfBytes());

        documentRepository.createDraftWithId(documentId, appContext.appId(), templateId, documentTitle,
                ref.providerId(), ref.storageKey(), generated.sha256Hash());
        auditLogRepository.log(appContext.appId(), documentId, "DOCUMENT_CREATED", "APP", appContext.appId(),
                req.getRemoteAddr(), req.getHeader("User-Agent"));

        ObjectNode json = MAPPER.createObjectNode();
        json.put("documentId", documentId);
        json.put("status", "DRAFT");
        json.put("originalHashSha256", generated.sha256Hash());
        json.put("storageKey", ref.storageKey());
        writeJson(res, HttpServletResponse.SC_CREATED, json);
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
