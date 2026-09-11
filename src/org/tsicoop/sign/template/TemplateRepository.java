package org.tsicoop.sign.template;

import org.tsicoop.sign.framework.PoolDB;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/** App-scoped template CRUD (§4.2: templates are namespaced per App). */
public class TemplateRepository {

    public record TemplateRecord(
            String templateId,
            String appId,
            String templateName,
            String category,
            String htmlContent,
            int version
    ) {
    }

    public String create(String appId, String templateName, String category, String htmlContent) throws Exception {
        String sql = "INSERT INTO templates (app_id, template_name, category, html_content) " +
                "VALUES (?::uuid, ?, ?, ?) RETURNING template_id";
        try (Connection con = PoolDB.getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {
            ps.setString(1, appId);
            ps.setString(2, templateName);
            ps.setString(3, category);
            ps.setString(4, htmlContent);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getString("template_id");
            }
        }
    }

    /**
     * Scoped to appId so one App can never read another's template by
     * guessing/reusing an id — callers should treat "not present" as 404,
     * not 403, to avoid leaking existence across Apps (§8).
     */
    public Optional<TemplateRecord> findByIdForApp(String appId, String templateId) {
        String sql = "SELECT template_id, app_id, template_name, category, html_content, version " +
                "FROM templates WHERE template_id = ?::uuid AND app_id = ?::uuid";
        try (Connection con = PoolDB.getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {
            ps.setString(1, templateId);
            ps.setString(2, appId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(new TemplateRecord(
                            rs.getString("template_id"),
                            rs.getString("app_id"),
                            rs.getString("template_name"),
                            rs.getString("category"),
                            rs.getString("html_content"),
                            rs.getInt("version")));
                }
            }
        } catch (Exception e) {
            // Malformed templateId (not a UUID) fails the ?::uuid cast — treat
            // it the same as "not found" rather than surfacing a 500, since
            // an invalid id is indistinguishable from one that just isn't ours.
            return Optional.empty();
        }
        return Optional.empty();
    }

    /** §10.3 Templates list, scoped to one App. */
    public List<TemplateRecord> listForApp(String appId) throws Exception {
        String sql = "SELECT template_id, app_id, template_name, category, html_content, version " +
                "FROM templates WHERE app_id = ?::uuid ORDER BY updated_at DESC";
        List<TemplateRecord> templates = new ArrayList<>();
        try (Connection con = PoolDB.getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {
            ps.setString(1, appId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    templates.add(new TemplateRecord(
                            rs.getString("template_id"),
                            rs.getString("app_id"),
                            rs.getString("template_name"),
                            rs.getString("category"),
                            rs.getString("html_content"),
                            rs.getInt("version")));
                }
            }
        }
        return templates;
    }
}
