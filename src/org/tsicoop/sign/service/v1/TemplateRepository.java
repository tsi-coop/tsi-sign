package org.tsicoop.sign.service.v1;

import org.tsicoop.sign.framework.PoolDB;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/** App-scoped template CRUD (§4.2: templates are namespaced per App). */
public class TemplateRepository {

    public record TemplateRecord(
            String templateId,
            String appId,
            String templateName,
            String category,
            String htmlContent,
            int version,
            boolean active
    ) {
    }

    public String create(String appId, String templateName, String category, String htmlContent) throws Exception {
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("INSERT INTO templates (app_id, template_name, category, html_content) " +
                    "VALUES (?::uuid, ?, ?, ?) RETURNING template_id");
            ps.setString(1, appId);
            ps.setString(2, templateName);
            ps.setString(3, category);
            ps.setString(4, htmlContent);
            rs = ps.executeQuery();
            rs.next();
            return rs.getString("template_id");
        } finally {
            pool.cleanup(rs, ps, con);
        }
    }

    /**
     * Scoped to appId so one App can never read another's template by
     * guessing/reusing an id — callers should treat "not present" as 404,
     * not 403, to avoid leaking existence across Apps (§8).
     */
    public Optional<TemplateRecord> findByIdForApp(String appId, String templateId) {
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = null;
        try {
            pool = new PoolDB();
            con = pool.getConnection();
            ps = con.prepareStatement("SELECT template_id, app_id, template_name, category, html_content, version, active " +
                    "FROM templates WHERE template_id = ?::uuid AND app_id = ?::uuid");
            ps.setString(1, templateId);
            ps.setString(2, appId);
            rs = ps.executeQuery();
            if (rs.next()) {
                return Optional.of(new TemplateRecord(
                        rs.getString("template_id"),
                        rs.getString("app_id"),
                        rs.getString("template_name"),
                        rs.getString("category"),
                        rs.getString("html_content"),
                        rs.getInt("version"),
                        rs.getBoolean("active")));
            }
            return Optional.empty();
        } catch (Exception e) {
            // Malformed templateId (not a UUID) fails the ?::uuid cast — treat
            // it the same as "not found" rather than surfacing a 500, since
            // an invalid id is indistinguishable from one that just isn't ours.
            return Optional.empty();
        } finally {
            if (pool != null) pool.cleanup(rs, ps, con);
        }
    }

    /** §10.3 Templates list, scoped to one App. */
    public List<TemplateRecord> listForApp(String appId) throws Exception {
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("SELECT template_id, app_id, template_name, category, html_content, version, active " +
                    "FROM templates WHERE app_id = ?::uuid ORDER BY updated_at DESC");
            ps.setString(1, appId);
            rs = ps.executeQuery();
            List<TemplateRecord> templates = new ArrayList<>();
            while (rs.next()) {
                templates.add(new TemplateRecord(
                        rs.getString("template_id"),
                        rs.getString("app_id"),
                        rs.getString("template_name"),
                        rs.getString("category"),
                        rs.getString("html_content"),
                        rs.getInt("version"),
                        rs.getBoolean("active")));
            }
            return templates;
        } finally {
            pool.cleanup(rs, ps, con);
        }
    }

    /**
     * Deactivating a template blocks it from new generate_document calls
     * (and hides it from "Generate from Template") without touching any
     * document already generated from it. Scoped to appId for the same
     * tenant-isolation reason as findByIdForApp. Returns false if no row
     * matched (wrong app or unknown templateId), so the caller can 404.
     */
    public boolean setActive(String appId, String templateId, boolean active) throws Exception {
        Connection con = null;
        PreparedStatement ps = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("UPDATE templates SET active = ?, updated_at = now() " +
                    "WHERE template_id = ?::uuid AND app_id = ?::uuid");
            ps.setBoolean(1, active);
            ps.setString(2, templateId);
            ps.setString(3, appId);
            return ps.executeUpdate() > 0;
        } finally {
            pool.cleanup(null, ps, con);
        }
    }

    /** Dashboard aggregate (§10.1): template count across every App the caller can see - null appIds means every App. */
    public int countForApps(Set<String> appIds) throws Exception {
        if (appIds != null && appIds.isEmpty()) return 0;
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            String sql = "SELECT COUNT(*) FROM templates";
            if (appIds != null) {
                sql += " WHERE app_id IN (" + placeholders(appIds.size()) + ")";
            }
            ps = con.prepareStatement(sql);
            if (appIds != null) {
                int i = 1;
                for (String appId : appIds) {
                    ps.setString(i++, appId);
                }
            }
            rs = ps.executeQuery();
            rs.next();
            return rs.getInt(1);
        } finally {
            pool.cleanup(rs, ps, con);
        }
    }

    private static String placeholders(int count) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < count; i++) {
            if (i > 0) sb.append(",");
            sb.append("?::uuid");
        }
        return sb.toString();
    }
}
