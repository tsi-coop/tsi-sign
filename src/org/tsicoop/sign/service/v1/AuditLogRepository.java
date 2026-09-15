package org.tsicoop.sign.service.v1;

import org.tsicoop.sign.framework.PoolDB;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * audit_logs writer/reader. Chunk 5 introduced the SEALED event; Chunk 6
 * added DOCUMENT_CREATED and LEGAL_CERTIFICATE_GENERATED; Chunk 8 reads the
 * timeline back for the Document Detail screen (§10.4); listAll/countAll
 * back the cross-app Audit screen (§10.9's AUDITOR role exists specifically
 * for this - read-only visibility across every App).
 */
public class AuditLogRepository {

    public record AuditLogEntry(
            String eventType, String actorType, String ipAddress, String userAgent, String createdAt
    ) {
    }

    public record AuditLogSummary(
            String auditId, String appId, String appName, String documentId, String documentTitle,
            String eventType, String actorType, String actorId, String actorName, String ipAddress, String createdAt
    ) {
    }

    public void log(String appId, String documentId, String eventType, String actorType, String actorId,
                     String ipAddress, String userAgent) throws Exception {
        Connection con = null;
        PreparedStatement ps = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("INSERT INTO audit_logs " +
                    "(app_id, document_id, event_type, actor_type, actor_id, ip_address, user_agent) " +
                    "VALUES (?::uuid, ?::uuid, ?, ?, ?::uuid, ?, ?)");
            ps.setString(1, appId);
            ps.setString(2, documentId);
            ps.setString(3, eventType);
            ps.setString(4, actorType);
            ps.setString(5, actorId);
            ps.setString(6, ipAddress);
            ps.setString(7, userAgent);
            ps.executeUpdate();
        } finally {
            pool.cleanup(null, ps, con);
        }
    }

    /** Full-lifecycle timeline for one document (§10.4 Document Detail). */
    public List<AuditLogEntry> listForDocument(String documentId) throws Exception {
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("SELECT event_type, actor_type, ip_address, user_agent, " +
                    "created_at::text AS created_at FROM audit_logs WHERE document_id = ?::uuid ORDER BY created_at");
            ps.setString(1, documentId);
            rs = ps.executeQuery();
            List<AuditLogEntry> entries = new ArrayList<>();
            while (rs.next()) {
                entries.add(new AuditLogEntry(
                        rs.getString("event_type"), rs.getString("actor_type"),
                        rs.getString("ip_address"), rs.getString("user_agent"), rs.getString("created_at")));
            }
            return entries;
        } finally {
            pool.cleanup(rs, ps, con);
        }
    }

    /**
     * Cross-app Audit screen (§10.9), paginated. scopedAppIds restricts an
     * APP_MANAGER to their assigned Apps (null means no restriction -
     * PLATFORM_ADMIN/AUDITOR see every App); appIdFilter further narrows to
     * one specific App when the console's App dropdown picks one.
     */
    public List<AuditLogSummary> listAll(Set<String> scopedAppIds, String appIdFilter, String eventType,
                                          int page, int pageSize) throws Exception {
        if (scopedAppIds != null && scopedAppIds.isEmpty()) return List.of();
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            StringBuilder sql = new StringBuilder(
                    "SELECT al.audit_id, al.app_id, a.app_name, al.document_id, d.title AS document_title, " +
                    "al.event_type, al.actor_type, al.actor_id::text AS actor_id, pu.full_name AS actor_name, " +
                    "al.ip_address, al.created_at::text AS created_at " +
                    "FROM audit_logs al " +
                    "JOIN apps a ON a.app_id = al.app_id " +
                    "LEFT JOIN documents d ON d.document_id = al.document_id " +
                    "LEFT JOIN platform_users pu ON pu.user_id = al.actor_id AND al.actor_type = 'PLATFORM_USER' " +
                    "WHERE 1=1");
            appendFilters(sql, scopedAppIds, appIdFilter, eventType);
            sql.append(" ORDER BY al.created_at DESC LIMIT ? OFFSET ?");

            ps = con.prepareStatement(sql.toString());
            int i = bindFilters(ps, 1, scopedAppIds, appIdFilter, eventType);
            ps.setInt(i++, pageSize);
            ps.setLong(i, (long) (page - 1) * pageSize);
            rs = ps.executeQuery();
            List<AuditLogSummary> entries = new ArrayList<>();
            while (rs.next()) {
                entries.add(new AuditLogSummary(
                        rs.getString("audit_id"), rs.getString("app_id"), rs.getString("app_name"),
                        rs.getString("document_id"), rs.getString("document_title"),
                        rs.getString("event_type"), rs.getString("actor_type"), rs.getString("actor_id"),
                        rs.getString("actor_name"), rs.getString("ip_address"), rs.getString("created_at")));
            }
            return entries;
        } finally {
            pool.cleanup(rs, ps, con);
        }
    }

    public int countAll(Set<String> scopedAppIds, String appIdFilter, String eventType) throws Exception {
        if (scopedAppIds != null && scopedAppIds.isEmpty()) return 0;
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            StringBuilder sql = new StringBuilder("SELECT COUNT(*) FROM audit_logs al WHERE 1=1");
            appendFilters(sql, scopedAppIds, appIdFilter, eventType);
            ps = con.prepareStatement(sql.toString());
            bindFilters(ps, 1, scopedAppIds, appIdFilter, eventType);
            rs = ps.executeQuery();
            rs.next();
            return rs.getInt(1);
        } finally {
            pool.cleanup(rs, ps, con);
        }
    }

    private static void appendFilters(StringBuilder sql, Set<String> scopedAppIds, String appIdFilter, String eventType) {
        if (appIdFilter != null) {
            sql.append(" AND al.app_id = ?::uuid");
        } else if (scopedAppIds != null) {
            sql.append(" AND al.app_id IN (").append(placeholders(scopedAppIds.size())).append(")");
        }
        if (eventType != null && !eventType.isBlank()) {
            sql.append(" AND al.event_type = ?");
        }
    }

    private static int bindFilters(PreparedStatement ps, int i, Set<String> scopedAppIds, String appIdFilter,
                                    String eventType) throws Exception {
        if (appIdFilter != null) {
            ps.setString(i++, appIdFilter);
        } else if (scopedAppIds != null) {
            for (String appId : scopedAppIds) {
                ps.setString(i++, appId);
            }
        }
        if (eventType != null && !eventType.isBlank()) {
            ps.setString(i++, eventType);
        }
        return i;
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
