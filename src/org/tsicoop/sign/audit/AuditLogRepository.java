package org.tsicoop.sign.audit;

import org.tsicoop.sign.framework.PoolDB;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

/**
 * audit_logs writer/reader. Chunk 5 introduced the SEALED event; Chunk 6
 * added DOCUMENT_CREATED and LEGAL_CERTIFICATE_GENERATED; Chunk 8 reads the
 * timeline back for the Document Detail screen (§10.4).
 */
public class AuditLogRepository {

    public record AuditLogEntry(
            String eventType, String actorType, String ipAddress, String userAgent, String createdAt
    ) {
    }

    public void log(String appId, String documentId, String eventType, String actorType, String actorId,
                     String ipAddress, String userAgent) throws Exception {
        String sql = "INSERT INTO audit_logs (app_id, document_id, event_type, actor_type, actor_id, ip_address, user_agent) " +
                "VALUES (?::uuid, ?::uuid, ?, ?, ?::uuid, ?, ?)";
        try (Connection con = PoolDB.getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {
            ps.setString(1, appId);
            ps.setString(2, documentId);
            ps.setString(3, eventType);
            ps.setString(4, actorType);
            ps.setString(5, actorId);
            ps.setString(6, ipAddress);
            ps.setString(7, userAgent);
            ps.executeUpdate();
        }
    }

    /** Full-lifecycle timeline for one document (§10.4 Document Detail). */
    public List<AuditLogEntry> listForDocument(String documentId) throws Exception {
        String sql = "SELECT event_type, actor_type, ip_address, user_agent, created_at::text AS created_at " +
                "FROM audit_logs WHERE document_id = ?::uuid ORDER BY created_at";
        List<AuditLogEntry> entries = new ArrayList<>();
        try (Connection con = PoolDB.getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {
            ps.setString(1, documentId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    entries.add(new AuditLogEntry(
                            rs.getString("event_type"), rs.getString("actor_type"),
                            rs.getString("ip_address"), rs.getString("user_agent"), rs.getString("created_at")));
                }
            }
        }
        return entries;
    }
}
