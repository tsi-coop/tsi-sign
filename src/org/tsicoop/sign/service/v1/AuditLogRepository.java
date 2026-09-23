package org.tsicoop.sign.service.v1;

import org.tsicoop.sign.framework.PoolDB;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import org.tsicoop.sign.framework.HashUtil;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.UUID;
import java.util.List;
import java.util.Set;

/**
 * audit_logs writer/reader - hash-chained per App (db/11_audit_hash_chain.sql). Chunk 5 introduced the SEALED event; Chunk 6
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

    /**
     * Appends an event to the App's hash chain: entry_hash = SHA-256 over this row's fields and the
     * previous row's entry_hash. The per-App advisory lock serializes writers so two concurrent events
     * can never both chain onto the same predecessor.
     */
    public void log(String appId, String documentId, String eventType, String actorType, String actorId,
                     String ipAddress, String userAgent) throws Exception {
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            con.setAutoCommit(false);

            ps = con.prepareStatement("SELECT pg_advisory_xact_lock(hashtext(?))");
            ps.setString(1, appId);
            ps.execute();
            ps.close();

            ps = con.prepareStatement("SELECT entry_hash FROM audit_logs " +
                    "WHERE app_id = ?::uuid AND entry_hash IS NOT NULL ORDER BY seq DESC LIMIT 1");
            ps.setString(1, appId);
            rs = ps.executeQuery();
            String prevHash = rs.next() ? rs.getString(1).trim() : "";
            rs.close();
            ps.close();

            String auditId = UUID.randomUUID().toString();
            Instant createdAt = Instant.now().truncatedTo(ChronoUnit.MICROS); // Postgres timestamptz precision
            String entryHash = entryHash(prevHash, auditId, appId, documentId, eventType, actorType, actorId,
                    ipAddress, userAgent, createdAt);

            ps = con.prepareStatement("INSERT INTO audit_logs " +
                    "(audit_id, app_id, document_id, event_type, actor_type, actor_id, ip_address, user_agent, " +
                    "created_at, prev_hash, entry_hash) " +
                    "VALUES (?::uuid, ?::uuid, ?::uuid, ?, ?, ?::uuid, ?, ?, ?, ?, ?)");
            ps.setString(1, auditId);
            ps.setString(2, appId);
            ps.setString(3, documentId);
            ps.setString(4, eventType);
            ps.setString(5, actorType);
            ps.setString(6, actorId);
            ps.setString(7, ipAddress);
            ps.setString(8, userAgent);
            ps.setObject(9, OffsetDateTime.ofInstant(createdAt, ZoneOffset.UTC));
            ps.setString(10, prevHash.isEmpty() ? null : prevHash);
            ps.setString(11, entryHash);
            ps.executeUpdate();
            con.commit();
        } catch (Exception e) {
            if (con != null) {
                try {
                    con.rollback();
                } catch (Exception ignored) {
                }
            }
            throw e;
        } finally {
            if (con != null) {
                try {
                    con.setAutoCommit(true);
                } catch (Exception ignored) {
                }
            }
            pool.cleanup(rs, ps, con);
        }
    }

    /** Length-prefixed fields, so no field value can be shifted into its neighbour to forge a collision. */
    static String entryHash(String prevHash, String auditId, String appId, String documentId, String eventType,
            String actorType, String actorId, String ipAddress, String userAgent, Instant createdAt) {
        StringBuilder canonical = new StringBuilder();
        for (String field : new String[]{prevHash, auditId, appId, documentId, eventType, actorType, actorId,
                ipAddress, userAgent, createdAt.toString()}) {
            String value = field == null ? "" : field;
            canonical.append(value.length()).append(':').append(value).append('|');
        }
        return HashUtil.sha256Hex(canonical.toString());
    }

    public record ChainVerification(boolean intact, int entriesChecked, String headHash, String brokenAtAuditId,
            String reason) {
    }

    /**
     * Recomputes an App's chain from its first hashed row. Detects an edited row, a deleted or reordered
     * row (the successor's prev_hash no longer matches), and a row injected without a hash. It cannot detect
     * loss of the newest entries, nor a database administrator recomputing the whole chain - record the
     * returned headHash somewhere outside the database to close that gap.
     */
    public ChainVerification verifyChain(String appId) throws Exception {
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("SELECT audit_id, document_id, event_type, actor_type, actor_id, ip_address, " +
                    "user_agent, created_at, prev_hash, entry_hash FROM audit_logs WHERE app_id = ?::uuid ORDER BY seq");
            ps.setString(1, appId);
            rs = ps.executeQuery();
            String expectedPrev = "";
            boolean chainStarted = false;
            int checked = 0;
            while (rs.next()) {
                String auditId = rs.getString("audit_id");
                String stored = rs.getString("entry_hash");
                if (stored == null) {
                    if (chainStarted) {
                        return new ChainVerification(false, checked, expectedPrev, auditId,
                                "Entry has no hash but follows hashed entries.");
                    }
                    continue; // written before the chain existed
                }
                chainStarted = true;
                String prev = rs.getString("prev_hash") == null ? "" : rs.getString("prev_hash").trim();
                if (!prev.equals(expectedPrev)) {
                    return new ChainVerification(false, checked, expectedPrev, auditId,
                            "Previous-entry link does not match - an earlier entry was removed, reordered or altered.");
                }
                Instant createdAt = rs.getObject("created_at", OffsetDateTime.class).toInstant();
                String recomputed = entryHash(prev, auditId, appId, rs.getString("document_id"),
                        rs.getString("event_type"), rs.getString("actor_type"), rs.getString("actor_id"),
                        rs.getString("ip_address"), rs.getString("user_agent"), createdAt);
                if (!recomputed.equals(stored.trim())) {
                    return new ChainVerification(false, checked, expectedPrev, auditId, "Entry contents were altered.");
                }
                expectedPrev = stored.trim();
                checked++;
            }
            return new ChainVerification(true, checked, expectedPrev.isEmpty() ? null : expectedPrev, null, null);
        } finally {
            pool.cleanup(rs, ps, con);
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
