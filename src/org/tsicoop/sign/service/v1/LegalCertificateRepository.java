package org.tsicoop.sign.service.v1;

import org.tsicoop.sign.framework.PoolDB;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class LegalCertificateRepository {

    public record CertificateRecord(
            String certificateId,
            String documentId,
            String appId,
            int version,
            String partAJson,
            String partBJson,
            String certificateHash,
            String storageProviderId,
            String certificateStorageKey
    ) {
    }

    /** §10.5 Registry row: certificate + enough document/App context to display without a second lookup. */
    public record RegistryEntry(
            String certificateId, String documentId, String documentTitle, String appId, String appName,
            int version, String certificateHash, String createdAt
    ) {
    }

    public int nextVersion(String documentId) throws Exception {
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("SELECT COALESCE(MAX(version), 0) + 1 AS next_version " +
                    "FROM legal_certificates WHERE document_id = ?::uuid");
            ps.setString(1, documentId);
            rs = ps.executeQuery();
            rs.next();
            return rs.getInt("next_version");
        } finally {
            pool.cleanup(rs, ps, con);
        }
    }

    public String insert(String documentId, String appId, int version, String partAJson, String partBJson,
                          String certificateHash, String storageProviderId, String certificateStorageKey)
            throws Exception {
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("INSERT INTO legal_certificates " +
                    "(document_id, app_id, version, part_a, part_b, certificate_hash, storage_provider_id, " +
                    "certificate_storage_key, sealed_at) " +
                    "VALUES (?::uuid, ?::uuid, ?, ?::jsonb, ?::jsonb, ?, ?, ?, now()) RETURNING certificate_id");
            ps.setString(1, documentId);
            ps.setString(2, appId);
            ps.setInt(3, version);
            ps.setString(4, partAJson);
            ps.setString(5, partBJson);
            ps.setString(6, certificateHash);
            ps.setString(7, storageProviderId);
            ps.setString(8, certificateStorageKey);
            rs = ps.executeQuery();
            rs.next();
            return rs.getString("certificate_id");
        } finally {
            pool.cleanup(rs, ps, con);
        }
    }

    /** "the latest sealed certificate PDF" (§9.4 GET) — highest version for this document. */
    public Optional<CertificateRecord> findLatestForApp(String appId, String documentId) {
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = null;
        try {
            pool = new PoolDB();
            con = pool.getConnection();
            ps = con.prepareStatement("SELECT certificate_id, document_id, app_id, version, part_a::text AS part_a, " +
                    "part_b::text AS part_b, certificate_hash, storage_provider_id, certificate_storage_key " +
                    "FROM legal_certificates WHERE app_id = ?::uuid AND document_id = ?::uuid " +
                    "ORDER BY version DESC LIMIT 1");
            ps.setString(1, appId);
            ps.setString(2, documentId);
            rs = ps.executeQuery();
            if (rs.next()) {
                return Optional.of(new CertificateRecord(
                        rs.getString("certificate_id"),
                        rs.getString("document_id"),
                        rs.getString("app_id"),
                        rs.getInt("version"),
                        rs.getString("part_a"),
                        rs.getString("part_b"),
                        rs.getString("certificate_hash"),
                        rs.getString("storage_provider_id"),
                        rs.getString("certificate_storage_key")));
            }
            return Optional.empty();
        } catch (Exception e) {
            return Optional.empty();
        } finally {
            if (pool != null) pool.cleanup(rs, ps, con);
        }
    }

    /** §10.5 Registry — every issued certificate across all Apps (PLATFORM_ADMIN view; per-App scoping is Chunk 9). */
    public List<RegistryEntry> listAll() throws Exception {
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("SELECT lc.certificate_id, lc.document_id, d.title AS document_title, " +
                    "lc.app_id, a.app_name, lc.version, lc.certificate_hash, lc.created_at::text AS created_at " +
                    "FROM legal_certificates lc " +
                    "JOIN documents d ON d.document_id = lc.document_id " +
                    "JOIN apps a ON a.app_id = lc.app_id " +
                    "ORDER BY lc.created_at DESC");
            rs = ps.executeQuery();
            List<RegistryEntry> entries = new ArrayList<>();
            while (rs.next()) {
                entries.add(new RegistryEntry(
                        rs.getString("certificate_id"), rs.getString("document_id"), rs.getString("document_title"),
                        rs.getString("app_id"), rs.getString("app_name"), rs.getInt("version"),
                        rs.getString("certificate_hash"), rs.getString("created_at")));
            }
            return entries;
        } finally {
            pool.cleanup(rs, ps, con);
        }
    }

    /** Certificate Detail (§10.5) — unscoped by App since PLATFORM_ADMIN can view any certificate. */
    public Optional<CertificateRecord> findById(String certificateId) {
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = null;
        try {
            pool = new PoolDB();
            con = pool.getConnection();
            ps = con.prepareStatement("SELECT certificate_id, document_id, app_id, version, part_a::text AS part_a, " +
                    "part_b::text AS part_b, certificate_hash, storage_provider_id, certificate_storage_key " +
                    "FROM legal_certificates WHERE certificate_id = ?::uuid");
            ps.setString(1, certificateId);
            rs = ps.executeQuery();
            if (rs.next()) {
                return Optional.of(new CertificateRecord(
                        rs.getString("certificate_id"),
                        rs.getString("document_id"),
                        rs.getString("app_id"),
                        rs.getInt("version"),
                        rs.getString("part_a"),
                        rs.getString("part_b"),
                        rs.getString("certificate_hash"),
                        rs.getString("storage_provider_id"),
                        rs.getString("certificate_storage_key")));
            }
            return Optional.empty();
        } catch (Exception e) {
            return Optional.empty();
        } finally {
            if (pool != null) pool.cleanup(rs, ps, con);
        }
    }
}
