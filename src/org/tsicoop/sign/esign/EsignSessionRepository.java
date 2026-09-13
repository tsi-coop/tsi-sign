package org.tsicoop.sign.esign;

import org.tsicoop.sign.framework.PoolDB;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Optional;

/** `esign_sessions` CRUD - see V4__esign_sessions.sql and the Aadhaar eSign plan. */
public class EsignSessionRepository {

    public record EsignSessionRecord(
            String sessionId, String documentId, String signerId, String providerId, String transactionId,
            String preparedStorageKey, int[] byteRange, String signatureFieldName, String status, String gatewayUrl
    ) {
    }

    public String create(String documentId, String signerId, String providerId, String transactionId,
                          String preparedStorageKey, int[] byteRange, String signatureFieldName,
                          String gatewayUrl) throws Exception {
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("INSERT INTO esign_sessions (document_id, signer_id, provider_id, " +
                    "transaction_id, prepared_storage_key, byte_range_0, byte_range_1, byte_range_2, " +
                    "byte_range_3, signature_field_name, gateway_url) " +
                    "VALUES (?::uuid, ?::uuid, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING session_id");
            ps.setString(1, documentId);
            ps.setString(2, signerId);
            ps.setString(3, providerId);
            ps.setString(4, transactionId);
            ps.setString(5, preparedStorageKey);
            ps.setInt(6, byteRange[0]);
            ps.setInt(7, byteRange[1]);
            ps.setInt(8, byteRange[2]);
            ps.setInt(9, byteRange[3]);
            ps.setString(10, signatureFieldName);
            ps.setString(11, gatewayUrl);
            rs = ps.executeQuery();
            rs.next();
            return rs.getString("session_id");
        } finally {
            pool.cleanup(rs, ps, con);
        }
    }

    public Optional<EsignSessionRecord> findByTransactionId(String providerId, String transactionId) throws Exception {
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("SELECT session_id, document_id, signer_id, provider_id, transaction_id, " +
                    "prepared_storage_key, byte_range_0, byte_range_1, byte_range_2, byte_range_3, " +
                    "signature_field_name, status, gateway_url FROM esign_sessions " +
                    "WHERE provider_id = ? AND transaction_id = ?");
            ps.setString(1, providerId);
            ps.setString(2, transactionId);
            rs = ps.executeQuery();
            if (rs.next()) {
                return Optional.of(toRecord(rs));
            }
            return Optional.empty();
        } finally {
            pool.cleanup(rs, ps, con);
        }
    }

    /** The console/get_document uses this to show a "resume signing" link while a session is still in flight. */
    public Optional<EsignSessionRecord> findActiveForSigner(String signerId) throws Exception {
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("SELECT session_id, document_id, signer_id, provider_id, transaction_id, " +
                    "prepared_storage_key, byte_range_0, byte_range_1, byte_range_2, byte_range_3, " +
                    "signature_field_name, status, gateway_url FROM esign_sessions " +
                    "WHERE signer_id = ?::uuid AND status = 'INITIATED' ORDER BY created_at DESC LIMIT 1");
            ps.setString(1, signerId);
            rs = ps.executeQuery();
            if (rs.next()) {
                return Optional.of(toRecord(rs));
            }
            return Optional.empty();
        } finally {
            pool.cleanup(rs, ps, con);
        }
    }

    public void markStatus(String sessionId, String status) throws Exception {
        Connection con = null;
        PreparedStatement ps = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("UPDATE esign_sessions SET status = ?, " +
                    "completed_at = CASE WHEN ? IN ('COMPLETED','FAILED','EXPIRED') THEN now() ELSE completed_at END " +
                    "WHERE session_id = ?::uuid");
            ps.setString(1, status);
            ps.setString(2, status);
            ps.setString(3, sessionId);
            ps.executeUpdate();
        } finally {
            pool.cleanup(null, ps, con);
        }
    }

    private EsignSessionRecord toRecord(ResultSet rs) throws Exception {
        int[] byteRange = {
                rs.getInt("byte_range_0"), rs.getInt("byte_range_1"),
                rs.getInt("byte_range_2"), rs.getInt("byte_range_3")
        };
        return new EsignSessionRecord(
                rs.getString("session_id"), rs.getString("document_id"), rs.getString("signer_id"),
                rs.getString("provider_id"), rs.getString("transaction_id"), rs.getString("prepared_storage_key"),
                byteRange, rs.getString("signature_field_name"), rs.getString("status"), rs.getString("gateway_url"));
    }
}
