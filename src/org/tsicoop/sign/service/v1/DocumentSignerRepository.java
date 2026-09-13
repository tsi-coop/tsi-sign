package org.tsicoop.sign.service.v1;

import org.tsicoop.sign.framework.PoolDB;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * `document_signers` CRUD (V1__init_schema.sql) - one row per party a
 * document is routed to for signature. Defined in the schema since Chunk 1
 * but, until Aadhaar eSign, never had any Java code touching it.
 */
public class DocumentSignerRepository {

    public record DocumentSignerRecord(
            String signerId, String documentId, String signerName, String signerEmail, String signerPhone,
            String signatureType, String status, String signedAt
    ) {
    }

    public String create(String documentId, String signerName, String signerEmail, String signerPhone,
                          String signatureType) throws Exception {
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("INSERT INTO document_signers (document_id, signer_name, signer_email, " +
                    "signer_phone, signature_type) VALUES (?::uuid, ?, ?, ?, ?) RETURNING signer_id");
            ps.setString(1, documentId);
            ps.setString(2, signerName);
            ps.setString(3, signerEmail);
            ps.setString(4, signerPhone);
            ps.setString(5, signatureType);
            rs = ps.executeQuery();
            rs.next();
            return rs.getString("signer_id");
        } finally {
            pool.cleanup(rs, ps, con);
        }
    }

    public Optional<DocumentSignerRecord> findById(String signerId) throws Exception {
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("SELECT signer_id, document_id, signer_name, signer_email, signer_phone, " +
                    "signature_type, status, signed_at::text AS signed_at FROM document_signers " +
                    "WHERE signer_id = ?::uuid");
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

    public List<DocumentSignerRecord> listForDocument(String documentId) throws Exception {
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("SELECT signer_id, document_id, signer_name, signer_email, signer_phone, " +
                    "signature_type, status, signed_at::text AS signed_at FROM document_signers " +
                    "WHERE document_id = ?::uuid ORDER BY signer_order, created_at");
            ps.setString(1, documentId);
            rs = ps.executeQuery();
            List<DocumentSignerRecord> signers = new ArrayList<>();
            while (rs.next()) {
                signers.add(toRecord(rs));
            }
            return signers;
        } finally {
            pool.cleanup(rs, ps, con);
        }
    }

    public void markStatus(String signerId, String status) throws Exception {
        Connection con = null;
        PreparedStatement ps = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("UPDATE document_signers SET status = ?, " +
                    "signed_at = CASE WHEN ? = 'SIGNED' THEN now() ELSE signed_at END WHERE signer_id = ?::uuid");
            ps.setString(1, status);
            ps.setString(2, status);
            ps.setString(3, signerId);
            ps.executeUpdate();
        } finally {
            pool.cleanup(null, ps, con);
        }
    }

    private DocumentSignerRecord toRecord(ResultSet rs) throws Exception {
        return new DocumentSignerRecord(
                rs.getString("signer_id"), rs.getString("document_id"), rs.getString("signer_name"),
                rs.getString("signer_email"), rs.getString("signer_phone"), rs.getString("signature_type"),
                rs.getString("status"), rs.getString("signed_at"));
    }
}
