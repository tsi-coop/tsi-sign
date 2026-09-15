package org.tsicoop.sign.service.v1;

import org.tsicoop.sign.framework.ApiKeyGenerator;
import org.tsicoop.sign.framework.PoolDB;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * §10.2 API Keys tab: issue/rotate (reveal-once), list, revoke - the
 * key+secret pair pattern shared across the TSI stack (tsi-ledger's App.java
 * is the canonical reference). api_key is a non-secret identifier, always
 * listable; only api_secret_hash is ever persisted for the real credential.
 */
public class ApiKeyRepository {

    public record ApiKeyRecord(
            String keyId, String appId, String apiKey, boolean isActive, String createdAt, String revokedAt
    ) {
    }

    public ApiKeyGenerator.GeneratedKeyPair issue(String appId) throws Exception {
        ApiKeyGenerator.GeneratedKeyPair pair = ApiKeyGenerator.generate();
        Connection con = null;
        PreparedStatement ps = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("INSERT INTO api_keys (app_id, api_key, api_secret_hash) VALUES (?::uuid, ?, ?)");
            ps.setString(1, appId);
            ps.setString(2, pair.apiKey());
            ps.setString(3, pair.apiSecretHash());
            ps.executeUpdate();
        } finally {
            pool.cleanup(null, ps, con);
        }
        return pair;
    }

    /**
     * Regenerates BOTH the api_key and the secret for an existing row
     * (matches tsi-ledger's rotate_api_key, not tsi-nexus's secret-only
     * variant) - the old key stops resolving immediately. Returns empty if
     * no active key matched (wrong app or already revoked).
     */
    public Optional<ApiKeyGenerator.GeneratedKeyPair> rotate(String appId, String keyId) throws Exception {
        ApiKeyGenerator.GeneratedKeyPair pair = ApiKeyGenerator.generate();
        Connection con = null;
        PreparedStatement ps = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("UPDATE api_keys SET api_key = ?, api_secret_hash = ? " +
                    "WHERE key_id = ?::uuid AND app_id = ?::uuid AND is_active = TRUE");
            ps.setString(1, pair.apiKey());
            ps.setString(2, pair.apiSecretHash());
            ps.setString(3, keyId);
            ps.setString(4, appId);
            int updated = ps.executeUpdate();
            return updated > 0 ? Optional.of(pair) : Optional.empty();
        } finally {
            pool.cleanup(null, ps, con);
        }
    }

    public List<ApiKeyRecord> listForApp(String appId) throws Exception {
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("SELECT key_id, app_id, api_key, is_active, created_at::text AS created_at, " +
                    "revoked_at::text AS revoked_at FROM api_keys WHERE app_id = ?::uuid ORDER BY created_at DESC");
            ps.setString(1, appId);
            rs = ps.executeQuery();
            List<ApiKeyRecord> keys = new ArrayList<>();
            while (rs.next()) {
                keys.add(new ApiKeyRecord(
                        rs.getString("key_id"), rs.getString("app_id"), rs.getString("api_key"),
                        rs.getBoolean("is_active"), rs.getString("created_at"), rs.getString("revoked_at")));
            }
            return keys;
        } finally {
            pool.cleanup(rs, ps, con);
        }
    }

    /** Scoped to appId so a key can only be revoked through its own App's admin page. */
    public boolean revoke(String appId, String keyId) throws Exception {
        Connection con = null;
        PreparedStatement ps = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("UPDATE api_keys SET is_active = FALSE, revoked_at = now() " +
                    "WHERE key_id = ?::uuid AND app_id = ?::uuid AND is_active = TRUE");
            ps.setString(1, keyId);
            ps.setString(2, appId);
            return ps.executeUpdate() > 0;
        } finally {
            pool.cleanup(null, ps, con);
        }
    }

}
