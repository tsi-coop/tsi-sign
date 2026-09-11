package org.tsicoop.sign.service.v1;

import org.tsicoop.sign.framework.ApiKeyGenerator;
import org.tsicoop.sign.framework.PoolDB;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

/** §10.2 API Keys tab: issue (reveal-once), list, revoke. */
public class ApiKeyRepository {

    public record ApiKeyRecord(
            String keyId, String appId, String keyPrefix, boolean isActive, String createdAt, String revokedAt
    ) {
    }

    public ApiKeyGenerator.GeneratedKey issue(String appId) throws Exception {
        ApiKeyGenerator.GeneratedKey key = ApiKeyGenerator.generate();
        Connection con = null;
        PreparedStatement ps = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("INSERT INTO api_keys (app_id, key_hash, key_prefix) VALUES (?::uuid, ?, ?)");
            ps.setString(1, appId);
            ps.setString(2, key.keyHash());
            ps.setString(3, key.keyPrefix());
            ps.executeUpdate();
        } finally {
            pool.cleanup(null, ps, con);
        }
        return key;
    }

    public List<ApiKeyRecord> listForApp(String appId) throws Exception {
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("SELECT key_id, app_id, key_prefix, is_active, created_at::text AS created_at, " +
                    "revoked_at::text AS revoked_at FROM api_keys WHERE app_id = ?::uuid ORDER BY created_at DESC");
            ps.setString(1, appId);
            rs = ps.executeQuery();
            List<ApiKeyRecord> keys = new ArrayList<>();
            while (rs.next()) {
                keys.add(new ApiKeyRecord(
                        rs.getString("key_id"), rs.getString("app_id"), rs.getString("key_prefix"),
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
