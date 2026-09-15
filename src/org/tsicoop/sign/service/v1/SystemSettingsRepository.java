package org.tsicoop.sign.service.v1;

import org.tsicoop.sign.framework.PoolDB;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

/**
 * The `system_settings` singleton row (db/06_system_settings.sql) - the
 * deployment-wide storage backend config console screen writes to. Every
 * field is nullable: null means "fall back to the equivalent env var" (see
 * StorageProviderRegistry), the same convention apps.storage_provider_id
 * already uses for its own fallback-to-default.
 */
public class SystemSettingsRepository {

    public record SystemSettingsRecord(
            String defaultStorageProviderId,
            String s3Endpoint, String s3Region, String s3Bucket, String s3AccessKey, String s3SecretKey,
            Boolean s3PathStyleAccess, String s3Sse, String s3KmsKeyId,
            String privacyVaultBaseUrl, String privacyVaultApiKey, String privacyVaultEntityCode
    ) {
    }

    public SystemSettingsRecord get() throws Exception {
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("SELECT default_storage_provider_id, s3_endpoint, s3_region, s3_bucket, " +
                    "s3_access_key, s3_secret_key, s3_path_style_access, s3_sse, s3_kms_key_id, " +
                    "privacy_vault_base_url, privacy_vault_api_key, privacy_vault_entity_code " +
                    "FROM system_settings WHERE id = TRUE");
            rs = ps.executeQuery();
            rs.next();
            return toRecord(rs);
        } finally {
            pool.cleanup(rs, ps, con);
        }
    }

    public void update(SystemSettingsRecord settings) throws Exception {
        Connection con = null;
        PreparedStatement ps = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("UPDATE system_settings SET default_storage_provider_id = ?, " +
                    "s3_endpoint = ?, s3_region = ?, s3_bucket = ?, s3_access_key = ?, s3_secret_key = ?, " +
                    "s3_path_style_access = ?, s3_sse = ?, s3_kms_key_id = ?, " +
                    "privacy_vault_base_url = ?, privacy_vault_api_key = ?, privacy_vault_entity_code = ?, " +
                    "updated_at = now() WHERE id = TRUE");
            ps.setString(1, settings.defaultStorageProviderId());
            ps.setString(2, settings.s3Endpoint());
            ps.setString(3, settings.s3Region());
            ps.setString(4, settings.s3Bucket());
            ps.setString(5, settings.s3AccessKey());
            ps.setString(6, settings.s3SecretKey());
            if (settings.s3PathStyleAccess() != null) {
                ps.setBoolean(7, settings.s3PathStyleAccess());
            } else {
                ps.setNull(7, java.sql.Types.BOOLEAN);
            }
            ps.setString(8, settings.s3Sse());
            ps.setString(9, settings.s3KmsKeyId());
            ps.setString(10, settings.privacyVaultBaseUrl());
            ps.setString(11, settings.privacyVaultApiKey());
            ps.setString(12, settings.privacyVaultEntityCode());
            ps.executeUpdate();
        } finally {
            pool.cleanup(null, ps, con);
        }
    }

    private SystemSettingsRecord toRecord(ResultSet rs) throws Exception {
        boolean pathStyleRaw = rs.getBoolean("s3_path_style_access");
        Boolean pathStyle = rs.wasNull() ? null : pathStyleRaw;
        return new SystemSettingsRecord(
                rs.getString("default_storage_provider_id"),
                rs.getString("s3_endpoint"), rs.getString("s3_region"), rs.getString("s3_bucket"),
                rs.getString("s3_access_key"), rs.getString("s3_secret_key"),
                pathStyle,
                rs.getString("s3_sse"), rs.getString("s3_kms_key_id"),
                rs.getString("privacy_vault_base_url"), rs.getString("privacy_vault_api_key"),
                rs.getString("privacy_vault_entity_code"));
    }
}
