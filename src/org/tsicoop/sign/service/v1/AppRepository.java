package org.tsicoop.sign.service.v1;

import org.tsicoop.sign.framework.PoolDB;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Types;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class AppRepository {

    public record AppRecord(
            String appId, String appName, String appSlug, boolean isActive,
            String defaultProviderId, String defaultKeyAlias, String webhookUrl, Integer rateLimitRpm,
            String storageProviderId, String createdAt
    ) {
    }

    /** apps.default_key_alias fallback for seal-local when no keyAlias is supplied (§8). */
    public Optional<String> findDefaultKeyAlias(String appId) {
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = null;
        try {
            pool = new PoolDB();
            con = pool.getConnection();
            ps = con.prepareStatement("SELECT default_key_alias FROM apps WHERE app_id = ?::uuid");
            ps.setString(1, appId);
            rs = ps.executeQuery();
            if (rs.next()) {
                return Optional.ofNullable(rs.getString("default_key_alias"));
            }
            return Optional.empty();
        } catch (Exception e) {
            return Optional.empty();
        } finally {
            if (pool != null) pool.cleanup(rs, ps, con);
        }
    }

    /** §10.2 Create App wizard: name, slug, default providerId/keyAlias, webhook URL. */
    public String create(String appName, String appSlug, String defaultProviderId, String defaultKeyAlias,
                          String webhookUrl) throws Exception {
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("INSERT INTO apps (app_name, app_slug, default_provider_id, " +
                    "default_key_alias, webhook_url) VALUES (?, ?, ?, ?, ?) RETURNING app_id");
            ps.setString(1, appName);
            ps.setString(2, appSlug);
            ps.setString(3, defaultProviderId);
            ps.setString(4, defaultKeyAlias);
            ps.setString(5, webhookUrl);
            rs = ps.executeQuery();
            rs.next();
            return rs.getString("app_id");
        } finally {
            pool.cleanup(rs, ps, con);
        }
    }

    public List<AppRecord> list() throws Exception {
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("SELECT app_id, app_name, app_slug, is_active, default_provider_id, " +
                    "default_key_alias, webhook_url, rate_limit_rpm, storage_provider_id, created_at::text AS created_at " +
                    "FROM apps ORDER BY created_at DESC");
            rs = ps.executeQuery();
            List<AppRecord> apps = new ArrayList<>();
            while (rs.next()) {
                apps.add(mapRow(rs));
            }
            return apps;
        } finally {
            pool.cleanup(rs, ps, con);
        }
    }

    public Optional<AppRecord> findById(String appId) {
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = null;
        try {
            pool = new PoolDB();
            con = pool.getConnection();
            ps = con.prepareStatement("SELECT app_id, app_name, app_slug, is_active, default_provider_id, " +
                    "default_key_alias, webhook_url, rate_limit_rpm, storage_provider_id, created_at::text AS created_at " +
                    "FROM apps WHERE app_id = ?::uuid");
            ps.setString(1, appId);
            rs = ps.executeQuery();
            if (rs.next()) {
                return Optional.of(mapRow(rs));
            }
            return Optional.empty();
        } catch (Exception e) {
            return Optional.empty();
        } finally {
            if (pool != null) pool.cleanup(rs, ps, con);
        }
    }

    /** §10.2 Signing Defaults tab: default_provider_id / default_key_alias / webhook URL. */
    public void updateSigningDefaults(String appId, String defaultProviderId, String defaultKeyAlias,
                                       String webhookUrl) throws Exception {
        Connection con = null;
        PreparedStatement ps = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("UPDATE apps SET default_provider_id = ?, default_key_alias = ?, " +
                    "webhook_url = ?, updated_at = now() WHERE app_id = ?::uuid");
            ps.setString(1, defaultProviderId);
            ps.setString(2, defaultKeyAlias);
            ps.setString(3, webhookUrl);
            ps.setString(4, appId);
            ps.executeUpdate();
        } finally {
            pool.cleanup(null, ps, con);
        }
    }

    /**
     * Chunk 12, §5.2: per-App storage backend override. NULL = fall back to
     * the deployment-wide DEFAULT_STORAGE_PROVIDER_ID (see
     * StorageProviderRegistry) - e.g. Loan App pinned to privacy_vault while
     * everything else uses the deployment default.
     */
    public void updateStorageProvider(String appId, String storageProviderId) throws Exception {
        Connection con = null;
        PreparedStatement ps = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("UPDATE apps SET storage_provider_id = ?, updated_at = now() WHERE app_id = ?::uuid");
            ps.setString(1, storageProviderId);
            ps.setString(2, appId);
            ps.executeUpdate();
        } finally {
            pool.cleanup(null, ps, con);
        }
    }

    /** §10.2 Overview tab, §9 Chunk 9: editable rate_limit_rpm (null = unlimited). */
    public void updateRateLimit(String appId, Integer rateLimitRpm) throws Exception {
        Connection con = null;
        PreparedStatement ps = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("UPDATE apps SET rate_limit_rpm = ?, updated_at = now() WHERE app_id = ?::uuid");
            if (rateLimitRpm != null) {
                ps.setInt(1, rateLimitRpm);
            } else {
                ps.setNull(1, Types.INTEGER);
            }
            ps.setString(2, appId);
            ps.executeUpdate();
        } finally {
            pool.cleanup(null, ps, con);
        }
    }

    private AppRecord mapRow(ResultSet rs) throws Exception {
        int rpm = rs.getInt("rate_limit_rpm");
        Integer rateLimitRpm = rs.wasNull() ? null : rpm;
        return new AppRecord(
                rs.getString("app_id"), rs.getString("app_name"), rs.getString("app_slug"),
                rs.getBoolean("is_active"), rs.getString("default_provider_id"),
                rs.getString("default_key_alias"), rs.getString("webhook_url"), rateLimitRpm,
                rs.getString("storage_provider_id"), rs.getString("created_at"));
    }
}
