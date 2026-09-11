package org.tsicoop.sign.app;

import org.tsicoop.sign.framework.PoolDB;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class AppRepository {

    public record AppRecord(
            String appId, String appName, String appSlug, boolean isActive,
            String defaultProviderId, String defaultKeyAlias, String webhookUrl, Integer rateLimitRpm,
            String createdAt
    ) {
    }

    /** apps.default_key_alias fallback for seal-local when no keyAlias is supplied (§8). */
    public Optional<String> findDefaultKeyAlias(String appId) {
        String sql = "SELECT default_key_alias FROM apps WHERE app_id = ?::uuid";
        try (Connection con = PoolDB.getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {
            ps.setString(1, appId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return Optional.ofNullable(rs.getString("default_key_alias"));
                }
            }
        } catch (Exception e) {
            return Optional.empty();
        }
        return Optional.empty();
    }

    /** §10.2 Create App wizard: name, slug, default providerId/keyAlias, webhook URL. */
    public String create(String appName, String appSlug, String defaultProviderId, String defaultKeyAlias,
                          String webhookUrl) throws Exception {
        String sql = "INSERT INTO apps (app_name, app_slug, default_provider_id, default_key_alias, webhook_url) " +
                "VALUES (?, ?, ?, ?, ?) RETURNING app_id";
        try (Connection con = PoolDB.getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {
            ps.setString(1, appName);
            ps.setString(2, appSlug);
            ps.setString(3, defaultProviderId);
            ps.setString(4, defaultKeyAlias);
            ps.setString(5, webhookUrl);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getString("app_id");
            }
        }
    }

    public List<AppRecord> list() throws Exception {
        String sql = "SELECT app_id, app_name, app_slug, is_active, default_provider_id, default_key_alias, " +
                "webhook_url, rate_limit_rpm, created_at::text AS created_at FROM apps ORDER BY created_at DESC";
        List<AppRecord> apps = new ArrayList<>();
        try (Connection con = PoolDB.getConnection();
             PreparedStatement ps = con.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                apps.add(mapRow(rs));
            }
        }
        return apps;
    }

    public Optional<AppRecord> findById(String appId) {
        String sql = "SELECT app_id, app_name, app_slug, is_active, default_provider_id, default_key_alias, " +
                "webhook_url, rate_limit_rpm, created_at::text AS created_at FROM apps WHERE app_id = ?::uuid";
        try (Connection con = PoolDB.getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {
            ps.setString(1, appId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(mapRow(rs));
                }
            }
        } catch (Exception e) {
            return Optional.empty();
        }
        return Optional.empty();
    }

    /** §10.2 Signing Defaults tab: default_provider_id / default_key_alias / webhook URL. */
    public void updateSigningDefaults(String appId, String defaultProviderId, String defaultKeyAlias,
                                       String webhookUrl) throws Exception {
        String sql = "UPDATE apps SET default_provider_id = ?, default_key_alias = ?, webhook_url = ?, " +
                "updated_at = now() WHERE app_id = ?::uuid";
        try (Connection con = PoolDB.getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {
            ps.setString(1, defaultProviderId);
            ps.setString(2, defaultKeyAlias);
            ps.setString(3, webhookUrl);
            ps.setString(4, appId);
            ps.executeUpdate();
        }
    }

    /** §10.2 Overview tab, §9 Chunk 9: editable rate_limit_rpm (null = unlimited). */
    public void updateRateLimit(String appId, Integer rateLimitRpm) throws Exception {
        String sql = "UPDATE apps SET rate_limit_rpm = ?, updated_at = now() WHERE app_id = ?::uuid";
        try (Connection con = PoolDB.getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {
            if (rateLimitRpm != null) {
                ps.setInt(1, rateLimitRpm);
            } else {
                ps.setNull(1, java.sql.Types.INTEGER);
            }
            ps.setString(2, appId);
            ps.executeUpdate();
        }
    }

    private AppRecord mapRow(ResultSet rs) throws Exception {
        int rpm = rs.getInt("rate_limit_rpm");
        Integer rateLimitRpm = rs.wasNull() ? null : rpm;
        return new AppRecord(
                rs.getString("app_id"), rs.getString("app_name"), rs.getString("app_slug"),
                rs.getBoolean("is_active"), rs.getString("default_provider_id"),
                rs.getString("default_key_alias"), rs.getString("webhook_url"), rateLimitRpm,
                rs.getString("created_at"));
    }
}
