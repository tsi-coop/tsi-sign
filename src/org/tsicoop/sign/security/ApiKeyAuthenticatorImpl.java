package org.tsicoop.sign.security;

import org.tsicoop.sign.app.AppContext;
import org.tsicoop.sign.framework.ApiKeyGenerator;
import org.tsicoop.sign.framework.PoolDB;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Optional;

/**
 * Resolves an X-API-Key header to its owning App (§6). Hashes the raw key
 * and looks it up by hash — the raw key itself is never stored or logged.
 */
public class ApiKeyAuthenticatorImpl implements ApiKeyAuthenticator {

    private static final String LOOKUP_SQL =
            "SELECT a.app_id, a.app_name, a.app_slug, a.rate_limit_rpm " +
            "FROM api_keys k JOIN apps a ON a.app_id = k.app_id " +
            "WHERE k.key_hash = ? AND k.is_active = TRUE AND a.is_active = TRUE";

    @Override
    public Optional<AppContext> resolve(String rawApiKey) {
        if (rawApiKey == null || rawApiKey.isBlank()) {
            return Optional.empty();
        }
        String keyHash = ApiKeyGenerator.sha256Hex(rawApiKey);
        try (Connection con = PoolDB.getConnection();
             PreparedStatement ps = con.prepareStatement(LOOKUP_SQL)) {
            ps.setString(1, keyHash);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    int rpm = rs.getInt("rate_limit_rpm");
                    Integer rateLimitRpm = rs.wasNull() ? null : rpm;
                    return Optional.of(new AppContext(
                            rs.getString("app_id"), rs.getString("app_name"), rs.getString("app_slug"), rateLimitRpm));
                }
            }
        } catch (Exception e) {
            System.err.println("ApiKeyAuthenticator: lookup failed: " + e.getMessage());
        }
        return Optional.empty();
    }
}
