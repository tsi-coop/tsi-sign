package org.tsicoop.sign.seed;

import org.tsicoop.sign.framework.ApiKeyGenerator;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

/**
 * One-off seed script (Chunk 1, §14): inserts one test App and prints its
 * raw API key to the console. No admin UI/API exists yet — this is the only
 * way to provision an App until Chunk 7.
 *
 * Run against a running docker-compose stack with:
 *   mvn exec:java -Dexec.args="'Demo App' demo-app"
 */
public class SeedApp {

    public static void main(String[] args) throws Exception {
        String appName = args.length > 0 ? args[0] : "Demo App";
        String appSlug = args.length > 1 ? args[1] : "demo-app";

        Class.forName("org.postgresql.Driver");
        String dbHost = System.getenv("POSTGRES_HOST");
        String dbName = System.getenv("POSTGRES_DB");
        String dbUser = System.getenv("POSTGRES_USER");
        String dbPass = System.getenv("POSTGRES_PASSWD");
        String sslMode = "local".equals(System.getenv("TSI_SIGN_ENV")) ? "prefer" : "require";
        String jdbcUrl = dbHost + "/" + dbName + "?sslmode=" + sslMode;

        try (Connection con = DriverManager.getConnection(jdbcUrl, dbUser, dbPass)) {
            String appId;
            try (PreparedStatement ps = con.prepareStatement(
                    "INSERT INTO apps (app_name, app_slug) VALUES (?, ?) RETURNING app_id")) {
                ps.setString(1, appName);
                ps.setString(2, appSlug);
                try (ResultSet rs = ps.executeQuery()) {
                    rs.next();
                    appId = rs.getString("app_id");
                }
            }

            ApiKeyGenerator.GeneratedKeyPair pair = ApiKeyGenerator.generate();
            try (PreparedStatement ps = con.prepareStatement(
                    "INSERT INTO api_keys (app_id, api_key, api_secret_hash) VALUES (?::uuid, ?, ?)")) {
                ps.setString(1, appId);
                ps.setString(2, pair.apiKey());
                ps.setString(3, pair.apiSecretHash());
                ps.executeUpdate();
            }

            System.out.println("Seeded App: " + appName + " (" + appSlug + ")");
            System.out.println("  app_id     = " + appId);
            System.out.println("  API key    = " + pair.apiKey() + "   (send as X-API-Key)");
            System.out.println("  API secret = " + pair.apiSecret() + "   (shown once — store it now; send as X-API-Secret)");
        }
    }
}
