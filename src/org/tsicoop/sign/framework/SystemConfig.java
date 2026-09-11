package org.tsicoop.sign.framework;

import jakarta.servlet.ServletContext;

import java.util.Properties;

/**
 * Holds DB connection settings read from environment variables at container
 * startup (AppBootstrapListener). Same env var names as the DB host string
 * passed to Flyway: POSTGRES_HOST is the full "jdbc:postgresql://host:port"
 * prefix, not just a hostname (matches the docker-compose convention shared
 * across TSI products).
 */
public class SystemConfig {

    private static Properties appConfig;

    public static void loadAppConfig(ServletContext ctx) {
        if (appConfig == null) {
            appConfig = new Properties();
        }
        appConfig.setProperty("framework.db.name", System.getenv("POSTGRES_DB"));
        appConfig.setProperty("framework.db.user", System.getenv("POSTGRES_USER"));
        appConfig.setProperty("framework.db.password", System.getenv("POSTGRES_PASSWD"));
        appConfig.setProperty("framework.db.host", System.getenv("POSTGRES_HOST"));
    }

    public static Properties getAppConfig() {
        return appConfig;
    }
}
