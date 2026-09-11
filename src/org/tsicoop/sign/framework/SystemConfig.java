package org.tsicoop.sign.framework;

import jakarta.servlet.ServletContext;

import java.io.IOException;
import java.util.Properties;

/**
 * Holds DB connection settings read from environment variables at container
 * startup (AppBootstrapListener), and the _processor.tsi service registry
 * InterceptingFilter dispatches on (§6, TSI framework standard pattern —
 * matches tsi-ledger/tsi-dpdp-cms/tsi-privacy-vault). Same env var names as
 * the DB host string passed to Flyway: POSTGRES_HOST is the full
 * "jdbc:postgresql://host:port" prefix, not just a hostname.
 */
public class SystemConfig {

    private static Properties appConfig;
    private static Properties processorConfig;

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

    public static void loadProcessorConfig(ServletContext ctx) {
        if (processorConfig == null) {
            processorConfig = new Properties();
            try {
                processorConfig.load(ctx.getResourceAsStream("/WEB-INF/_processor.tsi"));
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public static Properties getProcessorConfig() {
        return processorConfig;
    }
}
