package org.tsicoop.sign.framework;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import org.flywaydb.core.Flyway;

/**
 * Loads DB config from environment and applies pending Flyway migrations
 * (resources/db/migration, packaged onto the classpath) before any request
 * is served.
 */
public class AppBootstrapListener implements ServletContextListener {

    @Override
    public void contextInitialized(ServletContextEvent sce) {
        SystemConfig.loadAppConfig(sce.getServletContext());

        String dbHost = SystemConfig.getAppConfig().getProperty("framework.db.host");
        String dbName = SystemConfig.getAppConfig().getProperty("framework.db.name");
        String dbUser = SystemConfig.getAppConfig().getProperty("framework.db.user");
        String dbPass = SystemConfig.getAppConfig().getProperty("framework.db.password");
        String sslMode = "local".equals(System.getenv("TSI_SIGN_ENV")) ? "prefer" : "require";
        String jdbcUrl = dbHost + "/" + dbName + "?sslmode=" + sslMode;

        Flyway.configure()
                .dataSource(jdbcUrl, dbUser, dbPass)
                .locations("classpath:db/migration")
                .load()
                .migrate();

        System.out.println("TSI Sign: Flyway migrations applied; started in "
                + System.getenv("TSI_SIGN_ENV") + " environment.");
    }

    @Override
    public void contextDestroyed(ServletContextEvent sce) {
    }
}
