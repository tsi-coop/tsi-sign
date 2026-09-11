package org.tsicoop.sign.framework;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

import java.sql.Connection;
import java.sql.SQLException;

/**
 * Thread-safe singleton HikariCP connection pool. TSI_SIGN_ENV=local relaxes
 * sslmode to "prefer" for the docker-compose evaluation setup, where Postgres
 * has no TLS cert configured; any other environment requires "require".
 */
public class PoolDB {

    private static volatile HikariDataSource dataSource = null;

    private static void initDataSource() {
        synchronized (PoolDB.class) {
            if (dataSource == null) {
                try {
                    Class.forName("org.postgresql.Driver");

                    HikariConfig config = new HikariConfig();

                    String dbHost = SystemConfig.getAppConfig().getProperty("framework.db.host");
                    String dbName = SystemConfig.getAppConfig().getProperty("framework.db.name");
                    String sslMode = "local".equals(System.getenv("TSI_SIGN_ENV")) ? "prefer" : "require";
                    config.setJdbcUrl(dbHost + "/" + dbName + "?sslmode=" + sslMode);
                    config.setUsername(SystemConfig.getAppConfig().getProperty("framework.db.user"));
                    config.setPassword(SystemConfig.getAppConfig().getProperty("framework.db.password"));

                    config.setMaximumPoolSize(15);
                    config.setMinimumIdle(5);
                    config.setConnectionTimeout(30000);
                    config.setIdleTimeout(600000);
                    config.setMaxLifetime(1800000);

                    config.addDataSourceProperty("cachePrepStmts", "true");
                    config.addDataSourceProperty("prepStmtCacheSize", "250");
                    config.addDataSourceProperty("prepStmtCacheSqlLimit", "2048");
                    config.addDataSourceProperty("useServerPrepStmts", "true");

                    dataSource = new HikariDataSource(config);
                    System.out.println("TSI Sign: HikariCP DataSource initialized.");
                } catch (ClassNotFoundException e) {
                    throw new RuntimeException("PostgreSQL Driver not found", e);
                }
            }
        }
    }

    public static Connection getConnection() throws SQLException {
        if (dataSource == null) {
            initDataSource();
        }
        return dataSource.getConnection();
    }
}
