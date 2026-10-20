package org.tsicoop.sign.service.v1;

import org.tsicoop.sign.framework.PoolDB;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/** platform_users CRUD for the admin console (§4.1, §10.7). */
public class PlatformUserRepository {

    public record PlatformUserRecord(
            String userId, String email, String fullName, String passwordHash, String role, boolean isActive
    ) {
    }

    public boolean anyExists() throws Exception {
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("SELECT 1 FROM platform_users LIMIT 1");
            rs = ps.executeQuery();
            return rs.next();
        } finally {
            pool.cleanup(rs, ps, con);
        }
    }

    public String create(String email, String fullName, String passwordHash, String role) throws Exception {
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("INSERT INTO platform_users (email, full_name, password_hash, role) " +
                    "VALUES (?, ?, ?, ?) RETURNING user_id");
            ps.setString(1, email);
            ps.setString(2, fullName);
            ps.setString(3, passwordHash);
            ps.setString(4, role);
            rs = ps.executeQuery();
            rs.next();
            return rs.getString("user_id");
        } finally {
            pool.cleanup(rs, ps, con);
        }
    }

    /**
     * Creates the first user only if platform_users is still empty, with the check and the insert
     * in one SERIALIZABLE transaction: if two setup requests both see an empty table, Postgres
     * aborts the loser (SQLState 40001) rather than letting both create an admin.
     * Returns the new user id, or empty if a user already exists (or this request lost the race).
     */
    public Optional<String> createIfNoneExist(String email, String fullName, String passwordHash, String role)
            throws Exception {
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB(false);
        try {
            con = pool.getConnection();
            con.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);
            ps = con.prepareStatement("SELECT 1 FROM platform_users LIMIT 1");
            rs = ps.executeQuery();
            boolean exists = rs.next();
            rs.close();
            ps.close();
            if (exists) {
                con.rollback();
                return Optional.empty();
            }
            ps = con.prepareStatement("INSERT INTO platform_users (email, full_name, password_hash, role) " +
                    "VALUES (?, ?, ?, ?) RETURNING user_id");
            ps.setString(1, email);
            ps.setString(2, fullName);
            ps.setString(3, passwordHash);
            ps.setString(4, role);
            rs = ps.executeQuery();
            rs.next();
            String userId = rs.getString("user_id");
            con.commit();
            return Optional.of(userId);
        } catch (java.sql.SQLException e) {
            if (con != null) con.rollback();
            if ("40001".equals(e.getSQLState())) {
                return Optional.empty();
            }
            throw e;
        } finally {
            // The pooled connection is reused: restore the defaults before handing it back.
            if (con != null) {
                try {
                    con.setTransactionIsolation(Connection.TRANSACTION_READ_COMMITTED);
                    con.setAutoCommit(true);
                } catch (Exception ignored) {
                }
            }
            pool.cleanup(rs, ps, con);
        }
    }

    public Optional<PlatformUserRecord> findByEmail(String email) {
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = null;
        try {
            pool = new PoolDB();
            con = pool.getConnection();
            ps = con.prepareStatement("SELECT user_id, email, full_name, password_hash, role, is_active " +
                    "FROM platform_users WHERE email = ? AND is_active = TRUE");
            ps.setString(1, email);
            rs = ps.executeQuery();
            if (rs.next()) {
                return Optional.of(new PlatformUserRecord(
                        rs.getString("user_id"), rs.getString("email"), rs.getString("full_name"),
                        rs.getString("password_hash"), rs.getString("role"), rs.getBoolean("is_active")));
            }
            return Optional.empty();
        } catch (Exception e) {
            return Optional.empty();
        } finally {
            if (pool != null) pool.cleanup(rs, ps, con);
        }
    }

    public Optional<PlatformUserRecord> findById(String userId) {
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = null;
        try {
            pool = new PoolDB();
            con = pool.getConnection();
            ps = con.prepareStatement("SELECT user_id, email, full_name, password_hash, role, is_active " +
                    "FROM platform_users WHERE user_id = ?::uuid");
            ps.setString(1, userId);
            rs = ps.executeQuery();
            if (rs.next()) {
                return Optional.of(new PlatformUserRecord(
                        rs.getString("user_id"), rs.getString("email"), rs.getString("full_name"),
                        rs.getString("password_hash"), rs.getString("role"), rs.getBoolean("is_active")));
            }
            return Optional.empty();
        } catch (Exception e) {
            return Optional.empty();
        } finally {
            if (pool != null) pool.cleanup(rs, ps, con);
        }
    }

    /** §10.7 Platform Users & Roles list. */
    public List<PlatformUserRecord> listAll() throws Exception {
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("SELECT user_id, email, full_name, password_hash, role, is_active " +
                    "FROM platform_users ORDER BY full_name");
            rs = ps.executeQuery();
            List<PlatformUserRecord> users = new ArrayList<>();
            while (rs.next()) {
                users.add(new PlatformUserRecord(
                        rs.getString("user_id"), rs.getString("email"), rs.getString("full_name"),
                        rs.getString("password_hash"), rs.getString("role"), rs.getBoolean("is_active")));
            }
            return users;
        } finally {
            pool.cleanup(rs, ps, con);
        }
    }

    public void setActive(String userId, boolean isActive) throws Exception {
        Connection con = null;
        PreparedStatement ps = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("UPDATE platform_users SET is_active = ? WHERE user_id = ?::uuid");
            ps.setBoolean(1, isActive);
            ps.setString(2, userId);
            ps.executeUpdate();
        } finally {
            pool.cleanup(null, ps, con);
        }
    }

    /** Break-glass recovery key (§ RecoveryKeyGenerator): not single-use, persists until replaced. */
    public boolean setRecoveryKeyHash(String userId, String recoveryKeyHash) throws Exception {
        Connection con = null;
        PreparedStatement ps = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("UPDATE platform_users SET recovery_key_hash = ? WHERE user_id = ?::uuid");
            ps.setString(1, recoveryKeyHash);
            ps.setString(2, userId);
            return ps.executeUpdate() > 0;
        } finally {
            pool.cleanup(null, ps, con);
        }
    }

    /** True if this active user's recovery_key_hash matches - used by the public password-reset flow. */
    public boolean verifyRecoveryKey(String email, String recoveryKeyHash) throws Exception {
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("SELECT 1 FROM platform_users " +
                    "WHERE email = ? AND recovery_key_hash = ? AND is_active = TRUE");
            ps.setString(1, email);
            ps.setString(2, recoveryKeyHash);
            rs = ps.executeQuery();
            return rs.next();
        } finally {
            pool.cleanup(rs, ps, con);
        }
    }

    public void updatePasswordHash(String email, String passwordHash) throws Exception {
        Connection con = null;
        PreparedStatement ps = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("UPDATE platform_users SET password_hash = ? WHERE email = ?");
            ps.setString(1, passwordHash);
            ps.setString(2, email);
            ps.executeUpdate();
        } finally {
            pool.cleanup(null, ps, con);
        }
    }
}
