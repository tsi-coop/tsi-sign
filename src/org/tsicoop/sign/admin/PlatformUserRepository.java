package org.tsicoop.sign.admin;

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
        String sql = "SELECT 1 FROM platform_users LIMIT 1";
        try (Connection con = PoolDB.getConnection();
             PreparedStatement ps = con.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            return rs.next();
        }
    }

    public String create(String email, String fullName, String passwordHash, String role) throws Exception {
        String sql = "INSERT INTO platform_users (email, full_name, password_hash, role) " +
                "VALUES (?, ?, ?, ?) RETURNING user_id";
        try (Connection con = PoolDB.getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {
            ps.setString(1, email);
            ps.setString(2, fullName);
            ps.setString(3, passwordHash);
            ps.setString(4, role);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getString("user_id");
            }
        }
    }

    public Optional<PlatformUserRecord> findByEmail(String email) {
        String sql = "SELECT user_id, email, full_name, password_hash, role, is_active " +
                "FROM platform_users WHERE email = ? AND is_active = TRUE";
        try (Connection con = PoolDB.getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {
            ps.setString(1, email);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(new PlatformUserRecord(
                            rs.getString("user_id"), rs.getString("email"), rs.getString("full_name"),
                            rs.getString("password_hash"), rs.getString("role"), rs.getBoolean("is_active")));
                }
            }
        } catch (Exception e) {
            return Optional.empty();
        }
        return Optional.empty();
    }

    public Optional<PlatformUserRecord> findById(String userId) {
        String sql = "SELECT user_id, email, full_name, password_hash, role, is_active " +
                "FROM platform_users WHERE user_id = ?::uuid";
        try (Connection con = PoolDB.getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {
            ps.setString(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return Optional.of(new PlatformUserRecord(
                            rs.getString("user_id"), rs.getString("email"), rs.getString("full_name"),
                            rs.getString("password_hash"), rs.getString("role"), rs.getBoolean("is_active")));
                }
            }
        } catch (Exception e) {
            return Optional.empty();
        }
        return Optional.empty();
    }

    /** §10.7 Platform Users & Roles list. */
    public List<PlatformUserRecord> listAll() throws Exception {
        String sql = "SELECT user_id, email, full_name, password_hash, role, is_active " +
                "FROM platform_users ORDER BY full_name";
        List<PlatformUserRecord> users = new ArrayList<>();
        try (Connection con = PoolDB.getConnection();
             PreparedStatement ps = con.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                users.add(new PlatformUserRecord(
                        rs.getString("user_id"), rs.getString("email"), rs.getString("full_name"),
                        rs.getString("password_hash"), rs.getString("role"), rs.getBoolean("is_active")));
            }
        }
        return users;
    }

    public void setActive(String userId, boolean isActive) throws Exception {
        String sql = "UPDATE platform_users SET is_active = ? WHERE user_id = ?::uuid";
        try (Connection con = PoolDB.getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {
            ps.setBoolean(1, isActive);
            ps.setString(2, userId);
            ps.executeUpdate();
        }
    }
}
