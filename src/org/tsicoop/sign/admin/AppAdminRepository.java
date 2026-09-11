package org.tsicoop.sign.admin;

import org.tsicoop.sign.framework.PoolDB;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** app_admins scoping: which APP_MANAGER platform_users administer which Apps (§4.2, §10.2/§10.7). */
public class AppAdminRepository {

    public record AssignedUser(String userId, String email, String fullName) {
    }

    public void assign(String appId, String userId) throws Exception {
        String sql = "INSERT INTO app_admins (app_id, user_id) VALUES (?::uuid, ?::uuid) ON CONFLICT DO NOTHING";
        try (Connection con = PoolDB.getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {
            ps.setString(1, appId);
            ps.setString(2, userId);
            ps.executeUpdate();
        }
    }

    public void unassign(String appId, String userId) throws Exception {
        String sql = "DELETE FROM app_admins WHERE app_id = ?::uuid AND user_id = ?::uuid";
        try (Connection con = PoolDB.getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {
            ps.setString(1, appId);
            ps.setString(2, userId);
            ps.executeUpdate();
        }
    }

    public boolean isAssigned(String appId, String userId) throws Exception {
        String sql = "SELECT 1 FROM app_admins WHERE app_id = ?::uuid AND user_id = ?::uuid";
        try (Connection con = PoolDB.getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {
            ps.setString(1, appId);
            ps.setString(2, userId);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    public Set<String> listAppIdsForUser(String userId) throws Exception {
        String sql = "SELECT app_id::text AS app_id FROM app_admins WHERE user_id = ?::uuid";
        Set<String> ids = new HashSet<>();
        try (Connection con = PoolDB.getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {
            ps.setString(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    ids.add(rs.getString("app_id"));
                }
            }
        }
        return ids;
    }

    public List<AssignedUser> listUsersForApp(String appId) throws Exception {
        String sql = "SELECT u.user_id, u.email, u.full_name FROM app_admins aa " +
                "JOIN platform_users u ON u.user_id = aa.user_id " +
                "WHERE aa.app_id = ?::uuid ORDER BY u.full_name";
        List<AssignedUser> users = new ArrayList<>();
        try (Connection con = PoolDB.getConnection();
             PreparedStatement ps = con.prepareStatement(sql)) {
            ps.setString(1, appId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    users.add(new AssignedUser(rs.getString("user_id"), rs.getString("email"), rs.getString("full_name")));
                }
            }
        }
        return users;
    }
}
