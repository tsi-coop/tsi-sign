package org.tsicoop.sign.service.v1;

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
        Connection con = null;
        PreparedStatement ps = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("INSERT INTO app_admins (app_id, user_id) VALUES (?::uuid, ?::uuid) ON CONFLICT DO NOTHING");
            ps.setString(1, appId);
            ps.setString(2, userId);
            ps.executeUpdate();
        } finally {
            pool.cleanup(null, ps, con);
        }
    }

    public void unassign(String appId, String userId) throws Exception {
        Connection con = null;
        PreparedStatement ps = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("DELETE FROM app_admins WHERE app_id = ?::uuid AND user_id = ?::uuid");
            ps.setString(1, appId);
            ps.setString(2, userId);
            ps.executeUpdate();
        } finally {
            pool.cleanup(null, ps, con);
        }
    }

    public boolean isAssigned(String appId, String userId) throws Exception {
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("SELECT 1 FROM app_admins WHERE app_id = ?::uuid AND user_id = ?::uuid");
            ps.setString(1, appId);
            ps.setString(2, userId);
            rs = ps.executeQuery();
            return rs.next();
        } finally {
            pool.cleanup(rs, ps, con);
        }
    }

    public Set<String> listAppIdsForUser(String userId) throws Exception {
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("SELECT app_id::text AS app_id FROM app_admins WHERE user_id = ?::uuid");
            ps.setString(1, userId);
            rs = ps.executeQuery();
            Set<String> ids = new HashSet<>();
            while (rs.next()) {
                ids.add(rs.getString("app_id"));
            }
            return ids;
        } finally {
            pool.cleanup(rs, ps, con);
        }
    }

    public List<AssignedUser> listUsersForApp(String appId) throws Exception {
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        PoolDB pool = new PoolDB();
        try {
            con = pool.getConnection();
            ps = con.prepareStatement("SELECT u.user_id, u.email, u.full_name FROM app_admins aa " +
                    "JOIN platform_users u ON u.user_id = aa.user_id " +
                    "WHERE aa.app_id = ?::uuid ORDER BY u.full_name");
            ps.setString(1, appId);
            rs = ps.executeQuery();
            List<AssignedUser> users = new ArrayList<>();
            while (rs.next()) {
                users.add(new AssignedUser(rs.getString("user_id"), rs.getString("email"), rs.getString("full_name")));
            }
            return users;
        } finally {
            pool.cleanup(rs, ps, con);
        }
    }
}
