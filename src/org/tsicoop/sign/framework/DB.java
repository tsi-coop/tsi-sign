package org.tsicoop.sign.framework;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * Base class for DB connection holders (TSI framework standard pattern —
 * matches tsi-ledger/tsi-dpdp-cms/tsi-privacy-vault): centralizes the
 * close/cleanup helpers every PoolDB caller invokes in its own finally block.
 */
public abstract class DB {

    protected Connection con;

    public DB() {
    }

    public DB(Connection con) {
        this.con = con;
    }

    public void close(Connection con) {
        try {
            if (con != null) {
                con.close();
            }
        } catch (Exception e) {
        }
    }

    public void close(ResultSet rs) {
        try {
            if (rs != null) {
                rs.close();
            }
        } catch (Exception e) {
        }
    }

    public void close(PreparedStatement pStmt) {
        try {
            if (pStmt != null) {
                pStmt.close();
            }
        } catch (Exception e) {
        }
    }

    public static void close(Statement stmt) {
        try {
            if (stmt != null) {
                stmt.close();
            }
        } catch (Exception e) {
        }
    }

    public void cleanup(ResultSet rs, PreparedStatement pStmt, Connection con) {
        close(rs);
        close(pStmt);
        close(con);
    }

    public void rollback(Connection con) {
        try {
            if (con != null) {
                con.rollback();
            }
        } catch (Exception e) {
        }
    }
}
