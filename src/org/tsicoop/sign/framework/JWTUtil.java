package org.tsicoop.sign.framework;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Console-session JWTs (§10) - matches tsi-compass's JWTUtil so the admin
 * console session survives a server restart: the token itself carries
 * userId/email/fullName/role (self-contained, stateless) instead of a
 * plain in-memory HttpSession, which is lost the moment the JVM restarts.
 * Revocation (logout) is handled by TokenBlocklist, keyed on the token's
 * jti - the same tradeoff tsi-compass accepts: the blocklist is itself
 * in-memory, so a revoked token issued before a restart becomes valid
 * again until it naturally expires. Acceptable here for the same reason
 * it's acceptable there - a DB-backed revocation table is the next step
 * if that gap ever matters in practice.
 */
public final class JWTUtil {

    private static final long EXPIRATION_MS = 864_000_000L; // 10 days, matches tsi-compass
    private static volatile Key secretKey;

    private JWTUtil() {
    }

    private static Key secretKey() {
        Key key = secretKey;
        if (key == null) {
            synchronized (JWTUtil.class) {
                key = secretKey;
                if (key == null) {
                    String secret = System.getenv("JWT_SECRET");
                    if (secret == null || secret.isBlank()) {
                        throw new IllegalStateException("JWT_SECRET environment variable must be set");
                    }
                    key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
                    secretKey = key;
                }
            }
        }
        return key;
    }

    public static String generateToken(String userId, String email, String fullName, String role) {
        Map<String, String> claims = new HashMap<>();
        claims.put("email", email);
        claims.put("name", fullName);
        claims.put("role", role);
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userId)
                .setId(UUID.randomUUID().toString())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_MS))
                .signWith(secretKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    /** False for missing/expired/tampered/revoked tokens - never throws. */
    public static boolean isTokenValid(String token) {
        if (token == null || token.isBlank()) return false;
        try {
            Claims claims = parseClaims(token);
            String jti = claims.getId();
            return jti == null || !TokenBlocklist.isRevoked(jti);
        } catch (Exception e) {
            return false;
        }
    }

    public static String getUserIdFromToken(String token) {
        return parseClaims(token).getSubject();
    }

    public static String getEmailFromToken(String token) {
        return (String) parseClaims(token).get("email");
    }

    public static String getNameFromToken(String token) {
        return (String) parseClaims(token).get("name");
    }

    public static String getRoleFromToken(String token) {
        return (String) parseClaims(token).get("role");
    }

    public static String getJtiFromToken(String token) {
        return parseClaims(token).getId();
    }

    public static Date getExpiryFromToken(String token) {
        return parseClaims(token).getExpiration();
    }

    private static Claims parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey()).build()
                .parseClaimsJws(token).getBody();
    }
}
