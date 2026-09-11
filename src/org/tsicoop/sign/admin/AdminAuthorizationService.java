package org.tsicoop.sign.admin;

/**
 * Role-based gating per the §10.9 visibility matrix (Chunk 9). Certifying
 * officer sub-conditions on Legal Evidence generation are not enforced here
 * — that designation mechanism doesn't exist yet (§10.5, a later chunk).
 */
public class AdminAuthorizationService {

    private final AppAdminRepository appAdminRepository = new AppAdminRepository();

    public boolean canCreateApp(String role) {
        return "PLATFORM_ADMIN".equals(role);
    }

    public boolean canManagePlatformUsers(String role) {
        return "PLATFORM_ADMIN".equals(role);
    }

    /** Read access to one App's templates/documents/keys/legal evidence. AUDITOR is read-only, all Apps. */
    public boolean canRead(String role, String userId, String appId) throws Exception {
        if ("PLATFORM_ADMIN".equals(role) || "AUDITOR".equals(role)) {
            return true;
        }
        if ("APP_MANAGER".equals(role)) {
            return appAdminRepository.isAssigned(appId, userId);
        }
        return false;
    }

    /** Write access: issue/revoke keys, create/edit templates, signing defaults, generate legal certs. */
    public boolean canWrite(String role, String userId, String appId) throws Exception {
        if ("PLATFORM_ADMIN".equals(role)) {
            return true;
        }
        if ("APP_MANAGER".equals(role)) {
            return appAdminRepository.isAssigned(appId, userId);
        }
        return false;
    }
}
