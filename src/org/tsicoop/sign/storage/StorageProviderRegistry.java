package org.tsicoop.sign.storage;

import org.tsicoop.sign.service.v1.SystemSettingsRepository;

/**
 * Resolves a providerId to a configured DocumentStorageProvider instance
 * (Chunk 12, §5.2). Config comes from the system_settings DB row (the
 * System Settings console screen) with a per-field fallback to the
 * equivalent env var - a fresh deployment that never touches that screen
 * keeps working purely off env vars, and an operator can override any field
 * live from the console without a redeploy. Providers are built fresh on
 * every call rather than cached, since settings can change at any time and
 * construction is cheap (an S3Client/HttpClient, not a network round trip).
 *
 * <p>Two different resolution rules matter here, deliberately kept separate:
 * <ul>
 *   <li>{@link #resolve(String)} - for an *existing* document, always keyed
 *   by the providerId denormalized on that row (documents.storage_provider_id)
 *   at write time. Never "whichever backend is the deployment default right
 *   now" - switching a deployment's default must never strand documents
 *   written under the old one.</li>
 *   <li>{@link #resolveForWrite(String)} - for a *new* write, the caller's
 *   own storage_provider_id override (an App's apps.storage_provider_id) if
 *   set, else the deployment-wide default.</li>
 * </ul>
 */
public class StorageProviderRegistry {

    /**
     * local_fs needs no config at all, so it's resolved without ever
     * touching System Settings/the DB - only s3/privacy_vault load settings,
     * and only when actually asked for.
     */
    public static DocumentStorageProvider resolve(String providerId) throws StorageException {
        return switch (providerId) {
            case LocalFilesystemStorageProvider.PROVIDER_ID -> new LocalFilesystemStorageProvider();
            case S3StorageProvider.PROVIDER_ID -> buildS3(loadSettings());
            case PrivacyVaultStorageProvider.PROVIDER_ID -> buildPrivacyVault(loadSettings());
            default -> throw new StorageException(
                    "No storage provider configured for providerId '" + providerId + "' on this deployment.");
        };
    }

    /** Per-App override (nullable) if set, else the deployment-wide default - use when writing a *new* document. */
    public static DocumentStorageProvider resolveForWrite(String appStorageProviderIdOverride) throws StorageException {
        if (appStorageProviderIdOverride != null && !appStorageProviderIdOverride.isBlank()) {
            return resolve(appStorageProviderIdOverride);
        }
        return resolve(deploymentDefaultProviderId(loadSettings()));
    }

    private static SystemSettingsRepository.SystemSettingsRecord loadSettings() throws StorageException {
        try {
            return new SystemSettingsRepository().get();
        } catch (Exception e) {
            throw new StorageException("Failed to load System Settings", e);
        }
    }

    private static String deploymentDefaultProviderId(SystemSettingsRepository.SystemSettingsRecord settings) {
        String value = firstNonBlank(settings.defaultStorageProviderId(), System.getenv("DEFAULT_STORAGE_PROVIDER_ID"));
        return value != null ? value : LocalFilesystemStorageProvider.PROVIDER_ID;
    }

    private static DocumentStorageProvider buildS3(SystemSettingsRepository.SystemSettingsRecord settings)
            throws StorageException {
        String region = firstNonBlank(settings.s3Region(), System.getenv("S3_REGION"));
        String bucket = firstNonBlank(settings.s3Bucket(), System.getenv("S3_BUCKET"));
        if (region == null || bucket == null) {
            throw new StorageException("s3 storage provider is not configured on this deployment - " +
                    "set S3 Region/Bucket in System Settings or the S3_REGION/S3_BUCKET env vars.");
        }
        String endpoint = firstNonBlank(settings.s3Endpoint(), System.getenv("S3_ENDPOINT"));
        String accessKey = firstNonBlank(settings.s3AccessKey(), System.getenv("S3_ACCESS_KEY"));
        String secretKey = firstNonBlank(settings.s3SecretKey(), System.getenv("S3_SECRET_KEY"));
        boolean pathStyle = settings.s3PathStyleAccess() != null
                ? settings.s3PathStyleAccess()
                : "true".equalsIgnoreCase(System.getenv("S3_PATH_STYLE_ACCESS"));
        String sse = firstNonBlank(settings.s3Sse(), System.getenv("S3_SSE"));
        String kmsKeyId = firstNonBlank(settings.s3KmsKeyId(), System.getenv("S3_KMS_KEY_ID"));

        return S3StorageProvider.create(endpoint, region, bucket, accessKey, secretKey, pathStyle, sse, kmsKeyId);
    }

    private static DocumentStorageProvider buildPrivacyVault(SystemSettingsRepository.SystemSettingsRecord settings)
            throws StorageException {
        String baseUrl = firstNonBlank(settings.privacyVaultBaseUrl(), System.getenv("PRIVACY_VAULT_BASE_URL"));
        String apiKey = firstNonBlank(settings.privacyVaultApiKey(), System.getenv("PRIVACY_VAULT_API_KEY"));
        String entityCode = firstNonBlank(settings.privacyVaultEntityCode(), System.getenv("PRIVACY_VAULT_ENTITY_CODE"));
        if (baseUrl == null || apiKey == null || entityCode == null) {
            throw new StorageException("privacy_vault storage provider is not configured on this deployment - " +
                    "set Base URL/API Key/Entity Code in System Settings or the PRIVACY_VAULT_* env vars.");
        }
        return new PrivacyVaultStorageProvider(baseUrl, apiKey, entityCode);
    }

    private static String firstNonBlank(String dbValue, String envValue) {
        if (dbValue != null && !dbValue.isBlank()) {
            return dbValue;
        }
        return envValue != null && !envValue.isBlank() ? envValue : null;
    }

    private StorageProviderRegistry() {
    }
}
