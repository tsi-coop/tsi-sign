package org.tsicoop.sign.storage;

import org.tsicoop.sign.framework.HashUtil;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Phase 1 default storage backend (§5.1): writes to a mounted local
 * directory (e.g. a Docker volume such as /data/tsi-sign/documents). Zero
 * external dependency, simplest to reason about, backup = disk/volume
 * snapshot. Doesn't scale across multiple app instances without a
 * shared/NFS mount — see the s3 provider (Chunk 12) for that case.
 */
public class LocalFilesystemStorageProvider implements DocumentStorageProvider {

    public static final String PROVIDER_ID = "local_fs";
    private static final String DEFAULT_MOUNT_PATH = "/data/tsi-sign/documents";

    private static final DateTimeFormatter YEAR = DateTimeFormatter.ofPattern("yyyy");
    private static final DateTimeFormatter MONTH = DateTimeFormatter.ofPattern("MM");

    private final Path baseDir;

    /** Reads the mount path from STORAGE_LOCAL_FS_PATH (see docker-compose.yml / .env.example). */
    public LocalFilesystemStorageProvider() {
        this(System.getenv("STORAGE_LOCAL_FS_PATH") != null
                ? System.getenv("STORAGE_LOCAL_FS_PATH")
                : DEFAULT_MOUNT_PATH);
    }

    public LocalFilesystemStorageProvider(String mountPath) {
        this.baseDir = Paths.get(mountPath);
    }

    @Override
    public String getProviderId() {
        return PROVIDER_ID;
    }

    @Override
    public StorageObjectRef store(String appSlug, String documentId, String variant, byte[] content)
            throws StorageException {
        ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);
        String storageKey = String.join("/",
                appSlug, YEAR.format(now), MONTH.format(now), documentId, variant + ".pdf");

        Path target = resolveWithinBase(storageKey);

        try {
            Files.createDirectories(target.getParent());
            Path tmp = Files.createTempFile(target.getParent(), "upload-", ".tmp");
            Files.write(tmp, content);
            Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            throw new StorageException("Failed to write document to local filesystem: " + storageKey, e);
        }

        return new StorageObjectRef(PROVIDER_ID, storageKey, HashUtil.sha256Hex(content));
    }

    @Override
    public byte[] retrieve(StorageObjectRef ref) throws StorageException {
        requireOwnProvider(ref);
        try {
            return Files.readAllBytes(resolveWithinBase(ref.storageKey()));
        } catch (IOException e) {
            throw new StorageException("Failed to read document from local filesystem: " + ref.storageKey(), e);
        }
    }

    @Override
    public void delete(StorageObjectRef ref) throws StorageException {
        requireOwnProvider(ref);
        try {
            Files.deleteIfExists(resolveWithinBase(ref.storageKey()));
        } catch (IOException e) {
            throw new StorageException("Failed to delete document from local filesystem: " + ref.storageKey(), e);
        }
    }

    private Path resolveWithinBase(String storageKey) throws StorageException {
        Path normalizedBase = baseDir.normalize();
        Path target = normalizedBase.resolve(storageKey).normalize();
        if (!target.startsWith(normalizedBase)) {
            throw new StorageException("Resolved storage path escapes the configured mount path: " + storageKey);
        }
        return target;
    }

    private void requireOwnProvider(StorageObjectRef ref) throws StorageException {
        if (!PROVIDER_ID.equals(ref.providerId())) {
            throw new StorageException("StorageObjectRef belongs to provider '" + ref.providerId()
                    + "', not '" + PROVIDER_ID + "'");
        }
    }
}
