package org.tsicoop.sign.storage;

/**
 * Pluggable document storage backend (§5), keeping the sovereignty pitch —
 * documents never touch an external vendor's cloud storage unless a
 * deployment explicitly chooses that backend. Implementations: local_fs
 * (Chunk 3, Phase 1 default), s3 and privacy_vault (Chunk 12).
 */
public interface DocumentStorageProvider {

    String getProviderId();   // "local_fs", "s3", "privacy_vault"

    /**
     * @param appSlug    the App's slug (apps.app_slug), not its UUID — the
     *                   storage key convention embeds the human-readable
     *                   slug ({app_slug}/{yyyy}/{mm}/{documentId}/{variant}.pdf)
     *                   so keys stay navigable per App and month even on
     *                   backends with no native folder browsing (S3).
     * @param documentId documents.document_id
     * @param variant    "original" (freshly rendered, unsigned PDF) or
     *                   "sealed" (signed/sealed PDF) — kept as two distinct
     *                   objects so the original render can always be
     *                   independently re-hashed and verified against
     *                   documents.original_hash, even long after sealing.
     */
    StorageObjectRef store(String appSlug, String documentId, String variant, byte[] content)
            throws StorageException;

    byte[] retrieve(StorageObjectRef ref) throws StorageException;

    void delete(StorageObjectRef ref) throws StorageException;
}
