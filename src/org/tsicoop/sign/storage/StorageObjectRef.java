package org.tsicoop.sign.storage;

public record StorageObjectRef(
        String providerId,
        String storageKey,
        String sha256Checksum
) {
}
