package org.tsicoop.sign.storage;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class StorageProviderRegistryTest {

    @Test
    public void resolvesLocalFilesystemByDefault() throws Exception {
        DocumentStorageProvider provider = StorageProviderRegistry.resolve(LocalFilesystemStorageProvider.PROVIDER_ID);
        assertEquals("local_fs", provider.getProviderId());
    }

    @Test
    public void unknownProviderIdThrowsClearStorageExceptionWithoutTouchingSystemSettings() {
        // A bogus providerId is rejected before ever loading System Settings (the s3/privacy_vault
        // paths do need a live DB - covered by the docker-compose end-to-end verification instead).
        try {
            StorageProviderRegistry.resolve("nonexistent_provider");
        } catch (StorageException e) {
            assertTrue(e.getMessage().contains("nonexistent_provider"));
            return;
        }
        throw new AssertionError("Expected a StorageException");
    }
}
