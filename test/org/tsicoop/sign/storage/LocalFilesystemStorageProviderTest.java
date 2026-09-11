package org.tsicoop.sign.storage;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class LocalFilesystemStorageProviderTest {

    @Test
    public void storesAndRetrievesBytesRoundTrip() throws Exception {
        Path tempDir = Files.createTempDirectory("tsi-sign-storage-test");
        DocumentStorageProvider provider = new LocalFilesystemStorageProvider(tempDir.toString());

        byte[] content = "sample pdf bytes".getBytes(StandardCharsets.UTF_8);
        StorageObjectRef ref = provider.store("demo-app", "doc-123", "original", content);

        assertEquals("local_fs", ref.providerId());
        assertTrue(ref.storageKey().startsWith("demo-app/"));
        assertTrue(ref.storageKey().endsWith("/doc-123/original.pdf"));

        byte[] retrieved = provider.retrieve(ref);
        assertArrayEquals(content, retrieved);

        provider.delete(ref);
        assertFalse(Files.exists(tempDir.resolve(ref.storageKey())));
    }

    @Test(expected = StorageException.class)
    public void retrieveRejectsMismatchedProvider() throws Exception {
        Path tempDir = Files.createTempDirectory("tsi-sign-storage-test");
        DocumentStorageProvider provider = new LocalFilesystemStorageProvider(tempDir.toString());
        provider.retrieve(new StorageObjectRef("s3", "whatever", "hash"));
    }

    @Test(expected = StorageException.class)
    public void rejectsStorageKeysThatEscapeTheMountPath() throws Exception {
        Path tempDir = Files.createTempDirectory("tsi-sign-storage-test");
        DocumentStorageProvider provider = new LocalFilesystemStorageProvider(tempDir.toString());
        provider.store("../../etc", "doc-123", "original", "x".getBytes(StandardCharsets.UTF_8));
    }
}
