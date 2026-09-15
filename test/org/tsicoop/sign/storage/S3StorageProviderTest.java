package org.tsicoop.sign.storage;

import org.junit.Test;
import software.amazon.awssdk.core.ResponseBytes;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectResponse;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectResponse;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * A minimal in-test S3Client stub (S3Client is an interface with default
 * methods that throw UnsupportedOperationException for anything not
 * overridden) - verifies the key convention and error mapping without any
 * new test dependency or live S3/MinIO endpoint.
 */
public class S3StorageProviderTest {

    private static class FakeS3Client implements S3Client {
        final Map<String, byte[]> objects = new HashMap<>();

        @Override
        public String serviceName() {
            return "s3";
        }

        @Override
        public void close() {
        }

        @Override
        public PutObjectResponse putObject(PutObjectRequest request, RequestBody body) {
            try {
                objects.put(request.key(), body.contentStreamProvider().newStream().readAllBytes());
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
            return PutObjectResponse.builder().build();
        }

        @Override
        public ResponseBytes<GetObjectResponse> getObjectAsBytes(GetObjectRequest request) {
            byte[] content = objects.get(request.key());
            if (content == null) {
                throw NoSuchKeyException.builder().message("No such key: " + request.key()).build();
            }
            return ResponseBytes.fromByteArray(GetObjectResponse.builder().build(), content);
        }

        @Override
        public DeleteObjectResponse deleteObject(DeleteObjectRequest request) {
            objects.remove(request.key());
            return DeleteObjectResponse.builder().build();
        }
    }

    @Test
    public void storesAndRetrievesBytesRoundTrip() throws Exception {
        FakeS3Client fake = new FakeS3Client();
        DocumentStorageProvider provider = new S3StorageProvider(fake, "test-bucket", null, null);

        byte[] content = "sample pdf bytes".getBytes(StandardCharsets.UTF_8);
        StorageObjectRef ref = provider.store("demo-app", "doc-123", "original", content);

        assertEquals("s3", ref.providerId());
        assertTrue(ref.storageKey().startsWith("demo-app/"));
        assertTrue(ref.storageKey().endsWith("/doc-123/original.pdf"));

        byte[] retrieved = provider.retrieve(ref);
        assertArrayEquals(content, retrieved);

        provider.delete(ref);
        assertTrue(fake.objects.isEmpty());
    }

    @Test(expected = StorageException.class)
    public void retrieveRejectsMismatchedProvider() throws Exception {
        DocumentStorageProvider provider = new S3StorageProvider(new FakeS3Client(), "test-bucket", null, null);
        provider.retrieve(new StorageObjectRef("local_fs", "whatever", "hash"));
    }

    @Test(expected = StorageException.class)
    public void retrieveMissingKeyThrowsStorageException() throws Exception {
        DocumentStorageProvider provider = new S3StorageProvider(new FakeS3Client(), "test-bucket", null, null);
        provider.retrieve(new StorageObjectRef("s3", "nonexistent/key.pdf", "hash"));
    }
}
