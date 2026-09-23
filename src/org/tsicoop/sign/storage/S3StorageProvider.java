package org.tsicoop.sign.storage;

import org.tsicoop.sign.framework.HashUtil;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3ClientBuilder;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.ServerSideEncryption;

import java.net.URI;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

/**
 * S3-compatible DocumentStorageProvider (Chunk 12, §5.1) — one AWS SDK v2
 * client, config-driven so it covers AWS S3 *and* a self-hosted
 * S3-compatible store (MinIO, Ceph RGW, Cloudflare R2) with the same code
 * path: endpoint URL + path-style addressing are config, not a second
 * provider class (see docs/architecture.md §5, "one S3
 * driver, not two").
 */
public class S3StorageProvider implements DocumentStorageProvider {

    public static final String PROVIDER_ID = "s3";

    private static final DateTimeFormatter YEAR = DateTimeFormatter.ofPattern("yyyy");
    private static final DateTimeFormatter MONTH = DateTimeFormatter.ofPattern("MM");

    private final S3Client client;
    private final String bucket;
    private final ServerSideEncryption sse;
    private final String kmsKeyId;

    S3StorageProvider(S3Client client, String bucket, ServerSideEncryption sse, String kmsKeyId) {
        this.client = client;
        this.bucket = bucket;
        this.sse = sse;
        this.kmsKeyId = kmsKeyId;
    }

    /**
     * Builds the AWS SDK v2 client from already-resolved config (System
     * Settings DB row, falling back per-field to S3_* env vars - see
     * StorageProviderRegistry, which is the only caller). endpoint/
     * accessKey/secretKey/kmsKeyId are optional; region and bucket are not.
     */
    public static S3StorageProvider create(String endpoint, String region, String bucket, String accessKey,
            String secretKey, boolean pathStyleAccess, String sse, String kmsKeyId) {
        S3ClientBuilder builder = S3Client.builder().region(Region.of(region));
        if (endpoint != null && !endpoint.isBlank()) {
            builder.endpointOverride(URI.create(endpoint));
        }
        if (pathStyleAccess) {
            builder.forcePathStyle(true);
        }
        if (accessKey != null && secretKey != null) {
            builder.credentialsProvider(
                    StaticCredentialsProvider.create(AwsBasicCredentials.create(accessKey, secretKey)));
        }
        // Otherwise falls back to the SDK's default credential chain (env/profile/IAM role).

        ServerSideEncryption sseEnum = sse == null || sse.isBlank() || "NONE".equalsIgnoreCase(sse)
                ? null : ServerSideEncryption.fromValue(sse);

        return new S3StorageProvider(builder.build(), bucket, sseEnum, kmsKeyId);
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

        try {
            PutObjectRequest.Builder request = PutObjectRequest.builder()
                    .bucket(bucket)
                    .key(storageKey)
                    .contentType("application/pdf");
            if (sse != null) {
                request.serverSideEncryption(sse);
                if (sse == ServerSideEncryption.AWS_KMS && kmsKeyId != null) {
                    request.ssekmsKeyId(kmsKeyId);
                }
            }
            client.putObject(request.build(), RequestBody.fromBytes(content));
        } catch (SdkException e) {
            throw new StorageException("Failed to write document to S3: " + storageKey, e);
        }

        return new StorageObjectRef(PROVIDER_ID, storageKey, HashUtil.sha256Hex(content));
    }

    @Override
    public byte[] retrieve(StorageObjectRef ref) throws StorageException {
        requireOwnProvider(ref);
        try {
            return client.getObjectAsBytes(GetObjectRequest.builder()
                    .bucket(bucket)
                    .key(ref.storageKey())
                    .build()).asByteArray();
        } catch (SdkException e) {
            throw new StorageException("Failed to read document from S3: " + ref.storageKey(), e);
        }
    }

    @Override
    public void delete(StorageObjectRef ref) throws StorageException {
        requireOwnProvider(ref);
        try {
            client.deleteObject(DeleteObjectRequest.builder()
                    .bucket(bucket)
                    .key(ref.storageKey())
                    .build());
        } catch (SdkException e) {
            throw new StorageException("Failed to delete document from S3: " + ref.storageKey(), e);
        }
    }

    private void requireOwnProvider(StorageObjectRef ref) throws StorageException {
        if (!PROVIDER_ID.equals(ref.providerId())) {
            throw new StorageException("StorageObjectRef belongs to provider '" + ref.providerId()
                    + "', not '" + PROVIDER_ID + "'");
        }
    }
}
