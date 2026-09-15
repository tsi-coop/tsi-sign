package org.tsicoop.sign.storage;

import com.sun.net.httpserver.HttpServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

/**
 * Fakes Privacy Vault's single {@code POST /api/client/vault} endpoint with
 * the JDK's built-in HttpServer (no new test dependency) - verified against
 * the actual shipped API (org.tsicoop.privacyvault.api.client.Vault):
 * store_data returns {success, reference_key}, fetch_data returns
 * {success, value, flavor, fileName}, and there is no delete/remove _func.
 */
public class PrivacyVaultStorageProviderTest {

    private HttpServer server;
    private String baseUrl;
    private final java.util.Map<String, String> store = new java.util.HashMap<>();

    @Before
    public void startFakeVault() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/client/vault", exchange -> {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String response;
            if (body.contains("\"store_data\"")) {
                String key = "ref-" + (store.size() + 1);
                String content = extractField(body, "content");
                store.put(key, content);
                response = "{\"success\":true,\"reference_key\":\"" + key + "\"}";
            } else if (body.contains("\"fetch_data\"")) {
                String key = extractField(body, "reference-key");
                String content = store.get(key);
                response = content != null
                        ? "{\"success\":true,\"value\":\"" + content + "\",\"flavor\":\"FILE\"}"
                        : "{\"success\":false}";
            } else {
                response = "{\"success\":false}";
            }
            byte[] out = response.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, out.length);
            exchange.getResponseBody().write(out);
            exchange.close();
        });
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @After
    public void stopFakeVault() {
        server.stop(0);
    }

    private static String extractField(String json, String field) {
        String marker = "\"" + field + "\":\"";
        int start = json.indexOf(marker);
        if (start < 0) return null;
        start += marker.length();
        int end = json.indexOf('"', start);
        return json.substring(start, end);
    }

    @Test
    public void storesAndRetrievesBytesRoundTrip() throws Exception {
        DocumentStorageProvider provider = new PrivacyVaultStorageProvider(baseUrl, "test-api-key", "FILE_ENTITY");

        byte[] content = "sample pdf bytes".getBytes(StandardCharsets.UTF_8);
        StorageObjectRef ref = provider.store("demo-app", "doc-123", "original", content);

        assertEquals("privacy_vault", ref.providerId());

        byte[] retrieved = provider.retrieve(ref);
        assertArrayEquals(content, retrieved);
    }

    @Test(expected = StorageException.class)
    public void deleteIsNotSupported() throws Exception {
        DocumentStorageProvider provider = new PrivacyVaultStorageProvider(baseUrl, "test-api-key", "FILE_ENTITY");
        provider.delete(new StorageObjectRef("privacy_vault", "ref-1", "hash"));
    }

    @Test(expected = StorageException.class)
    public void retrieveRejectsMismatchedProvider() throws Exception {
        DocumentStorageProvider provider = new PrivacyVaultStorageProvider(baseUrl, "test-api-key", "FILE_ENTITY");
        provider.retrieve(new StorageObjectRef("s3", "whatever", "hash"));
    }
}
