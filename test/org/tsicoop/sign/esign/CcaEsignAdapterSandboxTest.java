package org.tsicoop.sign.esign;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.tsicoop.sign.framework.HashUtil;
import org.tsicoop.sign.pki.SignatureTimestamper;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Drives {@link CcaEsignAdapter} against a RUNNING sandbox (sandbox/, `java -jar
 * sandbox/target/tsi_esign_sandbox.jar`) - the full ASP-side protocol round trip, ending in a real
 * PDF whose embedded signature is independently verified. Skipped unless SANDBOX_URL is set:
 * {@code SANDBOX_URL=http://localhost:8090 mvn test -Dtest=CcaEsignAdapterSandboxTest}.
 * Proves protocol mechanics against the sandbox only - not compatibility with any real CA.
 */
public class CcaEsignAdapterSandboxTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private final HttpClient client = HttpClient.newHttpClient();
    private String sandbox;
    private CcaEsignAdapter adapter;
    private Path rootPem;
    private Path aspPem;

    @Before
    public void setUp() throws Exception {
        sandbox = System.getenv("SANDBOX_URL");
        Assume.assumeTrue("SANDBOX_URL not set - skipping sandbox integration test", sandbox != null && !sandbox.isBlank());
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        Path dir = Files.createTempDirectory("esign-it");
        Path root = dir.resolve("root.pem");
        rootPem = root;
        Files.writeString(root, get("/ca/root.pem"));
        Path espPem = dir.resolve("esp.pem");
        Files.writeString(espPem, get("/ca/esp.pem"));

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair pair = kpg.generateKeyPair();
        X500Name name = new X500Name("CN=Test ASP, O=Test, C=IN");
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(new JcaX509v3CertificateBuilder(name,
                BigInteger.ONE, new Date(System.currentTimeMillis() - 60_000), new Date(System.currentTimeMillis() + 3_600_000),
                name, pair.getPublic()).build(new JcaContentSignerBuilder("SHA256withRSA").build(pair.getPrivate())));
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("asp", pair.getPrivate(), "pw".toCharArray(), new java.security.cert.Certificate[]{cert});
        aspPem = dir.resolve("asp.pem");
        Files.writeString(aspPem, "-----BEGIN CERTIFICATE-----\n" + java.util.Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(cert.getEncoded()) + "\n-----END CERTIFICATE-----\n");
        Path p12 = dir.resolve("asp.p12");
        try (FileOutputStream out = new FileOutputStream(p12.toFile())) {
            ks.store(out, "pw".toCharArray());
        }

        adapter = new CcaEsignAdapter(new CcaEsignConfig("sandbox", "Aadhaar eSign (TSI Sandbox)",
                sandbox + "/esign/2.1/form/signdoc", "IT-ASP", "2.1", "1", "asp", p12.toString(), "PKCS12", "pw",
                List.of(root), List.of(espPem), "http://tsi.test"));
    }

    @Test
    public void fullRoundTripProducesAPdfWithAValidIndependentlyVerifiedSignature() throws Exception {
        byte[] pdf = blankPdf();
        ExternalCmsSpliceService splice = new ExternalCmsSpliceService();
        ExternalCmsSpliceService.PreparedSigning prepared = splice.prepare(pdf, "Aadhaar eSign (TSI Sandbox)", "Asha Rao", "IT", null);
        String hash = HashUtil.sha256Hex(prepared.contentToHash());

        SigningSessionResponse session = adapter.initiateSigning(
                new SigningSessionRequest("doc1", "app1", "Asha Rao", null, null, hash, "IT"));
        assertTrue(session.transactionId().startsWith("TSI"));
        assertTrue(session.gatewayUrl().contains("esign-redirect.html"));

        SigningResult result = adapter.processCallback(esp(session, "123456", "ok"), hash);
        assertTrue(result.failureReason(), result.success());
        assertTrue(result.trusted());
        assertEquals(session.transactionId(), result.transactionId());
        assertEquals("Asha Rao", result.signerCommonName());
        assertEquals("AADHAAR_OTP", result.authType());

        byte[] signed = splice.finalizeSignature(prepared.contentToHash(), prepared.byteRange(), result.pkcs7Signature());
        try (PDDocument doc = PDDocument.load(signed)) {
            PDSignature signature = doc.getSignatureDictionaries().get(0);
            CMSSignedData cms = new CMSSignedData(new CMSProcessableByteArray(signature.getSignedContent(signed)),
                    signature.getContents(signed));
            SignerInformation signer = cms.getSignerInfos().getSigners().iterator().next();
            X509CertificateHolder holder = (X509CertificateHolder) cms.getCertificates().getMatches(signer.getSID()).iterator().next();
            assertTrue("PDF signature must verify", signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(holder)));
        }
    }

    @Test
    public void attacksAndFailuresAreClassifiedCorrectly() throws Exception {
        byte[] hashBytes = java.security.MessageDigest.getInstance("SHA-256").digest("content".getBytes());
        String hash = java.util.HexFormat.of().formatHex(hashBytes);

        SigningResult tampered = adapter.processCallback(esp(begin(hash), "123456", "tampered_hash"), hash);
        assertFalse(tampered.success());
        assertFalse("signing a different hash is an untrusted callback", tampered.trusted());

        SigningResult rogue = adapter.processCallback(esp(begin(hash), "123456", "bad_signature"), hash);
        assertFalse(rogue.success());
        assertFalse("a response signed by a cert that merely chains to the CA (not the pinned ESP cert) must be rejected", rogue.trusted());

        SigningResult wrongExpected = adapter.processCallback(esp(begin(hash), "123456", "ok"),
                HashUtil.sha256Hex("something else"));
        assertFalse(wrongExpected.trusted());

        for (String[] c : new String[][]{{"000000", "ok", "ESP-OTP-INVALID"}, {"123456", "deny", "ESP-USER-CANCEL"},
                {"123456", "expired", "ESP-TXN-EXPIRED"}, {"123456", "esp_error", "ESP-500"}}) {
            SigningResult r = adapter.processCallback(esp(begin(hash), c[0], c[1]), hash);
            assertFalse(r.success());
            assertTrue("an authentic CA failure is trusted, so the session can be failed", r.trusted());
            assertTrue(r.failureReason(), r.failureReason().startsWith(c[2]));
        }
    }

    @Test
    public void forgedAndMalformedCallbacksAreNeverTrusted() {
        String hash = HashUtil.sha256Hex("x");
        for (String msg : new String[]{null, "", "not xml", "<EsignResp status=\"0\" txn=\"T\" errCode=\"X\"/>",
                "<!DOCTYPE a [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><EsignResp>&e;</EsignResp>"}) {
            com.fasterxml.jackson.databind.node.ObjectNode payload = MAPPER.createObjectNode();
            if (msg != null) {
                payload.put("msg", msg);
            }
            SigningResult r = adapter.processCallback(payload, hash);
            assertFalse(msg, r.trusted());
            assertFalse(msg, r.success());
        }
    }

    // ---- helpers: play the signer's browser ----

    private SigningSessionResponse begin(String hash) throws Exception {
        return adapter.initiateSigning(new SigningSessionRequest("d", "a", "Asha Rao", null, null, hash, "IT"));
    }

    /** Posts the adapter's signed request to the sandbox, completes consent, returns the {msg} the ESP would POST back. */
    private JsonNode esp(SigningSessionResponse session, String otp, String simulate) throws Exception {
        JsonNode payload = MAPPER.readTree(session.gatewayPayload());
        HttpResponse<String> signdoc = post(payload.path("actionUrl").asText(),
                "msg=" + enc(payload.path("fields").path("msg").asText()));
        assertEquals(signdoc.body(), 200, signdoc.statusCode());
        HttpResponse<String> consent = post(sandbox + "/esign/2.1/consent", "txnKey=" + enc(MAPPER.readTree(signdoc.body()).path("txnKey").asText())
                + "&otp=" + otp + "&simulate=" + simulate + "&signerName=" + enc("Asha Rao"));
        assertEquals(consent.body(), 200, consent.statusCode());
        return MAPPER.createObjectNode().put("msg", MAPPER.readTree(consent.body()).path("msg").asText());
    }

    private HttpResponse<String> post(String url, String form) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create(url)).header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json").POST(HttpRequest.BodyPublishers.ofString(form)).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private String get(String path) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create(sandbox + path)).GET().build(),
                HttpResponse.BodyHandlers.ofString()).body();
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private static byte[] blankPdf() throws Exception {
        try (PDDocument doc = new PDDocument(); ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            doc.addPage(new PDPage());
            doc.save(out);
            return out.toByteArray();
        }
    }

    @Test
    public void timestampedSignatureStillVerifiesAndCarriesATrustedToken() throws Exception {
        byte[] pdf = blankPdf();
        ExternalCmsSpliceService splice = new ExternalCmsSpliceService();
        ExternalCmsSpliceService.PreparedSigning prepared = splice.prepare(pdf, "Aadhaar eSign (TSI Sandbox)", "Asha Rao", "IT", null);
        String hash = HashUtil.sha256Hex(prepared.contentToHash());
        SigningSessionResponse session = adapter.initiateSigning(
                new SigningSessionRequest("doc1", "app1", "Asha Rao", null, null, hash, "IT"));
        SigningResult result = adapter.processCallback(esp(session, "123456", "ok"), hash);

        SignatureTimestamper.Result stamped = new SignatureTimestamper(sandbox + "/tsa", List.of(rootPem), true)
                .apply(result.pkcs7Signature());
        assertEquals("PAdES-B-T", stamped.signatureStandard());
        SignerInformation signerWithToken = new CMSSignedData(stamped.cms()).getSignerInfos().getSigners().iterator().next();
        assertNotNull(signerWithToken.getUnsignedAttributes().get(
                org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_aa_signatureTimeStampToken));

        byte[] signed = splice.finalizeSignature(prepared.contentToHash(), prepared.byteRange(), stamped.cms());
        try (PDDocument doc = PDDocument.load(signed)) {
            PDSignature signature = doc.getSignatureDictionaries().get(0);
            CMSSignedData cms = new CMSSignedData(new CMSProcessableByteArray(signature.getSignedContent(signed)),
                    signature.getContents(signed));
            SignerInformation signer = cms.getSignerInfos().getSigners().iterator().next();
            X509CertificateHolder holder = (X509CertificateHolder) cms.getCertificates().getMatches(signer.getSID()).iterator().next();
            assertTrue(signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(holder)));
        }
    }

    @Test
    public void untrustedTsaFailsClosedWhenRequiredAndDegradesToBBOtherwise() throws Exception {
        byte[] cms = adapterCms();
        try {
            new SignatureTimestamper(sandbox + "/tsa", List.of(aspPem), true).apply(cms); // wrong trust anchor
            throw new AssertionError("Expected failure with TSA_REQUIRED");
        } catch (Exception e) {
            assertTrue(e.getMessage(), e.getMessage().contains("TSA_REQUIRED"));
        }
        assertEquals("PAdES-B-B", new SignatureTimestamper(sandbox + "/tsa", List.of(aspPem), false).apply(cms).signatureStandard());
        assertEquals("PAdES-B-B", new SignatureTimestamper("http://localhost:1/tsa", List.of(rootPem), false).apply(cms).signatureStandard());
        assertEquals("PAdES-B-B", new SignatureTimestamper(null, List.of(), false).apply(cms).signatureStandard());
    }

    private byte[] adapterCms() throws Exception {
        String hash = HashUtil.sha256Hex("abc");
        return adapter.processCallback(esp(begin(hash), "123456", "ok"), hash).pkcs7Signature();
    }
}
