package org.tsicoop.sign.sandbox;

import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.HexFormat;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class SandboxServerTest {

    private MockCa ca;
    private SandboxServer server;
    private String base;
    private KeyPair aspPair;
    private X509Certificate aspCert;
    private final HttpClient client = HttpClient.newHttpClient();

    @Before
    public void start() throws Exception {
        ca = MockCa.loadOrCreate(null);
        aspPair = MockCa.newKeyPair();
        aspCert = ca.issueSigner("Test ASP", aspPair.getPublic(), new Date(), new Date(System.currentTimeMillis() + 3_600_000));
        startServer(false);
    }

    private void startServer(boolean strict) throws Exception {
        if (server != null) {
            server.stop();
        }
        server = new SandboxServer(ca, strict, 600);
        server.start(0);
        base = "http://localhost:" + server.port();
    }

    @After
    public void stop() {
        server.stop();
    }

    private String signedRequest(String txn, byte[] docHash) throws Exception {
        Document doc = Dsig.parse("<Esign ver=\"2.1\" sc=\"Y\" ts=\"2026-01-01T00:00:00\" txn=\"" + txn + "\" ekycId=\"\" "
                + "ekycIdType=\"A\" aspId=\"TEST-ASP\" AuthMode=\"1\" responseSigType=\"pkcs7\" "
                + "responseUrl=\"http://localhost:1/return\"><Docs><InputHash id=\"1\" hashAlgorithm=\"SHA256\" "
                + "docInfo=\"TSI Sign | signer: Asha Rao\">" + HexFormat.of().formatHex(docHash) + "</InputHash></Docs></Esign>");
        Dsig.sign(doc, aspPair.getPrivate(), aspCert);
        return Dsig.serialize(doc);
    }

    private HttpResponse<String> post(String path, String formBody) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create(base + path))
                .header("Content-Type", "application/x-www-form-urlencoded").header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(formBody)).build(), HttpResponse.BodyHandlers.ofString());
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private static String jsonField(String json, String name) {
        String marker = "\"" + name + "\":\"";
        int start = json.indexOf(marker);
        assertTrue("missing " + name + " in " + json, start >= 0);
        StringBuilder out = new StringBuilder();
        for (int i = start + marker.length(); i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '\\') {
                char n = json.charAt(++i);
                out.append(n == 'n' ? '\n' : n == 'r' ? '\r' : n);
            } else if (c == '"') {
                break;
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }

    private String consent(String requestXml, String otp, String simulate) throws Exception {
        HttpResponse<String> signdoc = post("/esign/2.1/form/signdoc", "msg=" + enc(requestXml));
        assertEquals(signdoc.body(), 200, signdoc.statusCode());
        HttpResponse<String> consent = post("/esign/2.1/consent", "txnKey=" + enc(jsonField(signdoc.body(), "txnKey"))
                + "&otp=" + otp + "&simulate=" + simulate + "&signerName=" + enc("Asha Rao"));
        assertEquals(consent.body(), 200, consent.statusCode());
        return jsonField(consent.body(), "msg");
    }

    @Test
    public void happyPathReturnsSignedResponseWhoseCmsSignsExactlyTheRequestedHash() throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest("the pdf byte range".getBytes());
        String msg = consent(signedRequest("T1", hash), "123456", "ok");

        Document resp = Dsig.parse(msg);
        Element root = resp.getDocumentElement();
        assertEquals("1", root.getAttribute("status"));
        assertEquals("T1", root.getAttribute("txn"));
        X509Certificate responseSigner = Dsig.verifyAndGetSigner(resp);
        assertNotNull(responseSigner);
        assertArrayEquals(ca.espCert.getEncoded(), responseSigner.getEncoded());

        byte[] cmsBytes = Base64.getDecoder().decode(resp.getElementsByTagName("DocSignature").item(0).getTextContent());
        CMSSignedData cms = new CMSSignedData(cmsBytes);
        SignerInformation signer = cms.getSignerInfos().getSigners().iterator().next();
        Attribute digest = signer.getSignedAttributes().get(CMSAttributes.messageDigest);
        assertArrayEquals(hash, ((org.bouncycastle.asn1.ASN1OctetString) digest.getAttrValues().getObjectAt(0)).getOctets());

        X509Certificate userCert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                new ByteArrayInputStream(Base64.getDecoder().decode(resp.getElementsByTagName("UserX509Certificate").item(0).getTextContent())));
        assertTrue(userCert.getSubjectX500Principal().getName().contains("CN=Asha Rao"));
        userCert.verify(ca.rootCert.getPublicKey());
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(userCert);
        verifier.update(signer.getEncodedSignedAttributes());
        assertTrue(verifier.verify(signer.getSignature()));
    }

    @Test
    public void requestTamperedAfterSigningIsRejected() throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest("x".getBytes());
        byte[] other = MessageDigest.getInstance("SHA-256").digest("y".getBytes());
        String tampered = signedRequest("T2", hash).replace(HexFormat.of().formatHex(hash), HexFormat.of().formatHex(other));
        HttpResponse<String> r = post("/esign/2.1/form/signdoc", "msg=" + enc(tampered));
        assertEquals(400, r.statusCode());
        assertEquals("ESP-104", jsonField(r.body(), "errCode"));
    }

    @Test
    public void strictModeRejectsUnregisteredAspAndAcceptsRegisteredOne() throws Exception {
        startServer(true);
        byte[] hash = MessageDigest.getInstance("SHA-256").digest("x".getBytes());
        HttpResponse<String> r = post("/esign/2.1/form/signdoc", "msg=" + enc(signedRequest("T3", hash)));
        assertEquals("ESP-105", jsonField(r.body(), "errCode"));
        server.registerAsp("TEST-ASP", aspCert);
        assertEquals(200, post("/esign/2.1/form/signdoc", "msg=" + enc(signedRequest("T4", hash))).statusCode());
    }

    @Test
    public void failureModesReturnSignedErrorResponses() throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest("x".getBytes());
        Object[][] cases = {{"000000", "ok", "ESP-OTP-INVALID"}, {"123456", "deny", "ESP-USER-CANCEL"},
                {"123456", "expired", "ESP-TXN-EXPIRED"}, {"123456", "esp_error", "ESP-500"}};
        int i = 0;
        for (Object[] c : cases) {
            Document resp = Dsig.parse(consent(signedRequest("F" + i++, hash), (String) c[0], (String) c[1]));
            assertEquals("0", resp.getDocumentElement().getAttribute("status"));
            assertEquals(c[2], resp.getDocumentElement().getAttribute("errCode"));
            assertNotNull(Dsig.verifyAndGetSigner(resp));
        }
    }

    @Test
    public void attackSimulationsAreDetectableByAnAdapter() throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest("x".getBytes());
        Document tampered = Dsig.parse(consent(signedRequest("A1", hash), "123456", "tampered_hash"));
        byte[] cmsBytes = Base64.getDecoder().decode(tampered.getElementsByTagName("DocSignature").item(0).getTextContent());
        Attribute digest = new CMSSignedData(cmsBytes).getSignerInfos().getSigners().iterator().next()
                .getSignedAttributes().get(CMSAttributes.messageDigest);
        byte[] signed = ((org.bouncycastle.asn1.ASN1OctetString) digest.getAttrValues().getObjectAt(0)).getOctets();
        assertTrue("tampered_hash must not sign the requested hash", !java.util.Arrays.equals(hash, signed));

        Document rogue = Dsig.parse(consent(signedRequest("A2", hash), "123456", "bad_signature"));
        X509Certificate signer = Dsig.verifyAndGetSigner(rogue);
        assertNotNull("XML-DSig itself is valid", signer);
        assertTrue("but the signer is not the ESP cert", !java.util.Arrays.equals(signer.getEncoded(), ca.espCert.getEncoded()));
    }

    @Test
    public void replayedTransactionAndDuplicateTxnAreRejected() throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest("x".getBytes());
        String req = signedRequest("R1", hash);
        HttpResponse<String> first = post("/esign/2.1/form/signdoc", "msg=" + enc(req));
        assertEquals(200, first.statusCode());
        assertEquals("ESP-109", jsonField(post("/esign/2.1/form/signdoc", "msg=" + enc(req)).body(), "errCode"));
        String key = enc(jsonField(first.body(), "txnKey"));
        assertEquals(200, post("/esign/2.1/consent", "txnKey=" + key + "&otp=123456&simulate=ok").statusCode());
        assertEquals("ESP-110", jsonField(post("/esign/2.1/consent", "txnKey=" + key + "&otp=123456&simulate=ok").body(), "errCode"));
    }

    @Test
    public void timestampAuthorityIssuesAVerifiableToken() throws Exception {
        org.bouncycastle.tsp.TimeStampRequestGenerator generator = new org.bouncycastle.tsp.TimeStampRequestGenerator();
        generator.setCertReq(true);
        byte[] digest = MessageDigest.getInstance("SHA-256").digest("sig".getBytes());
        org.bouncycastle.tsp.TimeStampRequest request = generator.generate(org.bouncycastle.tsp.TSPAlgorithms.SHA256, digest);
        HttpResponse<byte[]> r = client.send(HttpRequest.newBuilder(URI.create(base + "/tsa"))
                .header("Content-Type", "application/timestamp-query")
                .POST(HttpRequest.BodyPublishers.ofByteArray(request.getEncoded())).build(), HttpResponse.BodyHandlers.ofByteArray());
        org.bouncycastle.tsp.TimeStampResponse response = new org.bouncycastle.tsp.TimeStampResponse(r.body());
        response.validate(request);
        assertNull(response.getFailInfo());
        assertEquals(0, response.getStatus());
    }
}
