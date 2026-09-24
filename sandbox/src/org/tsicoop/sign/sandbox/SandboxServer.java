package org.tsicoop.sign.sandbox;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.io.ByteArrayInputStream;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * TSI eSign Sandbox - a mock CCA-licensed eSign Service Provider (with its own CA) speaking the
 * CCA eSign API 2.1 shape, for developing/testing ASP-side adapters without a real CA contract.
 * NOT a conformance suite and NOT for production: it validates the protocol mechanics
 * (signed request in, hash-only, signed response out) but not any real CA's quirks.
 *
 * <pre>
 *   POST /esign/2.1/form/signdoc   msg=&lt;signed Esign XML&gt;   -> consent page (or JSON if Accept: application/json)
 *   POST /esign/2.1/consent        txn, otp, signerName, simulate -> auto-post page to responseUrl (or JSON)
 *   POST /admin/asps               aspId, certPem (strict mode only)
 *   POST /tsa                      RFC 3161 request               -> RFC 3161 response
 *   GET  /ca/root.pem  /ca/esp.pem  /health
 * </pre>
 * Config (env): PORT (8091), SANDBOX_CA_DIR (persist CA; else in-memory), SANDBOX_STRICT_ASP (true: only
 * registered ASPs; default false: any ASP whose request signature is internally valid),
 * SANDBOX_TXN_TTL_SECONDS (600). OTP 123456 succeeds; the consent page's "simulate" selector drives failure modes.
 */
public class SandboxServer {

    static final String VALID_OTP = "123456";
    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss").withZone(ZoneId.of("Asia/Kolkata"));
    private static final Pattern HEX64 = Pattern.compile("^[0-9a-fA-F]{64}$");

    record Txn(String aspId, String txn, String hashHex, String docInfo, String responseUrl, Instant created) {
    }

    private final MockCa ca;
    private final boolean strictAsp;
    private final long txnTtlSeconds;
    private final Map<String, X509Certificate> registeredAsps = new ConcurrentHashMap<>();
    private final Map<String, Txn> transactions = new ConcurrentHashMap<>();
    private HttpServer http;

    public SandboxServer(MockCa ca, boolean strictAsp, long txnTtlSeconds) {
        this.ca = ca;
        this.strictAsp = strictAsp;
        this.txnTtlSeconds = txnTtlSeconds;
    }

    public static void main(String[] args) throws Exception {
        String dir = System.getenv("SANDBOX_CA_DIR");
        MockCa ca = MockCa.loadOrCreate(dir != null && !dir.isBlank() ? Path.of(dir) : null);
        SandboxServer server = new SandboxServer(ca,
                "true".equalsIgnoreCase(System.getenv("SANDBOX_STRICT_ASP")),
                Long.parseLong(envOr("SANDBOX_TXN_TTL_SECONDS", "600")));
        int port = Integer.parseInt(envOr("PORT", "8091"));
        server.start(port);
        System.out.println("TSI eSign Sandbox listening on :" + server.port() + " (strictAsp=" + server.strictAsp + ")");
        System.out.println("NOT FOR PRODUCTION. Root CA: " + ca.rootCert.getSubjectX500Principal());
    }

    public void start(int port) throws IOException {
        http = HttpServer.create(new InetSocketAddress(port), 0);
        http.createContext("/", this::route);
        http.start();
    }

    public int port() {
        return http.getAddress().getPort();
    }

    public void stop() {
        http.stop(0);
    }

    // ---- routing ----

    private void route(HttpExchange ex) throws IOException {
        try {
            String path = ex.getRequestURI().getPath();
            String method = ex.getRequestMethod();
            if ("GET".equals(method) && "/health".equals(path)) {
                send(ex, 200, "text/plain", "ok");
            } else if ("GET".equals(method) && "/ca/root.pem".equals(path)) {
                send(ex, 200, "application/x-pem-file", MockCa.toPem(ca.rootCert));
            } else if ("GET".equals(method) && "/ca/esp.pem".equals(path)) {
                send(ex, 200, "application/x-pem-file", MockCa.toPem(ca.espCert));
            } else if ("POST".equals(method) && "/esign/2.1/form/signdoc".equals(path)) {
                signdoc(ex);
            } else if ("POST".equals(method) && "/esign/2.1/consent".equals(path)) {
                consent(ex);
            } else if ("POST".equals(method) && "/admin/asps".equals(path)) {
                registerAsp(ex);
            } else if ("POST".equals(method) && "/tsa".equals(path)) {
                byte[] response = Tsa.respond(ca, readBody(ex));
                ex.getResponseHeaders().set("Content-Type", "application/timestamp-reply");
                ex.sendResponseHeaders(200, response.length);
                ex.getResponseBody().write(response);
                ex.close();
            } else {
                send(ex, 404, "text/plain", "Not found");
            }
        } catch (Exception e) {
            e.printStackTrace();
            send(ex, 500, "text/plain", "Sandbox error: " + e.getMessage());
        }
    }

    // ---- ASP -> ESP: signed request in ----

    private void signdoc(HttpExchange ex) throws Exception {
        boolean json = wantsJson(ex);
        String xml = form(readBody(ex)).get("msg");
        if (xml == null || xml.isBlank()) {
            fail(ex, json, "ESP-100", "Missing 'msg' form field.");
            return;
        }
        Document doc;
        try {
            doc = Dsig.parse(xml);
        } catch (Exception e) {
            fail(ex, json, "ESP-101", "Request is not well-formed XML.");
            return;
        }
        Element root = doc.getDocumentElement();
        if (!"Esign".equals(root.getLocalName())) {
            fail(ex, json, "ESP-101", "Root element must be Esign.");
            return;
        }
        String aspId = root.getAttribute("aspId");
        String txn = root.getAttribute("txn");
        String responseUrl = root.getAttribute("responseUrl");
        if (aspId.isBlank() || txn.isBlank() || responseUrl.isBlank()) {
            fail(ex, json, "ESP-102", "aspId, txn and responseUrl are required.");
            return;
        }
        if (!"2.1".equals(root.getAttribute("ver"))) {
            fail(ex, json, "ESP-103", "Unsupported ver '" + root.getAttribute("ver") + "' (sandbox speaks 2.1).");
            return;
        }
        X509Certificate embedded = Dsig.verifyAndGetSigner(doc);
        if (embedded == null) {
            fail(ex, json, "ESP-104", "Request signature missing or invalid.");
            return;
        }
        if (strictAsp) {
            X509Certificate registered = registeredAsps.get(aspId);
            if (registered == null) {
                fail(ex, json, "ESP-105", "ASP '" + aspId + "' is not registered.");
                return;
            }
            if (!java.util.Arrays.equals(registered.getEncoded(), embedded.getEncoded())) {
                fail(ex, json, "ESP-106", "Request was not signed with the registered ASP certificate.");
                return;
            }
        }
        org.w3c.dom.NodeList hashes = root.getElementsByTagName("InputHash");
        if (hashes.getLength() != 1) {
            fail(ex, json, "ESP-107", "Exactly one InputHash is required.");
            return;
        }
        Element hashElement = (Element) hashes.item(0);
        String hashHex = hashElement.getTextContent().trim();
        if (!"SHA256".equalsIgnoreCase(hashElement.getAttribute("hashAlgorithm")) || !HEX64.matcher(hashHex).matches()) {
            fail(ex, json, "ESP-108", "InputHash must be a hex SHA256 digest.");
            return;
        }
        if (transactions.containsKey(aspId + "|" + txn)) {
            fail(ex, json, "ESP-109", "Duplicate txn.");
            return;
        }
        Txn t = new Txn(aspId, txn, hashHex.toLowerCase(), hashElement.getAttribute("docInfo"), responseUrl, Instant.now());
        transactions.put(aspId + "|" + txn, t);

        String key = aspId + "|" + txn;
        if (json) {
            send(ex, 200, "application/json", "{\"txnKey\":\"" + esc(key) + "\",\"consentUrl\":\"/esign/2.1/consent\","
                    + "\"otp\":\"" + VALID_OTP + "\",\"signerName\":\"" + esc(prefillName(t.docInfo)) + "\"}");
        } else {
            send(ex, 200, "text/html", consentPage(key, t));
        }
    }

    // ---- user consent -> signed response out ----

    private void consent(HttpExchange ex) throws Exception {
        boolean json = wantsJson(ex);
        Map<String, String> f = form(readBody(ex));
        Txn t = transactions.remove(f.getOrDefault("txnKey", ""));
        if (t == null) {
            fail(ex, json, "ESP-110", "Unknown or already-used transaction.");
            return;
        }
        String otp = f.getOrDefault("otp", "");
        String simulate = f.getOrDefault("simulate", "ok");
        String signerName = f.getOrDefault("signerName", "").isBlank() ? "Sandbox Signer" : f.get("signerName").trim();

        String errCode = null;
        String errMsg = null;
        if (Instant.now().isAfter(t.created().plusSeconds(txnTtlSeconds)) || "expired".equals(simulate)) {
            errCode = "ESP-TXN-EXPIRED";
            errMsg = "Transaction expired.";
        } else if ("deny".equals(simulate)) {
            errCode = "ESP-USER-CANCEL";
            errMsg = "User cancelled.";
        } else if ("esp_error".equals(simulate)) {
            errCode = "ESP-500";
            errMsg = "Simulated internal ESP error.";
        } else if (!VALID_OTP.equals(otp)) {
            errCode = "ESP-OTP-INVALID";
            errMsg = "Invalid OTP.";
        }

        Document resp = Dsig.parse("<EsignResp/>");
        Element root = resp.getDocumentElement();
        root.setAttribute("ts", TS.format(Instant.now()));
        root.setAttribute("txn", t.txn());
        root.setAttribute("resCode", UUID.randomUUID().toString());
        if (errCode != null) {
            root.setAttribute("status", "0");
            root.setAttribute("errCode", errCode);
            root.setAttribute("errMsg", errMsg);
        } else {
            root.setAttribute("status", "1");
            root.setAttribute("errCode", "NA");
            root.setAttribute("errMsg", "NA");
            byte[] hash = hex(t.hashHex());
            if ("tampered_hash".equals(simulate)) {
                hash = MessageDigest.getInstance("SHA-256").digest(hash); // signs something other than what was asked
            }
            KeyPair signerPair = MockCa.newKeyPair(); // per-transaction key, discarded right after use
            Date now = new Date();
            X509Certificate signerCert = ca.issueSigner(signerName, signerPair.getPublic(),
                    new Date(now.getTime() - 60_000), new Date(now.getTime() + 30 * 60_000L));
            byte[] cms = HashSigner.signHash(hash, signerPair.getPrivate(), signerCert, ca.rootCert);

            Element userCert = resp.createElement("UserX509Certificate");
            userCert.setTextContent(Base64.getEncoder().encodeToString(signerCert.getEncoded()));
            root.appendChild(userCert);
            Element signatures = resp.createElement("Signatures");
            Element docSignature = resp.createElement("DocSignature");
            docSignature.setAttribute("id", "1");
            docSignature.setAttribute("sigHashAlgorithm", "SHA256");
            docSignature.setAttribute("error", "NA");
            docSignature.setTextContent(Base64.getEncoder().encodeToString(cms));
            signatures.appendChild(docSignature);
            root.appendChild(signatures);
        }
        if ("bad_signature".equals(simulate)) {
            KeyPair rogue = MockCa.newKeyPair();
            X509Certificate rogueCert = ca.issueSigner("Rogue", rogue.getPublic(), new Date(), new Date(System.currentTimeMillis() + 60_000));
            Dsig.sign(resp, rogue.getPrivate(), rogueCert); // valid XML-DSig, but not from a trusted ESP cert
        } else {
            Dsig.sign(resp, ca.espKey, ca.espCert);
        }
        String msg = Dsig.serialize(resp);
        if (json) {
            send(ex, 200, "application/json", "{\"responseUrl\":\"" + esc(t.responseUrl()) + "\",\"msg\":\"" + esc(msg) + "\"}");
        } else {
            send(ex, 200, "text/html", "<!doctype html><meta charset=utf-8><title>Returning to application</title>"
                    + "<body onload=\"document.forms[0].submit()\"><p>Returning to the application...</p>"
                    + "<form method=\"post\" action=\"" + h(t.responseUrl()) + "\"><input type=\"hidden\" name=\"msg\" value=\""
                    + h(msg) + "\"><noscript><button>Continue</button></noscript></form></body>");
        }
    }

    private void registerAsp(HttpExchange ex) throws Exception {
        Map<String, String> f = form(readBody(ex));
        X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(f.getOrDefault("certPem", "").getBytes(StandardCharsets.US_ASCII)));
        registeredAsps.put(f.getOrDefault("aspId", ""), cert);
        send(ex, 200, "application/json", "{\"registered\":\"" + esc(f.get("aspId")) + "\"}");
    }

    /** Test/admin hook: register an ASP certificate directly (strict mode). */
    public void registerAsp(String aspId, X509Certificate cert) {
        registeredAsps.put(aspId, cert);
    }

    // ---- pages / helpers ----

    private static String prefillName(String docInfo) {
        Matcher m = Pattern.compile("signer:\\s*([^|]+)").matcher(docInfo == null ? "" : docInfo);
        return m.find() ? m.group(1).trim() : "";
    }

    private static String consentPage(String key, Txn t) {
        return """
                <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
                <title>TSI eSign Sandbox</title>
                <style>body{font-family:system-ui,sans-serif;background:#f3f7f8;color:#172033;display:flex;justify-content:center;padding:32px 16px}
                .card{background:#fff;border:1px solid #d9e2ec;border-top:4px solid #b7791f;border-radius:12px;padding:28px;max-width:440px;width:100%%}
                .banner{background:#fff8e1;border:1px solid #ffe9a8;color:#7a5b00;border-radius:8px;padding:8px 12px;font-size:12.5px;font-weight:700;margin-bottom:16px}
                label{display:block;font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:.06em;color:#607086;margin:14px 0 4px}
                input,select{width:100%%;box-sizing:border-box;padding:10px;border:1px solid #d9e2ec;border-radius:6px;font:inherit}
                button{margin-top:20px;width:100%%;padding:12px;border:0;border-radius:7px;background:#006a67;color:#fff;font-weight:800;cursor:pointer}
                code{word-break:break-all;font-size:12px}</style></head><body><div class="card">
                <div class="banner">SANDBOX - a mock ESP/CA. Not a real Aadhaar authentication. OTP: 123456</div>
                <h2 style="margin:0 0 4px">Aadhaar eSign consent</h2>
                <p style="color:#607086;font-size:13px;margin:0">ASP <b>%s</b> requests your signature on:</p>
                <p><b>%s</b></p><p style="font-size:12px;color:#607086">Document hash (SHA-256; the ESP never sees the document):<br><code>%s</code></p>
                <form method="post" action="/esign/2.1/consent"><input type="hidden" name="txnKey" value="%s">
                <label>Aadhaar / VID (any, not checked)</label><input name="aadhaar" value="999999999999">
                <label>Name as per Aadhaar</label><input name="signerName" value="%s">
                <label>OTP</label><input name="otp" value="123456" autocomplete="off">
                <label>Simulate outcome</label><select name="simulate">
                <option value="ok">Success</option><option value="deny">User cancels</option><option value="expired">Transaction expired</option>
                <option value="esp_error">ESP internal error</option><option value="tampered_hash">Signs a different hash (attack)</option>
                <option value="bad_signature">Response signed by untrusted key (attack)</option></select>
                <button type="submit">Authenticate &amp; sign</button></form></div></body></html>
                """.formatted(h(t.aspId()), h(t.docInfo()), h(t.hashHex()), h(key), h(prefillName(t.docInfo())));
    }

    private void fail(HttpExchange ex, boolean json, String code, String message) throws IOException {
        if (json) {
            send(ex, 400, "application/json", "{\"errCode\":\"" + code + "\",\"errMsg\":\"" + esc(message) + "\"}");
        } else {
            send(ex, 400, "text/html", "<!doctype html><meta charset=utf-8><title>Sandbox error</title><body style=\"font-family:system-ui;padding:32px\">"
                    + "<h2>eSign request rejected</h2><p><b>" + code + "</b>: " + h(message) + "</p></body>");
        }
    }

    private static boolean wantsJson(HttpExchange ex) {
        String accept = ex.getRequestHeaders().getFirst("Accept");
        return accept != null && accept.contains("application/json");
    }

    private static byte[] readBody(HttpExchange ex) throws IOException {
        try (InputStream in = ex.getRequestBody()) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            in.transferTo(out);
            return out.toByteArray();
        }
    }

    private static Map<String, String> form(byte[] body) {
        return form(new String(body, StandardCharsets.UTF_8));
    }

    private static Map<String, String> form(String body) {
        Map<String, String> map = new HashMap<>();
        for (String pair : body.split("&")) {
            int i = pair.indexOf('=');
            if (i > 0) {
                map.put(URLDecoder.decode(pair.substring(0, i), StandardCharsets.UTF_8),
                        URLDecoder.decode(pair.substring(i + 1), StandardCharsets.UTF_8));
            }
        }
        return map;
    }

    private static void send(HttpExchange ex, int status, String contentType, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", contentType + "; charset=utf-8");
        ex.sendResponseHeaders(status, bytes.length);
        ex.getResponseBody().write(bytes);
        ex.close();
    }

    private static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    private static String h(String s) {
        return s == null ? "" : s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    private static String esc(String s) {
        return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    private static String envOr(String name, String fallback) {
        String v = System.getenv(name);
        return v != null && !v.isBlank() ? v : fallback;
    }
}
