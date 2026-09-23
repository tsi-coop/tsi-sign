package org.tsicoop.sign.pki;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.tsicoop.sign.esign.TrustAnchors;

import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Upgrades a CMS signature from PAdES-B-B to PAdES-B-T by embedding an RFC 3161 time-stamp token
 * over the signature value (unsigned attribute {@code id-aa-signatureTimeStampToken}) - proof the
 * signature existed at that time, even if the signer's certificate later expires or is revoked.
 * Off unless {@code TSA_URL} is set; then {@code TSA_TRUST_CERTS} (PEM: the TSA's CA) is required,
 * because a token is only evidence if its signer is authenticated. {@code TSA_REQUIRED=true} makes a
 * TSA failure fail the signing; otherwise it degrades to B-B (the seal record says which was applied).
 *
 * <p>NOT implemented: PAdES-B-LT/LTA (embedding OCSP/CRL revocation data and a document
 * time-stamp), i.e. this is not long-term validation.
 */
public class SignatureTimestamper {

    public static final String B_B = "PAdES-B-B";
    public static final String B_T = "PAdES-B-T";
    private static final String TIMESTAMPING_EKU = "1.3.6.1.5.5.7.3.8";
    private static final SecureRandom RANDOM = new SecureRandom();

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public record Result(byte[] cms, String signatureStandard) {
    }

    private static volatile SignatureTimestamper fromEnv;

    private final String tsaUrl;
    private final boolean required;
    private final List<Path> trustFiles;
    private volatile TrustAnchors trust;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    public SignatureTimestamper(String tsaUrl, List<Path> trustFiles, boolean required) {
        this.tsaUrl = tsaUrl;
        this.trustFiles = trustFiles;
        this.required = required;
    }

    public static SignatureTimestamper fromEnv() {
        SignatureTimestamper t = fromEnv;
        if (t == null) {
            String url = System.getenv("TSA_URL");
            List<Path> trust = new ArrayList<>();
            if (url != null && !url.isBlank()) {
                String certs = System.getenv("TSA_TRUST_CERTS");
                if (certs == null || certs.isBlank()) {
                    throw new IllegalStateException("TSA_URL is set but TSA_TRUST_CERTS (PEM of the TSA's CA) is not - " +
                            "a time-stamp token from an unauthenticated TSA is not evidence.");
                }
                for (String p : certs.split(",")) {
                    if (!p.isBlank()) {
                        trust.add(Path.of(p.trim()));
                    }
                }
            }
            t = new SignatureTimestamper(url == null || url.isBlank() ? null : url, trust,
                    "true".equalsIgnoreCase(System.getenv("TSA_REQUIRED")));
            fromEnv = t;
        }
        return t;
    }

    public boolean enabled() {
        return tsaUrl != null;
    }

    /** Adds a signature time-stamp if a TSA is configured; returns the (possibly unchanged) CMS and the resulting standard. */
    public Result apply(byte[] cmsBytes) throws Exception {
        if (!enabled()) {
            return new Result(cmsBytes, B_B);
        }
        try {
            return new Result(addTimestamp(cmsBytes), B_T);
        } catch (Exception e) {
            if (required) {
                throw new Exception("Time-stamping failed and TSA_REQUIRED=true: " + e.getMessage(), e);
            }
            System.err.println("SignatureTimestamper: TSA unavailable, sealing without time-stamp (PAdES-B-B): " + e);
            return new Result(cmsBytes, B_B);
        }
    }

    byte[] addTimestamp(byte[] cmsBytes) throws Exception {
        CMSSignedData cms = new CMSSignedData(cmsBytes);
        SignerInformation signer = cms.getSignerInfos().getSigners().iterator().next();

        byte[] digest = MessageDigest.getInstance("SHA-256").digest(signer.getSignature());
        TimeStampRequestGenerator generator = new TimeStampRequestGenerator();
        generator.setCertReq(true);
        TimeStampRequest request = generator.generate(TSPAlgorithms.SHA256, digest, new BigInteger(64, RANDOM).add(BigInteger.ONE));

        HttpResponse<byte[]> response = http.send(HttpRequest.newBuilder(URI.create(tsaUrl))
                .timeout(Duration.ofSeconds(10)).header("Content-Type", "application/timestamp-query")
                .POST(HttpRequest.BodyPublishers.ofByteArray(request.getEncoded())).build(), HttpResponse.BodyHandlers.ofByteArray());
        if (response.statusCode() != 200) {
            throw new Exception("TSA returned HTTP " + response.statusCode());
        }
        TimeStampResponse tsResponse = new TimeStampResponse(response.body());
        tsResponse.validate(request); // status granted, nonce and digest echo the request
        TimeStampToken token = tsResponse.getTimeStampToken();
        if (token == null) {
            throw new Exception("TSA granted no token");
        }

        List<X509Certificate> certs = new ArrayList<>();
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider("BC");
        for (X509CertificateHolder holder : token.getCertificates().getMatches(null)) {
            certs.add(converter.getCertificate(holder));
        }
        java.util.Iterator<?> matches = token.getCertificates().getMatches(token.getSID()).iterator();
        if (!matches.hasNext()) {
            throw new Exception("TSA certificate not in token");
        }
        X509CertificateHolder tsaHolder = (X509CertificateHolder) matches.next();
        X509Certificate tsaCert = converter.getCertificate(tsaHolder);
        if (tsaCert.getExtendedKeyUsage() == null || !tsaCert.getExtendedKeyUsage().contains(TIMESTAMPING_EKU)) {
            throw new Exception("TSA certificate is not valid for time-stamping");
        }
        if (!trust().validates(tsaCert, certs)) {
            throw new Exception("TSA certificate does not chain to TSA_TRUST_CERTS");
        }
        token.validate(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(tsaHolder));

        ASN1EncodableVector unsigned = new ASN1EncodableVector();
        if (signer.getUnsignedAttributes() != null) {
            unsigned = signer.getUnsignedAttributes().toASN1EncodableVector();
        }
        unsigned.add(new Attribute(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken,
                new DERSet(ASN1Primitive.fromByteArray(token.getEncoded()))));
        SignerInformation stamped = SignerInformation.replaceUnsignedAttributes(signer, new AttributeTable(unsigned));
        return CMSSignedData.replaceSigners(cms, new SignerInformationStore(stamped)).getEncoded();
    }

    private TrustAnchors trust() throws Exception {
        TrustAnchors t = trust;
        if (t == null) {
            synchronized (this) {
                if (trust == null) {
                    trust = TrustAnchors.load(trustFiles);
                }
                t = trust;
            }
        }
        return t;
    }
}
