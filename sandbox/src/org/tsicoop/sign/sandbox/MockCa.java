package org.tsicoop.sign.sandbox;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * The sandbox's stand-in for a CCA hierarchy: one root CA, one ESP response-signing
 * certificate (what a real ESP signs its EsignResp XML with), one timestamp
 * authority certificate, and on-demand short-lived signer certificates (what a real
 * eSign issues per Aadhaar authentication, valid ~30 minutes, key destroyed after use).
 * Persisted to {@code <dir>/ca.p12} when a directory is given so trust survives a
 * restart; the root and the ESP response-signing cert are always written to {@code <dir>/root.pem} / {@code esp.pem}
 * (an adapter trusts the root for signer certs and PINS the ESP cert for response signatures).
 */
public class MockCa {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static final char[] PASSWORD = "sandbox".toCharArray();
    private static final SecureRandom RANDOM = new SecureRandom();

    public final X509Certificate rootCert;
    private final PrivateKey rootKey;
    public final X509Certificate espCert;
    public final PrivateKey espKey;
    public final X509Certificate tsaCert;
    public final PrivateKey tsaKey;

    private MockCa(X509Certificate rootCert, PrivateKey rootKey, X509Certificate espCert, PrivateKey espKey,
            X509Certificate tsaCert, PrivateKey tsaKey) {
        this.rootCert = rootCert;
        this.rootKey = rootKey;
        this.espCert = espCert;
        this.espKey = espKey;
        this.tsaCert = tsaCert;
        this.tsaKey = tsaKey;
    }

    /** @param dir where to persist the CA (nullable: in-memory, regenerated each start) */
    public static MockCa loadOrCreate(Path dir) throws Exception {
        MockCa ca = null;
        if (dir != null) {
            Files.createDirectories(dir);
            Path p12 = dir.resolve("ca.p12");
            if (Files.exists(p12)) {
                KeyStore ks = KeyStore.getInstance("PKCS12");
                try (FileInputStream in = new FileInputStream(p12.toFile())) {
                    ks.load(in, PASSWORD);
                }
                ca = new MockCa((X509Certificate) ks.getCertificate("root"), (PrivateKey) ks.getKey("root", PASSWORD),
                        (X509Certificate) ks.getCertificate("esp"), (PrivateKey) ks.getKey("esp", PASSWORD),
                        (X509Certificate) ks.getCertificate("tsa"), (PrivateKey) ks.getKey("tsa", PASSWORD));
            }
        }
        if (ca == null) {
            ca = generate();
            if (dir != null) {
                KeyStore ks = KeyStore.getInstance("PKCS12");
                ks.load(null, null);
                ks.setKeyEntry("root", ca.rootKey, PASSWORD, new java.security.cert.Certificate[]{ca.rootCert});
                ks.setKeyEntry("esp", ca.espKey, PASSWORD, new java.security.cert.Certificate[]{ca.espCert, ca.rootCert});
                ks.setKeyEntry("tsa", ca.tsaKey, PASSWORD, new java.security.cert.Certificate[]{ca.tsaCert, ca.rootCert});
                try (FileOutputStream out = new FileOutputStream(dir.resolve("ca.p12").toFile())) {
                    ks.store(out, PASSWORD);
                }
            }
        }
        if (dir != null) {
            Files.writeString(dir.resolve("root.pem"), toPem(ca.rootCert));
            Files.writeString(dir.resolve("esp.pem"), toPem(ca.espCert));
        }
        return ca;
    }

    private static MockCa generate() throws Exception {
        KeyPair rootPair = newKeyPair();
        X500Name rootName = new X500Name("CN=TSI eSign Sandbox Root CA (NOT FOR PRODUCTION), O=TSI Coop Sandbox, C=IN");
        long tenYears = 10L * 365 * 24 * 3600 * 1000;
        JcaX509v3CertificateBuilder rootBuilder = new JcaX509v3CertificateBuilder(rootName, serial(),
                new Date(System.currentTimeMillis() - 60_000), new Date(System.currentTimeMillis() + tenYears),
                rootName, rootPair.getPublic());
        rootBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        rootBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        X509Certificate rootCert = new JcaX509CertificateConverter().setProvider("BC")
                .getCertificate(rootBuilder.build(new JcaContentSignerBuilder("SHA256withRSA").build(rootPair.getPrivate())));

        KeyPair espPair = newKeyPair();
        X509Certificate espCert = issue(rootCert, rootPair.getPrivate(),
                "CN=TSI eSign Sandbox ESP, O=TSI Coop Sandbox, C=IN", espPair.getPublic(),
                new Date(System.currentTimeMillis() - 60_000), new Date(System.currentTimeMillis() + tenYears),
                new KeyUsage(KeyUsage.digitalSignature), null);

        KeyPair tsaPair = newKeyPair();
        X509Certificate tsaCert = issue(rootCert, rootPair.getPrivate(),
                "CN=TSI eSign Sandbox TSA, O=TSI Coop Sandbox, C=IN", tsaPair.getPublic(),
                new Date(System.currentTimeMillis() - 60_000), new Date(System.currentTimeMillis() + tenYears),
                new KeyUsage(KeyUsage.digitalSignature), new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));
        return new MockCa(rootCert, rootPair.getPrivate(), espCert, espPair.getPrivate(), tsaCert, tsaPair.getPrivate());
    }

    /** A short-lived (default 30 minute) certificate for one Aadhaar-authenticated signer. */
    public X509Certificate issueSigner(String commonName, PublicKey publicKey, Date notBefore, Date notAfter)
            throws Exception {
        String safe = commonName.replaceAll("[,=+<>#;\"\\\\]", " ").trim();
        return issue(rootCert, rootKey, "CN=" + (safe.isEmpty() ? "Sandbox Signer" : safe) + ", C=IN", publicKey,
                notBefore, notAfter, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation), null);
    }

    public static KeyPair newKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, RANDOM);
        return generator.generateKeyPair();
    }

    private static X509Certificate issue(X509Certificate issuerCert, PrivateKey issuerKey, String subject,
            PublicKey subjectKey, Date notBefore, Date notAfter, KeyUsage keyUsage, ExtendedKeyUsage eku)
            throws Exception {
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerCert, serial(), notBefore,
                notAfter, new X500Name(subject), subjectKey);
        JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true, keyUsage);
        builder.addExtension(Extension.authorityKeyIdentifier, false, utils.createAuthorityKeyIdentifier(issuerCert));
        builder.addExtension(Extension.subjectKeyIdentifier, false, utils.createSubjectKeyIdentifier(subjectKey));
        if (eku != null) {
            builder.addExtension(Extension.extendedKeyUsage, true, eku);
        }
        return new JcaX509CertificateConverter().setProvider("BC")
                .getCertificate(builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(issuerKey)));
    }

    private static BigInteger serial() {
        return new BigInteger(120, RANDOM).add(BigInteger.ONE);
    }

    public static String toPem(X509Certificate cert) throws Exception {
        StringWriter out = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(out)) {
            writer.writeObject(cert);
        }
        return out.toString();
    }
}
