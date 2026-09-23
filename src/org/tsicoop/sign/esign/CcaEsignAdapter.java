package org.tsicoop.sign.esign;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.tsicoop.sign.pki.LocalKeyStoreProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.TimeZone;
import java.util.UUID;

/**
 * A generic adapter for any CCA-licensed eSign Service Provider speaking the CCA's eSign API 2.1
 * (eMudhra, C-DAC, Protean/NSDL, VSign, ...): those differ in endpoint URL, ASP id, and trust
 * chain - configuration, see {@link CcaEsignConfig} - not in code.
 *
 * <p>Flow: {@link #initiateSigning} builds an {@code <Esign>} request carrying ONLY the SHA-256 of
 * the bytes to be signed (never the document or any PII), signs it with our ASP key (XML-DSig), and
 * returns a payload for the signer's browser to POST to the ESP. The ESP authenticates the signer
 * (Aadhaar OTP), issues a short-lived certificate, and POSTs a signed {@code <EsignResp>} back to our
 * {@code responseUrl}; {@link #processCallback} authenticates that response (XML-DSig by the PINNED ESP
 * certificate), checks the returned PKCS#7's signed digest is exactly the hash we sent,
 * and verifies the signer certificate - only then is the signature spliced into the PDF.
 *
 * <p>Verified against {@code sandbox/} (a protocol-level mock ESP/CA), NOT against any real CA:
 * profile-specific quirks are only discovered against that CA's own sandbox.
 */
public class CcaEsignAdapter implements ESignAdapter {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final CcaEsignConfig config;
    private volatile TrustAnchors trust;
    private volatile TrustAnchors pinnedEsp;

    public CcaEsignAdapter(CcaEsignConfig config) {
        this.config = config;
    }

    @Override
    public String getProviderId() {
        return config.providerId();
    }

    @Override
    public String getDisplayName() {
        return config.displayName();
    }

    @Override
    public SigningSessionResponse initiateSigning(SigningSessionRequest request) throws Exception {
        String txn = "TSI" + UUID.randomUUID().toString().replace("-", "");
        String responseUrl = config.publicBaseUrl() + "/esign/return/" + config.providerId() + "/" + txn;
        String docInfo = truncate("TSI Sign | signer: " + request.signerName(), 100);

        SimpleDateFormat ts = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
        ts.setTimeZone(TimeZone.getTimeZone("Asia/Kolkata"));
        Document doc = XmlDsig.parse("<Esign/>");
        Element root = doc.getDocumentElement();
        root.setAttribute("ver", config.version());
        root.setAttribute("sc", "Y");
        root.setAttribute("ts", ts.format(new Date()));
        root.setAttribute("txn", txn);
        root.setAttribute("ekycId", "");
        root.setAttribute("ekycIdType", "A");
        root.setAttribute("aspId", config.aspId());
        root.setAttribute("AuthMode", config.authMode());
        root.setAttribute("responseSigType", "pkcs7");
        root.setAttribute("responseUrl", responseUrl);
        Element docs = doc.createElement("Docs");
        Element inputHash = doc.createElement("InputHash");
        inputHash.setAttribute("id", "1");
        inputHash.setAttribute("hashAlgorithm", "SHA256");
        inputHash.setAttribute("docInfo", docInfo);
        inputHash.setTextContent(request.documentHash());
        docs.appendChild(inputHash);
        root.appendChild(docs);

        KeyStore.PrivateKeyEntry aspKey = loadAspKey();
        XmlDsig.sign(doc, aspKey.getPrivateKey(), (X509Certificate) aspKey.getCertificate());

        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("actionUrl", config.endpointUrl());
        payload.putObject("fields").put("msg", XmlDsig.serialize(doc));

        String gatewayUrl = config.publicBaseUrl() + "/console/esign-redirect.html?provider=" + config.providerId() + "&txn=" + txn;
        return new SigningSessionResponse(txn, gatewayUrl, payload.toString());
    }

    @Override
    public SigningResult processCallback(JsonNode callbackPayload, String expectedHashHex) {
        try {
            String msg = callbackPayload.path("msg").asText(null);
            if (msg == null || msg.isBlank()) {
                return SigningResult.rejected("Callback carries no 'msg'.");
            }
            Document doc = XmlDsig.parse(msg);
            Element root = doc.getDocumentElement();
            if (!"EsignResp".equals(root.getLocalName())) {
                return SigningResult.rejected("Callback root element is not EsignResp.");
            }

            // 1. Authenticate the ESP BEFORE believing anything else in the message (including a failure status).
            X509Certificate espCert = XmlDsig.verifyAndGetSigner(doc);
            if (espCert == null) {
                return SigningResult.rejected("Response signature missing or invalid.");
            }
            TrustAnchors anchors = trust();
            if (!pinnedEsp().isPinned(espCert)) {
                return SigningResult.rejected("Response is not signed by the configured ESP certificate.");
            }
            espCert.checkValidity();

            String txn = root.getAttribute("txn");
            if (!"1".equals(root.getAttribute("status"))) {
                String code = root.getAttribute("errCode");
                String message = root.getAttribute("errMsg");
                return SigningResult.caFailure(txn, (code.isBlank() ? "ESP error" : code)
                        + (message.isBlank() ? "" : ": " + message));
            }

            // 2. The PKCS#7 must sign exactly the hash we sent.
            org.w3c.dom.NodeList docSignatures = root.getElementsByTagName("DocSignature");
            if (docSignatures.getLength() != 1) {
                return SigningResult.rejected("Expected exactly one DocSignature.");
            }
            byte[] cmsBytes = Base64.getDecoder().decode(docSignatures.item(0).getTextContent().trim());
            CMSSignedData cms = new CMSSignedData(cmsBytes);
            if (cms.getSignerInfos().size() != 1) {
                return SigningResult.rejected("Expected exactly one signer in the PKCS#7.");
            }
            SignerInformation signer = cms.getSignerInfos().getSigners().iterator().next();
            Attribute digestAttr = signer.getSignedAttributes() == null ? null
                    : signer.getSignedAttributes().get(CMSAttributes.messageDigest);
            if (digestAttr == null) {
                return SigningResult.rejected("PKCS#7 has no signed messageDigest.");
            }
            byte[] signedDigest = ((ASN1OctetString) digestAttr.getAttrValues().getObjectAt(0)).getOctets();
            if (!MessageDigest.isEqual(signedDigest, HexFormat.of().parseHex(expectedHashHex))) {
                return SigningResult.rejected("PKCS#7 signs a different hash than the one requested.");
            }

            // 3. The signer certificate must chain to a trusted CA and actually verify the signature.
            List<X509Certificate> certs = new ArrayList<>();
            JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider("BC");
            for (X509CertificateHolder holder : cms.getCertificates().getMatches(null)) {
                certs.add(converter.getCertificate(holder));
            }
            X509Certificate signerCert = null;
            for (X509Certificate c : certs) {
                if (signer.getSID().match(new X509CertificateHolder(c.getEncoded()))) {
                    signerCert = c;
                }
            }
            if (signerCert == null) {
                signerCert = userCertificate(root);
            }
            if (signerCert == null) {
                return SigningResult.rejected("Signer certificate not found in the response.");
            }
            signerCert.checkValidity();
            if (!anchors.validates(signerCert, certs)) {
                return SigningResult.rejected("Signer certificate does not chain to a trusted CA.");
            }
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(signerCert);
            verifier.update(signer.getEncodedSignedAttributes());
            if (!verifier.verify(signer.getSignature())) {
                return SigningResult.rejected("PKCS#7 signature does not verify against the signer certificate.");
            }

            return SigningResult.signed(txn, cmsBytes, commonName(signerCert), signerCert.getIssuerX500Principal().getName(),
                    authTypeName(config.authMode()));
        } catch (Exception e) {
            return SigningResult.rejected("Callback could not be processed: " + e.getClass().getSimpleName());
        }
    }

    private static X509Certificate userCertificate(Element root) throws Exception {
        org.w3c.dom.NodeList nodes = root.getElementsByTagName("UserX509Certificate");
        if (nodes.getLength() != 1) {
            return null;
        }
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                new ByteArrayInputStream(Base64.getDecoder().decode(nodes.item(0).getTextContent().trim())));
    }

    private TrustAnchors trust() throws Exception {
        TrustAnchors t = trust;
        if (t == null) {
            synchronized (this) {
                if (trust == null) {
                    trust = TrustAnchors.load(config.trustCertFiles());
                }
                t = trust;
            }
        }
        return t;
    }

    private TrustAnchors pinnedEsp() throws Exception {
        TrustAnchors t = pinnedEsp;
        if (t == null) {
            synchronized (this) {
                if (pinnedEsp == null) {
                    pinnedEsp = TrustAnchors.load(config.espCertFiles());
                }
                t = pinnedEsp;
            }
        }
        return t;
    }

    private KeyStore.PrivateKeyEntry loadAspKey() throws Exception {
        if (config.aspKeystorePath() == null) {
            return new LocalKeyStoreProvider().getPrivateKeyEntry(config.aspKeyAlias());
        }
        char[] password = (config.aspKeystorePassword() == null ? "" : config.aspKeystorePassword()).toCharArray();
        KeyStore keyStore = KeyStore.getInstance(config.aspKeystoreType());
        try (FileInputStream in = new FileInputStream(config.aspKeystorePath())) {
            keyStore.load(in, password);
        }
        KeyStore.Entry entry = keyStore.getEntry(config.aspKeyAlias(), new KeyStore.PasswordProtection(password));
        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            throw new IllegalStateException("No ASP private key under alias " + config.aspKeyAlias());
        }
        return (KeyStore.PrivateKeyEntry) entry;
    }

    private static String commonName(X509Certificate cert) {
        try {
            for (Rdn rdn : new LdapName(cert.getSubjectX500Principal().getName()).getRdns()) {
                if ("CN".equalsIgnoreCase(rdn.getType())) {
                    return rdn.getValue().toString();
                }
            }
        } catch (Exception ignored) {
        }
        return cert.getSubjectX500Principal().getName();
    }

    private static String authTypeName(String authMode) {
        return switch (authMode) {
            case "2" -> "AADHAAR_FINGERPRINT";
            case "3" -> "AADHAAR_IRIS";
            case "4" -> "AADHAAR_FACE";
            default -> "AADHAAR_OTP";
        };
    }

    private static String truncate(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max);
    }

}
