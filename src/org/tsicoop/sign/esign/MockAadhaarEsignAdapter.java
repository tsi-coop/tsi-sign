package org.tsicoop.sign.esign;

import com.fasterxml.jackson.databind.JsonNode;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.tsicoop.sign.pki.LocalKeyStoreProvider;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Phase 1 stand-in for a real CCA-licensed ESP (eMudhra/C-DAC/NSDL) - no
 * network call, no real Aadhaar verification. Signs with a dedicated
 * keypair (alias {@code mock_aadhaar_esign}, a distinct CN from
 * {@code tsi_corporate_seal} - see the Dockerfile) so a stamp can never be
 * confused between "the org's own seal" and "an individual's eSign," even
 * in dev. A real adapter is a drop-in later implementing the same
 * {@link ESignAdapter} interface - nothing else in the flow changes.
 *
 * <p>A real ESP only ever receives a hash over the network and returns a
 * CMS signature computed over it. This mock runs in-process, so rather than
 * reproduce that wire format faithfully, {@link #signApproved} simply signs
 * the same {@code contentToHash} bytes {@link ExternalCmsSpliceService}
 * already prepared - the point of the mock is to exercise the async
 * persisted-state architecture end-to-end with a verifiable result, not to
 * simulate ESP network semantics.
 */
public class MockAadhaarEsignAdapter implements ESignAdapter {

    public static final String PROVIDER_ID = "mock_aadhaar";
    public static final String MOCK_KEY_ALIAS = "mock_aadhaar_esign";

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final LocalKeyStoreProvider keyStoreProvider;
    private final String consoleBaseUrl;

    public MockAadhaarEsignAdapter(LocalKeyStoreProvider keyStoreProvider, String consoleBaseUrl) {
        this.keyStoreProvider = keyStoreProvider;
        this.consoleBaseUrl = consoleBaseUrl;
    }

    @Override
    public String getProviderId() {
        return PROVIDER_ID;
    }

    @Override
    public SigningSessionResponse initiateSigning(SigningSessionRequest request) {
        String transactionId = "MOCK-" + UUID.randomUUID();
        String gatewayUrl = consoleBaseUrl + "/mock-esign-consent.html?txn=" + transactionId;
        return new SigningSessionResponse(transactionId, gatewayUrl);
    }

    /**
     * Not used by the mock's own flow (its consent page calls
     * {@link #signApproved} directly, since there's no real external
     * gateway posting a callback to us) - implemented to satisfy the
     * interface uniformly with a real adapter, which WOULD parse its
     * provider-specific webhook payload here.
     */
    @Override
    public SigningResult processCallback(JsonNode callbackPayload) {
        return new SigningResult(false, null, null, null, null, null,
                "MockAadhaarEsignAdapter has no external callback - use signApproved(...) instead.");
    }

    /** Called by the mock consent page's "Approve" action, standing in for the ESP's own signing step. */
    public SigningResult signApproved(String transactionId, byte[] contentToHash, String signerName) throws Exception {
        KeyStore.PrivateKeyEntry keyEntry = keyStoreProvider.getPrivateKeyEntry(MOCK_KEY_ALIAS);
        byte[] cms = signCms(contentToHash, keyEntry);
        Certificate cert = keyEntry.getCertificate();
        X509CertificateHolder holder = new X509CertificateHolder(cert.getEncoded());
        String caIssuer = holder.getSubject().toString();
        return new SigningResult(true, transactionId, cms, signerName, caIssuer, "MOCK_OTP", null);
    }

    private byte[] signCms(byte[] content, KeyStore.PrivateKeyEntry keyEntry) throws Exception {
        PrivateKey privateKey = keyEntry.getPrivateKey();
        Certificate[] chain = keyEntry.getCertificateChain();

        ContentSigner sha256Signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(privateKey);
        X509CertificateHolder certHolder = new X509CertificateHolder(chain[0].getEncoded());

        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        generator.addSignerInfoGenerator(
                new JcaSignerInfoGeneratorBuilder(
                        new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                        .build(sha256Signer, certHolder));

        List<Certificate> certList = new ArrayList<>(List.of(chain));
        Store<?> certStore = new JcaCertStore(certList);
        generator.addCertificates(certStore);

        CMSTypedData cmsData = new CMSProcessableByteArray(content);
        CMSSignedData signedData = generator.generate(cmsData, false);
        return signedData.getEncoded();
    }
}
