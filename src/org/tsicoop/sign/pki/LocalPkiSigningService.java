package org.tsicoop.sign.pki;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
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
import org.tsicoop.sign.framework.HashUtil;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

/**
 * Seals a PDF with a PAdES-B-B (CAdES-detached) signature using a local
 * KeyStore alias — no external CA, no network hop (§7 Local PKI flow).
 * The actual CMS/PKCS7 computation follows PDFBox's own reference pattern
 * (org.apache.pdfbox.examples.signature.CreateSignature) via BouncyCastle.
 */
public class LocalPkiSigningService {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final LocalKeyStoreProvider keyStoreProvider;

    public LocalPkiSigningService(LocalKeyStoreProvider keyStoreProvider) {
        this.keyStoreProvider = keyStoreProvider;
    }

    public record SealResult(byte[] sealedPdfBytes, String sha256Hash) {
    }

    public SealResult seal(byte[] originalPdfBytes, String keyAlias, String reason, String location) throws Exception {
        KeyStore.PrivateKeyEntry keyEntry = keyStoreProvider.getPrivateKeyEntry(keyAlias);

        try (PDDocument document = PDDocument.load(originalPdfBytes)) {
            PDSignature signature = new PDSignature();
            signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            signature.setSubFilter(PDSignature.SUBFILTER_ETSI_CADES_DETACHED);
            signature.setName("TSI Sign Local PKI");
            signature.setReason(reason != null ? reason : "Document sealed via TSI Sign Local PKI");
            if (location != null) {
                signature.setLocation(location);
            }
            signature.setSignDate(Calendar.getInstance());

            SignatureInterface signatureInterface = content -> signCms(content, keyEntry);

            SignatureOptions signatureOptions = new SignatureOptions();
            signatureOptions.setPreferredSignatureSize(SignatureOptions.DEFAULT_SIGNATURE_SIZE * 2);

            document.addSignature(signature, signatureInterface, signatureOptions);

            ByteArrayOutputStream sealedOut = new ByteArrayOutputStream();
            document.saveIncremental(sealedOut);

            byte[] sealedBytes = sealedOut.toByteArray();
            return new SealResult(sealedBytes, HashUtil.sha256Hex(sealedBytes));
        }
    }

    private byte[] signCms(InputStream content, KeyStore.PrivateKeyEntry keyEntry) throws IOException {
        try {
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

            CMSTypedData cmsData = new CMSProcessableByteArray(content.readAllBytes());
            CMSSignedData signedData = generator.generate(cmsData, false);
            return signedData.getEncoded();
        } catch (Exception e) {
            throw new IOException("Failed to compute CMS/PKCS7 signature", e);
        }
    }
}
