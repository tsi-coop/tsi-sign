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
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSigProperties;
import org.tsicoop.sign.framework.HashUtil;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.Map;

/**
 * Seals a PDF with a PAdES-B-B (CAdES-detached) signature using a local
 * KeyStore alias — no external CA, no network hop (§7 Local PKI flow).
 * The actual CMS/PKCS7 computation follows PDFBox's own reference pattern
 * (org.apache.pdfbox.examples.signature.CreateSignature) via BouncyCastle.
 *
 * <p>If the rendered PDF contains one or more {@code [[TSI_SIGNATURE:name]]}
 * markers (see {@link SignaturePlaceholderLocator}), a visible Corporate
 * Seal stamp (signer/reason/date + QR) is drawn at each one - one becomes
 * the real signature widget ({@link VisibleSignatureStamper}), the rest are
 * plain overlay stamps. Templates with no marker keep today's fully
 * invisible signature, unchanged.
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
        String originalHash = HashUtil.sha256Hex(originalPdfBytes);

        try (PDDocument document = PDDocument.load(originalPdfBytes)) {
            Map<String, SignaturePlaceholderLocator.Placement> placements =
                    SignaturePlaceholderLocator.locate(document);

            PDSignature signature = new PDSignature();
            signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            signature.setSubFilter(PDSignature.SUBFILTER_ETSI_CADES_DETACHED);
            signature.setName("TSI Sign Local PKI");
            String effectiveReason = reason != null ? reason : "Document sealed via TSI Sign Local PKI";
            signature.setReason(effectiveReason);
            if (location != null) {
                signature.setLocation(location);
            }
            Calendar signDate = Calendar.getInstance();
            signature.setSignDate(signDate);

            SignatureInterface signatureInterface = content -> signCms(content, keyEntry);

            SignatureOptions signatureOptions = new SignatureOptions();
            signatureOptions.setPreferredSignatureSize(SignatureOptions.DEFAULT_SIGNATURE_SIZE * 2);

            if (!placements.isEmpty()) {
                stampCorporateSeal(document, signatureOptions, placements, keyAlias, effectiveReason,
                        signDate, originalHash);
            }

            document.addSignature(signature, signatureInterface, signatureOptions);

            ByteArrayOutputStream sealedOut = new ByteArrayOutputStream();
            document.saveIncremental(sealedOut);

            byte[] sealedBytes = sealedOut.toByteArray();
            return new SealResult(sealedBytes, HashUtil.sha256Hex(sealedBytes));
        }
    }

    /**
     * Draws the visible Corporate Seal at every located placeholder. The
     * first one found (reading order) becomes the real signature widget via
     * {@code signatureOptions}; any others are plain overlay stamps drawn
     * directly onto the document now, before the signature's byte-range
     * hash is computed by {@code addSignature}.
     */
    private void stampCorporateSeal(PDDocument document, SignatureOptions signatureOptions,
            Map<String, SignaturePlaceholderLocator.Placement> placements, String keyAlias,
            String effectiveReason, Calendar signDate, String originalHash) throws Exception {
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z");
        dateFormat.setTimeZone(signDate.getTimeZone());

        String signerLine = "By: " + keyAlias;
        String reasonLine = "Reason: " + truncate(effectiveReason, 40);
        String dateLine = "Date: " + dateFormat.format(signDate.getTime());
        String qrPayload = VisibleSignatureStamper.buildQrPayload(
                originalHash, keyAlias, signDate.toInstant().toString());

        String primaryName = placements.keySet().iterator().next();
        for (Map.Entry<String, SignaturePlaceholderLocator.Placement> entry : placements.entrySet()) {
            if (!entry.getKey().equals(primaryName)) {
                VisibleSignatureStamper.drawOverlayStamp(
                        document, entry.getValue(), signerLine, reasonLine, dateLine, qrPayload);
            }
        }

        SignaturePlaceholderLocator.Placement primary = placements.get(primaryName);
        PDVisibleSigProperties visibleProperties = VisibleSignatureStamper.buildSignatureAppearance(
                document, primary, "tsi_signature_" + primaryName, signerLine, reasonLine, dateLine, qrPayload);
        signatureOptions.setVisualSignature(visibleProperties);
        signatureOptions.setPage(primary.pageIndex());
    }

    private static String truncate(String text, int maxLength) {
        return text.length() <= maxLength ? text : text.substring(0, maxLength - 3) + "...";
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
