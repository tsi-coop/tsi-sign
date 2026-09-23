package org.tsicoop.sign.esign;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSigProperties;
import org.apache.pdfbox.util.Hex;
import org.tsicoop.sign.pki.SignaturePlaceholderLocator;
import org.tsicoop.sign.pki.VisibleSignatureStamper;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Map;
import java.util.UUID;

/**
 * The async, two-phase signing mechanic Aadhaar eSign needs and Corporate
 * Seal doesn't (the reason this class exists - see below).
 *
 * <p>Verified against PDFBox 3.0.6's own source
 * ({@code COSWriter.doWriteSignature}/{@code writeExternalSignature}):
 * {@code PDDocument.saveIncrementalForExternalSigning(...)} does NOT write
 * anything to its output stream until {@code setSignature(...)} is called -
 * the "prepared" state lives only in private fields of a live
 * {@code COSWriter}, which cannot survive a real HTTP redirect gap (a
 * different request, possibly a different server instance, possibly
 * minutes later). So this class never tries to keep that object alive:
 * {@link #prepare} extracts just two plain, persistable things - the exact
 * bytes to hash ({@code ExternalSigningSupport.getContent()}) and the
 * signature's {@code ByteRange} - and closes the document immediately.
 * {@link #finalizeSignature} does the byte-splice PDFBox itself would have
 * done, using only those two persisted values: since {@code getContent()}'s
 * bytes are precisely "the final file with the whole {@code <...>}
 * placeholder span removed," and {@code ByteRange[1]} is exactly the offset
 * where that span belongs, re-inserting a same-length {@code <hex...0>}
 * block at that offset reconstructs the complete, correctly hashed file -
 * no PDDocument, no COSWriter, needed for phase two at all.
 */
public class ExternalCmsSpliceService {

    /** Reserved placeholder size - generous for an RSA CMS + CA cert chain response; can't be resized after prepare(). */
    private static final int PREFERRED_SIGNATURE_SIZE = SignatureOptions.DEFAULT_SIGNATURE_SIZE * 4;

    public record PreparedSigning(byte[] contentToHash, int[] byteRange, String signatureFieldName) {
    }

    /**
     * Phase 1 (synchronous): reserves signature space, draws the visible
     * Corporate-Seal-style stamp at any {@code [[TSI_SIGNATURE:name]]}
     * marker (signer identity instead of an org key alias), and returns
     * exactly what's needed to (a) send a hash to the ESP and (b) finish
     * the signature later with no PDFBox objects in memory.
     */
    public PreparedSigning prepare(byte[] originalPdfBytes, String providerLabel, String signerName, String reason)
            throws Exception {
        return prepare(originalPdfBytes, providerLabel, signerName, reason, null);
    }

    /**
     * @param targetPlaceholderName null: every located marker gets stamped -
     *                              first becomes the real widget, the rest
     *                              plain overlay stamps (today's behavior).
     *                              Non-null (docs/architecture.md §6.4):
     *                              only that one named marker becomes the
     *                              real widget; every other marker is left
     *                              completely untouched for a later signer.
     */
    public PreparedSigning prepare(byte[] originalPdfBytes, String providerLabel, String signerName, String reason,
            String targetPlaceholderName) throws Exception {
        try (PDDocument document = PDDocument.load(originalPdfBytes)) {
            Map<String, SignaturePlaceholderLocator.Placement> placements =
                    SignaturePlaceholderLocator.locate(document);

            PDSignature signature = new PDSignature();
            signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            signature.setSubFilter(PDSignature.SUBFILTER_ETSI_CADES_DETACHED);
            signature.setName("TSI Aadhaar eSign");
            String effectiveReason = reason != null ? reason : "Aadhaar eSign";
            signature.setReason(effectiveReason);
            Calendar signDate = Calendar.getInstance();
            signature.setSignDate(signDate);

            SignatureOptions signatureOptions = new SignatureOptions();
            signatureOptions.setPreferredSignatureSize(PREFERRED_SIGNATURE_SIZE);

            String fieldName = "tsi_aadhaar_esign_" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);

            if (!placements.isEmpty()) {
                SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z");
                dateFormat.setTimeZone(signDate.getTimeZone());

                String signerLine = "By: " + providerLabel;
                String signedByLine = "Signed by: " + signerName;
                String reasonLine = "Reason: " + truncate(effectiveReason, 40);
                String dateLine = "Date: " + dateFormat.format(signDate.getTime());

                boolean targeted = targetPlaceholderName != null && placements.containsKey(targetPlaceholderName);
                String primaryName = targeted ? targetPlaceholderName : placements.keySet().iterator().next();

                if (!targeted) {
                    for (Map.Entry<String, SignaturePlaceholderLocator.Placement> entry : placements.entrySet()) {
                        if (!entry.getKey().equals(primaryName)) {
                            VisibleSignatureStamper.drawOverlayStamp(
                                    document, entry.getValue(), signerLine, signedByLine, reasonLine, dateLine);
                        }
                    }
                }

                SignaturePlaceholderLocator.Placement primary = placements.get(primaryName);
                PDVisibleSigProperties visibleProperties = VisibleSignatureStamper.buildSignatureAppearance(
                        document, primary, fieldName, signerLine, signedByLine, reasonLine, dateLine);
                signatureOptions.setVisualSignature(visibleProperties);
                signatureOptions.setPage(primary.pageIndex());
            }

            document.addSignature(signature, signatureOptions);

            ByteArrayOutputStream discard = new ByteArrayOutputStream();
            ExternalSigningSupport externalSigning = document.saveIncrementalForExternalSigning(discard);
            byte[] contentToHash;
            try (InputStream in = externalSigning.getContent()) {
                contentToHash = in.readAllBytes();
            }
            int[] byteRange = signature.getByteRange();
            return new PreparedSigning(contentToHash, byteRange, fieldName);
        }
    }

    /**
     * Phase 2 (from a callback, possibly minutes later, no PDFBox objects
     * alive): splices the ESP's CMS bytes into the exact reserved span and
     * returns the complete, correctly signed PDF.
     */
    public byte[] finalizeSignature(byte[] contentToHash, int[] byteRange, byte[] cmsSignature) throws IOException {
        int placeholderTotalLength = byteRange[2] - byteRange[1];
        String hex = Hex.getString(cmsSignature);
        if (hex.length() > placeholderTotalLength - 2) {
            throw new IOException("CMS signature (" + hex.length() + " hex chars) does not fit the reserved " +
                    "signature space (" + (placeholderTotalLength - 2) + ") - increase PREFERRED_SIGNATURE_SIZE.");
        }

        StringBuilder placeholder = new StringBuilder(placeholderTotalLength);
        placeholder.append('<').append(hex);
        for (int i = hex.length(); i < placeholderTotalLength - 2; i++) {
            placeholder.append('0');
        }
        placeholder.append('>');
        byte[] placeholderBytes = placeholder.toString().getBytes(StandardCharsets.ISO_8859_1);

        ByteArrayOutputStream out = new ByteArrayOutputStream(contentToHash.length + placeholderBytes.length);
        out.write(contentToHash, 0, byteRange[1]);
        out.write(placeholderBytes);
        out.write(contentToHash, byteRange[1], contentToHash.length - byteRange[1]);
        return out.toByteArray();
    }

    private static String truncate(String text, int maxLength) {
        return text.length() <= maxLength ? text : text.substring(0, maxLength - 3) + "...";
    }
}
