package org.tsicoop.sign.pki;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.graphics.image.LosslessFactory;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSignDesigner;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSigProperties;

import java.awt.Color;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.util.EnumMap;
import java.util.Map;

/**
 * Draws the visible Corporate Seal stamp (text + QR) at a located
 * {@code [[TSI_SIGNATURE:name]]} marker - see
 * prep/TSI-Sign-Visible-Signature-Placeholder-Plan.md.
 *
 * <p>Exactly one placeholder per document becomes the real interactive
 * {@code PDSignature} widget ({@link #buildSignatureAppearance}, merged in
 * by PDFBox's own {@code PDDocument.addSignature}/{@code
 * SignatureOptions.setVisualSignature} mechanism); any additional named
 * placeholders are drawn as plain, non-interactive overlay images
 * ({@link #drawOverlayStamp}) - the CMS signature covers the whole document
 * either way, regardless of how many visible stamps are drawn.
 */
public class VisibleSignatureStamper {

    public static final float STAMP_WIDTH_PT = 220f;
    public static final float STAMP_HEIGHT_PT = 70f;

    private static final int SCALE = 3;

    private VisibleSignatureStamper() {
    }

    /**
     * Self-contained, scannable QR payload - labeled key:value lines, one per
     * field, readable offline with no app or server round-trip (the same
     * "self-contained, offline-verifiable" spirit as GST e-way bills' QR
     * spec, which is one of Corporate Seal's own named use cases - just
     * without that spec's GSTIN-specific fields, which don't apply here).
     * Encodes the original (pre-seal) document hash, since the sealed
     * file's own hash doesn't exist yet at the point the stamp is drawn.
     */
    public static String buildQrPayload(String documentTitle, String documentId, String documentHash,
            String keyAlias, String reason, String sealedAtIso) {
        return "TSI Sign Corporate Seal\n" +
                "Document: " + documentTitle + "\n" +
                "Document ID: " + documentId + "\n" +
                "Doc SHA-256: " + documentHash + "\n" +
                "Sealed By: " + keyAlias + "\n" +
                "Reason: " + reason + "\n" +
                "Sealed At: " + sealedAtIso;
    }

    /**
     * Builds the visual signature properties for the one placeholder that will carry the
     * real cryptographic signature - hand this to {@code SignatureOptions.setVisualSignature(...)}.
     */
    public static PDVisibleSigProperties buildSignatureAppearance(PDDocument document,
            SignaturePlaceholderLocator.Placement placement, String fieldName,
            String signerLine, String reasonLine, String dateLine, String qrPayload) throws Exception {
        BufferedImage stamp = composeStampImage(signerLine, reasonLine, dateLine, qrPayload);

        float pageHeight = document.getPage(placement.pageIndex()).getMediaBox().getHeight();
        PDVisibleSignDesigner designer = new PDVisibleSignDesigner(document, stamp, placement.pageIndex() + 1);
        designer.xAxis(placement.x())
                .yAxis(pageHeight - placement.y())
                .width(STAMP_WIDTH_PT)
                .height(STAMP_HEIGHT_PT)
                .signatureFieldName(fieldName);

        PDVisibleSigProperties properties = new PDVisibleSigProperties();
        properties.signerName(signerLine)
                .signatureReason(reasonLine)
                .page(placement.pageIndex() + 1)
                .visualSignEnabled(true)
                .setPdVisibleSignature(designer)
                .buildSignature();
        return properties;
    }

    /** Draws the same stamp as a plain overlay image on a page that isn't carrying the real signature widget. */
    public static void drawOverlayStamp(PDDocument document, SignaturePlaceholderLocator.Placement placement,
            String signerLine, String reasonLine, String dateLine, String qrPayload) throws Exception {
        BufferedImage stamp = composeStampImage(signerLine, reasonLine, dateLine, qrPayload);
        PDPage page = document.getPage(placement.pageIndex());
        PDImageXObject imageXObject = LosslessFactory.createFromImage(document, stamp);
        try (PDPageContentStream cs = new PDPageContentStream(document, page,
                PDPageContentStream.AppendMode.APPEND, true, true)) {
            cs.drawImage(imageXObject, placement.x(), placement.y() - STAMP_HEIGHT_PT, STAMP_WIDTH_PT, STAMP_HEIGHT_PT);
        }
        // COSDictionary mutations on pre-existing objects (the page's /Contents
        // and /Resources here) aren't auto-tracked - saveIncremental() only
        // rewrites objects with setNeedToBeUpdated(true), so without this the
        // appended image reference would silently be dropped from the output.
        page.getCOSObject().setNeedToBeUpdated(true);
        page.getResources().getCOSObject().setNeedToBeUpdated(true);
    }

    private static BufferedImage composeStampImage(String signerLine, String reasonLine, String dateLine,
            String qrPayload) throws WriterException {
        int width = (int) (STAMP_WIDTH_PT * SCALE);
        int height = (int) (STAMP_HEIGHT_PT * SCALE);
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = image.createGraphics();
        try {
            g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g.setColor(Color.WHITE);
            g.fillRect(0, 0, width, height);
            g.setColor(Color.BLACK);
            g.drawRect(0, 0, width - 1, height - 1);

            int qrSize = height - 2 * SCALE * 4;
            BufferedImage qr = renderQr(qrPayload, qrSize);
            int qrX = width - qrSize - SCALE * 6;
            int qrY = (height - qrSize) / 2;
            g.drawImage(qr, qrX, qrY, null);

            int textRight = qrX - SCALE * 4;
            g.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 7 * SCALE));
            g.drawString("Digitally Signed", SCALE * 5, SCALE * 14);
            g.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 6 * SCALE));
            drawClipped(g, signerLine, SCALE * 5, SCALE * 28, textRight);
            drawClipped(g, reasonLine, SCALE * 5, SCALE * 41, textRight);
            drawClipped(g, dateLine, SCALE * 5, SCALE * 54, textRight);
        } finally {
            g.dispose();
        }
        return image;
    }

    private static void drawClipped(Graphics2D g, String text, int x, int y, int maxX) {
        FontMetrics fm = g.getFontMetrics();
        String s = text;
        while (fm.stringWidth(s) > (maxX - x) && s.length() > 4) {
            s = s.substring(0, s.length() - 4) + "...";
        }
        g.drawString(s, x, y);
    }

    private static BufferedImage renderQr(String payload, int size) throws WriterException {
        Map<EncodeHintType, Object> hints = new EnumMap<>(EncodeHintType.class);
        hints.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.M);
        hints.put(EncodeHintType.MARGIN, 0);
        QRCodeWriter writer = new QRCodeWriter();
        BitMatrix matrix = writer.encode(payload, BarcodeFormat.QR_CODE, size, size, hints);
        BufferedImage image = new BufferedImage(size, size, BufferedImage.TYPE_INT_RGB);
        for (int x = 0; x < size; x++) {
            for (int y = 0; y < size; y++) {
                image.setRGB(x, y, matrix.get(x, y) ? 0x000000 : 0xFFFFFF);
            }
        }
        return image;
    }
}
