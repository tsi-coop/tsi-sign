package org.tsicoop.sign.pki;

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
import java.util.ArrayList;
import java.util.List;

/**
 * Draws the visible Corporate Seal stamp (a plain text block: signer,
 * who triggered it, reason, date) at a located
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
    public static final float STAMP_HEIGHT_PT = 80f;

    private static final int SCALE = 3;

    private VisibleSignatureStamper() {
    }

    /**
     * Builds the visual signature properties for the one placeholder that will carry the
     * real cryptographic signature - hand this to {@code SignatureOptions.setVisualSignature(...)}.
     */
    public static PDVisibleSigProperties buildSignatureAppearance(PDDocument document,
            SignaturePlaceholderLocator.Placement placement, String fieldName,
            String signerLine, String signedByLine, String reasonLine, String dateLine) throws Exception {
        BufferedImage stamp = composeStampImage(signerLine, signedByLine, reasonLine, dateLine);

        // PDVisibleSignDesigner.yAxis() already expects a top-down offset (distance
        // from the top of the page) - PDVisibleSigBuilder.createSignatureRectangle
        // internally computes templateHeight - yAxis to get the real PDF (bottom-up)
        // rectangle. placement.y() (from SignaturePlaceholderLocator/PDFTextStripper)
        // is already top-down, so it must be passed through as-is: subtracting it from
        // pageHeight here double-flips it, mirroring the stamp to the wrong marker
        // when a document has more than one placeholder at different heights.
        PDVisibleSignDesigner designer = new PDVisibleSignDesigner(document, stamp, placement.pageIndex() + 1);
        designer.xAxis(placement.x())
                .yAxis(placement.y())
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
            String signerLine, String signedByLine, String reasonLine, String dateLine) throws Exception {
        BufferedImage stamp = composeStampImage(signerLine, signedByLine, reasonLine, dateLine);
        PDPage page = document.getPage(placement.pageIndex());
        // drawImage() takes native PDF (bottom-up) coordinates, but placement.y() is
        // top-down (see buildSignatureAppearance) - convert, then drop by the stamp's
        // height so the marker position is the top-left corner of the stamp, matching
        // buildSignatureAppearance's convention.
        float pageHeight = page.getMediaBox().getHeight();
        float bottomUpY = pageHeight - placement.y() - STAMP_HEIGHT_PT;
        PDImageXObject imageXObject = LosslessFactory.createFromImage(document, stamp);
        try (PDPageContentStream cs = new PDPageContentStream(document, page,
                PDPageContentStream.AppendMode.APPEND, true, true)) {
            cs.drawImage(imageXObject, placement.x(), bottomUpY, STAMP_WIDTH_PT, STAMP_HEIGHT_PT);
        }
        // COSDictionary mutations on pre-existing objects (the page's /Contents
        // and /Resources here) aren't auto-tracked - saveIncremental() only
        // rewrites objects with setNeedToBeUpdated(true), so without this the
        // appended image reference would silently be dropped from the output.
        page.getCOSObject().setNeedToBeUpdated(true);
        page.getResources().getCOSObject().setNeedToBeUpdated(true);
    }

    private static BufferedImage composeStampImage(String signerLine, String signedByLine,
            String reasonLine, String dateLine) {
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

            int textRight = width - SCALE * 5;
            g.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 7 * SCALE));
            g.drawString("Digitally Signed", SCALE * 5, SCALE * 14);

            g.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 6 * SCALE));
            List<String> lines = new ArrayList<>();
            lines.add(signerLine);
            if (signedByLine != null && !signedByLine.isBlank()) {
                lines.add(signedByLine);
            }
            lines.add(reasonLine);
            lines.add(dateLine);

            int y = SCALE * 28;
            for (String line : lines) {
                drawClipped(g, line, SCALE * 5, y, textRight);
                y += SCALE * 13;
            }
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
}
