package org.tsicoop.sign.pki;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.text.PDFTextStripper;
import org.apache.pdfbox.text.TextPosition;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Scans a rendered PDF for {@code [[TSI_SIGNATURE:<name>]]} markers - plain
 * literal text a template author types directly into the HTML template (see
 * prep/TSI-Sign-Visible-Signature-Placeholder-Plan.md) - and records where
 * each named marker landed, so {@link LocalPkiSigningService} can stamp a
 * visible Corporate Seal appearance at that spot. {@code [[TSI_SIGNATURE]]}
 * (no name) is shorthand for {@code [[TSI_SIGNATURE:default]]}.
 *
 * <p>Anchors are the top-left of the marker glyphs, in raw PDF user-space
 * coordinates (bottom-left origin) - obtained from {@link TextPosition}'s
 * text matrix, which matches PDF space directly for the unrotated pages
 * {@code OpenHtmlToPdfGeneratorServiceImpl} produces.
 */
public class SignaturePlaceholderLocator extends PDFTextStripper {

    public record Placement(int pageIndex, float x, float y) {
    }

    private static final Pattern MARKER_PATTERN =
            Pattern.compile("\\[\\[TSI_SIGNATURE(?::([A-Za-z0-9_-]+))?]]");

    private final Map<String, Placement> placements = new LinkedHashMap<>();
    private StringBuilder pageText;
    private List<TextPosition> pagePositions;

    public SignaturePlaceholderLocator() throws IOException {
        setSortByPosition(true);
    }

    /** Runs the locator over the whole document and returns every named marker found, in reading order. */
    public static Map<String, Placement> locate(PDDocument document) throws IOException {
        SignaturePlaceholderLocator locator = new SignaturePlaceholderLocator();
        locator.getText(document);
        return locator.placements;
    }

    @Override
    protected void startPage(PDPage page) throws IOException {
        pageText = new StringBuilder();
        pagePositions = new ArrayList<>();
    }

    @Override
    protected void writeString(String text, List<TextPosition> textPositions) throws IOException {
        pageText.append(text);
        pagePositions.addAll(textPositions);
    }

    @Override
    protected void endPage(PDPage page) throws IOException {
        int pageIndex = getCurrentPageNo() - 1;
        Matcher matcher = MARKER_PATTERN.matcher(pageText);
        while (matcher.find()) {
            String name = matcher.group(1) != null ? matcher.group(1) : "default";
            int start = matcher.start();
            if (start < pagePositions.size()) {
                TextPosition anchor = pagePositions.get(start);
                placements.putIfAbsent(name, new Placement(pageIndex, anchor.getX(), anchor.getY()));
            }
        }
    }
}
