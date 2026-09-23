package org.tsicoop.sign.service.v1;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.tsicoop.sign.pki.SignaturePlaceholderLocator;

import java.util.Map;

/**
 * Pre-registers a PENDING/UNASSIGNED {@code document_signers} row for every
 * named {@code [[TSI_SIGNATURE:name]]} marker found in a document's PDF at
 * creation time (docs/architecture.md §6.4).
 *
 * <p>Without this, {@code document_signers} stayed empty until the first
 * seal/eSign call created a row as a side effect - so the console's
 * `document-detail.html` (which only shows the per-signer row list once
 * {@code signers.length > 0}) fell back to its single global "Apply
 * Corporate Seal" button even for a template with multiple markers. That
 * button calls {@code seal_local} with no {@code signerName}, which takes
 * the legacy "stamp every marker as one signer's operation" path and seals
 * the whole document in one shot - silently skipping the per-marker,
 * independent-signer flow the template author asked for. Calling this
 * right after the document is stored makes the markers visible immediately,
 * so the console shows one row per signer from the start and every seal
 * action is scoped to a single marker.
 */
public class SignerDiscoveryService {

    private final DocumentSignerRepository documentSignerRepository;

    public SignerDiscoveryService(DocumentSignerRepository documentSignerRepository) {
        this.documentSignerRepository = documentSignerRepository;
    }

    /** A document with no markers at all is left untouched - the existing implicit single-signer flow already handles that correctly. */
    public void discoverMarkers(String documentId, byte[] pdfBytes) throws Exception {
        Map<String, SignaturePlaceholderLocator.Placement> markers;
        try (PDDocument doc = PDDocument.load(pdfBytes)) {
            markers = SignaturePlaceholderLocator.locate(doc);
        }
        for (String name : markers.keySet()) {
            if (documentSignerRepository.findByAnchor(documentId, name).isEmpty()) {
                documentSignerRepository.create(documentId, name, null, null, "UNASSIGNED", name);
            }
        }
    }
}
