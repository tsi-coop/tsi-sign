-- Multi-Signature Documents (docs/architecture.md §6.4)
--
-- A document that has collected one of several independent signers' seals
-- but not all of them yet is neither DRAFT (nothing signed) nor SIGNED
-- (fully executed) nor PENDING (a different, narrower meaning already
-- claimed for "one Aadhaar eSign session is in flight"). New state:
-- DRAFT -(first signer completes)-> PARTIALLY_SIGNED -> (last outstanding
-- signer completes) -> SIGNED.

ALTER TABLE documents DROP CONSTRAINT documents_status_check;
ALTER TABLE documents ADD CONSTRAINT documents_status_check
    CHECK (status IN ('DRAFT', 'PENDING', 'PARTIALLY_SIGNED', 'SIGNED', 'EXPIRED'));

-- One document_signers row per (document, marker) pair going forward - a
-- signer discovered via a [[TSI_SIGNATURE:name]] marker (or claimed by a
-- later signer's turn) must resolve to exactly one row, never a duplicate.
ALTER TABLE document_signers ADD CONSTRAINT uq_document_signers_anchor
    UNIQUE (document_id, anchor_element_id);
