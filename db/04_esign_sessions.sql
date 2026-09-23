-- TSI Aadhaar eSign — transient session state for the async, redirect-based
-- signing flow (see README "eSign providers"). Kept separate from
-- the audit-facing document_signers/document_seals tables (V1): this table
-- only exists to survive the gap between "we reserved a signature slot and
-- sent the hash to the ESP" and "the ESP called us back" — it holds the
-- prepared (placeholder-signature) PDF bytes' storage key and the exact
-- byte range PDFBox reserved, since neither a live PDDocument nor an
-- in-memory object can be assumed to survive that gap (may be minutes,
-- may cross a server restart).
CREATE TABLE esign_sessions (
    session_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id           UUID NOT NULL REFERENCES documents(document_id) ON DELETE CASCADE,
    signer_id             UUID NOT NULL REFERENCES document_signers(signer_id) ON DELETE CASCADE,
    provider_id            VARCHAR(50) NOT NULL,        -- sandbox | emudhra | cdac | ...
    transaction_id          VARCHAR(255) NOT NULL,
    prepared_storage_key    TEXT NOT NULL,               -- placeholder-PDF bytes, via DocumentStorageProvider
    byte_range_0            BIGINT NOT NULL,
    byte_range_1            BIGINT NOT NULL,
    byte_range_2            BIGINT NOT NULL,
    byte_range_3            BIGINT NOT NULL,
    signature_field_name    VARCHAR(100) NOT NULL,
    status                  VARCHAR(30) NOT NULL DEFAULT 'INITIATED'
                            CHECK (status IN ('INITIATED', 'COMPLETED', 'FAILED', 'EXPIRED')),
    gateway_url             TEXT,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at            TIMESTAMPTZ
);
CREATE INDEX idx_esign_sessions_document ON esign_sessions(document_id);
CREATE UNIQUE INDEX idx_esign_sessions_txn ON esign_sessions(provider_id, transaction_id);
