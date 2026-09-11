-- Chunk 6, §9.2: Legal Evidence Support (BSA §63). version supports
-- re-generation after a document is re-sealed (e.g. counter-signed) —
-- §9.4 requires a new certificate version rather than mutating the sealed
-- original, so (document_id, version) rows accumulate instead of updating
-- in place.
CREATE TABLE legal_certificates (
    certificate_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id             UUID NOT NULL REFERENCES documents(document_id) ON DELETE CASCADE,
    app_id                  UUID NOT NULL REFERENCES apps(app_id),
    version                 INT NOT NULL DEFAULT 1,
    part_a                  JSONB NOT NULL,
    part_b                  JSONB NOT NULL,
    certifying_officer_id   UUID REFERENCES platform_users(user_id),
    certificate_hash        VARCHAR(64) NOT NULL,
    storage_provider_id     VARCHAR(50) NOT NULL,
    certificate_storage_key TEXT NOT NULL,
    sealed_at               TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_legal_certificates_document_version UNIQUE (document_id, version)
);
CREATE INDEX idx_legal_certificates_document ON legal_certificates(document_id);
