-- TSI Sign — core schema (Chunk 1, plan §4.1 / §5.2 / §5.3)
--
-- PostgreSQL 15. gen_random_uuid() is built in since PG13, so no uuid-ossp
-- extension is needed (the plan doc's uuid_generate_v4() reference predates
-- this; TSI Ledger's own shipped schema made the same simplification).
--
-- This is the "apps-first" schema: there is no organizations table anywhere.
-- documents ships directly with the storage-provider columns from §5.3
-- (storage_provider_id / original_storage_key / sealed_storage_key) instead
-- of the file_path column shown first in §4.1, which §5.3 explicitly
-- supersedes before anything ships.

-- 1. APPS — top-level scoping entity, replaces "organizations" (§4.1, §5.2)
CREATE TABLE apps (
    app_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_name            VARCHAR(255) NOT NULL,
    app_slug            VARCHAR(100) NOT NULL UNIQUE,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    default_provider_id VARCHAR(50),
    default_key_alias   VARCHAR(255),
    storage_provider_id VARCHAR(50),          -- NULL = use deployment-wide default (§5.2)
    webhook_url         TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 2. API KEYS — separate table (not a column on apps) so a key can be
-- rotated/revoked without regenerating the App's identity (§4.2).
CREATE TABLE api_keys (
    key_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id      UUID NOT NULL REFERENCES apps(app_id) ON DELETE CASCADE,
    key_hash    VARCHAR(64) NOT NULL UNIQUE,   -- SHA-256 hex of the raw key; raw key shown once
    key_prefix  VARCHAR(12) NOT NULL,          -- e.g. "sk_9f2a...", for display/audit only
    is_active   BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at  TIMESTAMPTZ
);
CREATE INDEX idx_api_keys_hash ON api_keys(key_hash) WHERE is_active = TRUE;
CREATE INDEX idx_api_keys_app ON api_keys(app_id);

-- 3. PLATFORM USERS — internal ops/admin console users (§4.1). Not per-App
-- end users; those only ever authenticate via X-API-Key. password_hash is
-- nullable until Chunk 7 wires up console session auth and provisioning.
CREATE TABLE platform_users (
    user_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email         VARCHAR(255) NOT NULL UNIQUE,
    full_name     VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255),
    role          VARCHAR(50) NOT NULL DEFAULT 'APP_MANAGER'
                  CHECK (role IN ('PLATFORM_ADMIN', 'APP_MANAGER', 'AUDITOR')),
    is_active     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 4. APP <-> PLATFORM USER scoping — an APP_MANAGER may only administer the
-- specific Apps assigned here (§4.2, RBAC).
CREATE TABLE app_admins (
    app_id  UUID NOT NULL REFERENCES apps(app_id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES platform_users(user_id) ON DELETE CASCADE,
    PRIMARY KEY (app_id, user_id)
);

-- 5. TEMPLATES — namespaced per App, not global (§4.2).
CREATE TABLE templates (
    template_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id        UUID NOT NULL REFERENCES apps(app_id) ON DELETE CASCADE,
    template_name VARCHAR(255) NOT NULL,
    category      VARCHAR(100),
    html_content  TEXT NOT NULL,
    version       INT NOT NULL DEFAULT 1,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_app_template_name UNIQUE (app_id, template_name)
);

-- 6. DOCUMENTS — app_id replaces org_id; ships with the storage-provider
-- columns directly (§5.3) rather than the superseded file_path column.
CREATE TABLE documents (
    document_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id                UUID NOT NULL REFERENCES apps(app_id) ON DELETE CASCADE,
    template_id           UUID REFERENCES templates(template_id),
    title                 VARCHAR(255) NOT NULL,
    storage_provider_id   VARCHAR(50) NOT NULL,   -- denormalized at write time (§5.3)
    original_storage_key  TEXT NOT NULL,
    sealed_storage_key    TEXT,                    -- NULL until signed
    original_hash         VARCHAR(64) NOT NULL,
    sealed_hash           VARCHAR(64),
    status                VARCHAR(30) NOT NULL DEFAULT 'DRAFT'
                          CHECK (status IN ('DRAFT', 'PENDING', 'SIGNED', 'EXPIRED')),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at            TIMESTAMPTZ
);
CREATE INDEX idx_documents_app ON documents(app_id, created_at DESC);
CREATE INDEX idx_documents_template ON documents(template_id);

-- 7. DOCUMENT SIGNERS — one row per party a document is routed to for
-- signature (Technical Architecture doc's SignerIdentity / signers[] shape).
CREATE TABLE document_signers (
    signer_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id       UUID NOT NULL REFERENCES documents(document_id) ON DELETE CASCADE,
    signer_order      INT NOT NULL DEFAULT 1,
    signer_name       VARCHAR(255) NOT NULL,
    signer_email      VARCHAR(255),
    signer_phone      VARCHAR(50),
    signature_type    VARCHAR(30) NOT NULL,        -- e.g. AADHAAR_OTP, LOCAL_PKI
    anchor_element_id VARCHAR(100),                -- ties to the template's tsi-signature-anchor div
    status            VARCHAR(30) NOT NULL DEFAULT 'PENDING'
                      CHECK (status IN ('PENDING', 'SIGNED', 'FAILED')),
    signed_at         TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_document_signers_document ON document_signers(document_id);

-- 8. DOCUMENT SEALS — one row per cryptographic seal applied to a document
-- (an external CA callback or a Local PKI keystore signature). Kept separate
-- from document_signers since a Local PKI corporate seal isn't tied to an
-- individual signer.
CREATE TABLE document_seals (
    seal_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id        UUID NOT NULL REFERENCES documents(document_id) ON DELETE CASCADE,
    signer_id          UUID REFERENCES document_signers(signer_id),
    provider_id        VARCHAR(50) NOT NULL,        -- emudhra | cdac | local_pki
    key_alias          VARCHAR(255),                -- set for local_pki seals
    transaction_id     VARCHAR(255),                -- set for external CA seals
    pkcs7_signature    TEXT,
    signature_standard VARCHAR(30),                 -- e.g. PAdES-B-B
    ca_issuer          VARCHAR(255),
    auth_type          VARCHAR(50),
    sealed_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_document_seals_document ON document_seals(document_id);

-- 9. AUDIT LOGS — full-lifecycle trail (§6). app_id is denormalized so
-- App-scoped queries stay fast even for rows not tied to one document
-- (key issuance/revocation, etc.); document_id is nullable for that reason.
CREATE TABLE audit_logs (
    audit_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id      UUID NOT NULL REFERENCES apps(app_id) ON DELETE CASCADE,
    document_id UUID REFERENCES documents(document_id) ON DELETE CASCADE,
    event_type  VARCHAR(100) NOT NULL,   -- e.g. DOCUMENT_CREATED, SEALED, KEY_ISSUED, KEY_REVOKED
    actor_type  VARCHAR(30) NOT NULL CHECK (actor_type IN ('APP', 'PLATFORM_USER', 'SYSTEM')),
    actor_id    UUID,
    ip_address  VARCHAR(64),
    user_agent  TEXT,
    metadata    JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_logs_app ON audit_logs(app_id, created_at DESC);
CREATE INDEX idx_audit_logs_document ON audit_logs(document_id);
