-- Deployment-wide System Settings (storage backend config) - a console
-- screen for what was previously env-var-only (DEFAULT_STORAGE_PROVIDER_ID,
-- S3_*, PRIVACY_VAULT_*). Singleton row: "id BOOLEAN PRIMARY KEY DEFAULT
-- TRUE CHECK (id)" means at most one row can ever exist.
--
-- Every column is nullable with no default (aside from the id/updated_at
-- bookkeeping columns): NULL means "not configured via this screen, fall
-- back to the equivalent env var" - the same NULL-means-fallback convention
-- already used by apps.storage_provider_id (falls back to the deployment
-- default) and apps.default_key_alias (falls back to DEFAULT_KEY_ALIAS).
-- This lets a deployment keep working purely off env vars until an operator
-- explicitly saves something here, at which point the DB value wins.

CREATE TABLE system_settings (
    id                           BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    default_storage_provider_id VARCHAR(50),
    s3_endpoint                  TEXT,
    s3_region                    VARCHAR(50),
    s3_bucket                    VARCHAR(255),
    s3_access_key                TEXT,
    s3_secret_key                TEXT,
    s3_path_style_access         BOOLEAN,
    s3_sse                       VARCHAR(20),
    s3_kms_key_id                TEXT,
    privacy_vault_base_url       TEXT,
    privacy_vault_api_key        TEXT,
    privacy_vault_entity_code    VARCHAR(255),
    updated_at                   TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO system_settings (id) VALUES (TRUE);
