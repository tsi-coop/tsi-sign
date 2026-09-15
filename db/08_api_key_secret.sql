-- API key + secret pair, replacing the single opaque key - the shared
-- tenant-credential shape used across the TSI stack (tsi-ledger's `apps`
-- table is the canonical reference; tsi-nexus mirrors it). api_key is a
-- non-secret public identifier, shown/returned always, used as the direct
-- lookup key on each request. api_secret_hash is a SHA-256 hex digest of
-- the real secret - never the secret itself - compared against the hash of
-- whatever the caller presents in X-API-Secret.
--
-- Pre-existing rows were single opaque tokens (only their hash was ever
-- stored, per the old key_hash column) and cannot be split into a
-- key+secret pair retroactively, so they're deleted here - any App still
-- using one must reissue a new key+secret pair from the console.
ALTER TABLE api_keys ADD COLUMN api_key VARCHAR(80);
ALTER TABLE api_keys ADD COLUMN api_secret_hash CHAR(64);
DELETE FROM api_keys WHERE key_hash IS NOT NULL;
ALTER TABLE api_keys DROP COLUMN key_hash;
ALTER TABLE api_keys DROP COLUMN key_prefix;
ALTER TABLE api_keys ALTER COLUMN api_key SET NOT NULL;
ALTER TABLE api_keys ALTER COLUMN api_secret_hash SET NOT NULL;
ALTER TABLE api_keys ADD CONSTRAINT uq_api_keys_api_key UNIQUE (api_key);

DROP INDEX IF EXISTS idx_api_keys_hash;
CREATE INDEX idx_api_keys_key ON api_keys(api_key) WHERE is_active = TRUE;
