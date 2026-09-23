-- Tamper-evident audit trail: every audit_logs row records the SHA-256 of its own contents chained
-- to the previous row of the same App (prev_hash -> entry_hash), so editing, deleting or reordering
-- a recorded event breaks verification (console: Audit -> Verify integrity). Rows written before
-- this script have NULL hashes and are simply outside the chain. Databases created before this
-- script existed: run it by hand
-- (docker exec -i tsi_sign_postgres psql -U tsi_sign_admin tsi_sign < db/11_audit_hash_chain.sql).
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS seq BIGSERIAL;
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS prev_hash CHAR(64);
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS entry_hash CHAR(64);
CREATE INDEX IF NOT EXISTS idx_audit_logs_chain ON audit_logs(app_id, seq);
