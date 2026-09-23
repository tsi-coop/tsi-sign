-- CCA eSign API: the signer's browser must POST a signed <Esign> request to the ESP, so the
-- session keeps that payload ({"actionUrl":..., "fields":{"msg":...}}) for the redirect page to
-- submit. Databases created before this script existed: run it by hand
-- (docker exec -i tsi_sign_postgres psql -U tsi_sign_admin tsi_sign < db/10_esign_gateway_payload.sql).
ALTER TABLE esign_sessions ADD COLUMN IF NOT EXISTS gateway_payload TEXT;
