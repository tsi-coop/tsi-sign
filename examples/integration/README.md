# TSI Sign - API integration demo scripts

Runnable scripts that walk through the full lifecycle any integrating App
follows over the TSI Sign HTTP API - register templates, generate documents
from them, then sign whichever one you want to try - using the sample
templates/payloads in `../templates/` and `../payloads/`. No shortcuts into
the database, and no admin console session used by any script here (modeled
on `tsi-ledger/examples`, adapted to TSI Sign's TENANT/App auth).

## Prerequisites

- A running instance: `docker compose up -d` from the repo root, reachable
  at `http://localhost:8088` (override with `BASE_URL`).
- `bash`, `curl`, `jq`.

## One-time setup (by hand, in the console)

These scripts pick up *after* an App exists - creating one requires a
Platform Admin console session, which is intentionally not scripted here.

1. Complete the initial setup wizard at `http://localhost:8088/console` and
   log in as the Platform Admin.
2. On the Apps page, create an App (e.g. name it "Sign Demo"). Copy its
   `API_KEY` and `API_SECRET` when they're shown - `API_SECRET` is shown
   once and can't be retrieved again; `API_KEY` stays visible on the Apps
   page any time.
3. Leave `defaultKeyAlias` unset. With no `keyAlias` on `seal_local` and no
   `default_key_alias` configured on the App, sealing falls back to the dev
   keystore's `tsi_corporate_seal` alias baked into the Dockerfile - so
   signing works immediately, with zero per-App PKI setup.

## Scripts

Scripts 1 and 2 are bulk setup - they build the catalog of sample templates
and documents you get to choose from. Scripts 3 and 4 sign **one document
(and, for a multisig document, one signer) per run** - pick which one you
want to experience, rather than everything signing at once.

| # | Script | Calls | Does |
|---|--------|-------|------|
| 1 | `1_register_templates.sh` | `templates` / `create_template` | Registers all 6 sample templates from `../templates/` |
| 2 | `2_create_documents.sh` | `templates` / `generate_document` | Renders each template with its matching `../payloads/*.json`, producing a DRAFT PDF per document |
| 3 | `3_sign_documents.sh <document-key> [signerName]` | `documents` / `seal_local` | Seals the one document/signer you name, via **Corporate Seal** |
| 4 | `4_sign_via_aadhaar_esign.sh <document-key> [signerName]` | `documents` / `initiate_esign`, then opens your browser for the consent step, then polls `documents` / `get_esign_status` | Signs the one document/signer you name, via **Aadhaar eSign** |

### Document keys and signers

| `<document-key>` | `signerName` |
|---|---|
| `nda-mutual` | `party_a` or `party_b` (required - multisig) |
| `loan-agreement` | `lender` or `borrower` (required - multisig) |
| `experience-certificate` | omit (single signer) |
| `offer-letter` | omit (single signer) |
| `rental-agreement` | omit (single signer) |
| `consulting-services-agreement` | omit (single signer) |

Run either script with no arguments to print this list.

```bash
export API_KEY='key_...' API_SECRET='sk_...'   # the App from setup above
./1_register_templates.sh
./2_create_documents.sh

# Now pick whatever you want to try:
./3_sign_documents.sh offer-letter                    # Corporate Seal, single signer - completes immediately
./4_sign_via_aadhaar_esign.sh rental-agreement         # Aadhaar eSign, single signer - opens your browser, then waits for your click
./3_sign_documents.sh nda-mutual party_a               # Corporate Seal for one signer...
./4_sign_via_aadhaar_esign.sh nda-mutual party_b       # ...Aadhaar eSign for the other
```

Each script prints what it did and passes IDs to the next one via a local
`.state.json` file in this directory (not committed - see below) - you don't
need to copy any IDs by hand.

## Why no appId or console session anywhere here

Every call above authenticates with `X-API-Key`/`X-API-Secret` (TENANT
auth). `Templates` and `Documents` are `TENANT_OR_CONSOLE` Actions - a
`TENANT` caller's App is resolved from the API key itself
(`InputProcessor.getAppContext`), so unlike a console/admin call these
bodies never need an explicit `appId`. This is the same `_func`-dispatch,
`POST /api/v1/<resource>` convention used by `tsi-ledger`, `tsi-dpdp-cms`
and `tsi-privacy-vault` - see `_processor.tsi` and `Action`/
`InterceptingFilter` in `src/org/tsicoop/sign/framework/`.

## Multisig signing

`nda-mutual` and `loan-agreement` each have two `[[TSI_SIGNATURE:name]]`
markers (`party_a`/`party_b`, `lender`/`borrower`). Each signer seals
independently - run script 3 or 4 once per signer, in either order, mixing
signature types freely (e.g. one signer via Corporate Seal, the other via
Aadhaar eSign). The document status moves `DRAFT` -> `PARTIALLY_SIGNED`
once one signer has completed, then `SIGNED` once both have. The other four
sample documents have a single anonymous `[[TSI_SIGNATURE]]` marker
(`signerName` "default" internally), so no `signerName` argument is needed
for them with script 3; script 4 still needs one internally since
`initiate_esign` always requires it, so it fills in "default" for you.

## Aadhaar eSign is human-in-the-loop - the script sends you to the browser

Unlike `seal_local`, Aadhaar eSign is a genuinely three-step, human-in-the-
loop flow, and `4_sign_via_aadhaar_esign.sh` walks through all three rather
than shortcutting any of them:

1. `initiate_esign` (documentId, signerName) doesn't sign anything itself -
   it returns a `gatewayUrl` + `transactionId`. The script prints this URL
   and best-effort opens it in your default browser (`xdg-open`/`open`/
   `wslview`, whichever is on your PATH) - if none of those work in your
   environment (e.g. a headless container or a remote SSH session), just
   copy the printed URL into a browser yourself.
2. You land on the mock consent screen
   (`web/console/mock-esign-consent.html`) - a real ESP would show its own
   real OTP/biometric screen here instead - and click **Approve & Sign**
   (or **Deny**). That click is what calls the `PUBLIC` `esign/callback`
   endpoint's `mock_approve`/`mock_deny` func and actually splices the
   signature into the PDF - the script itself never calls it.
3. The script polls `get_esign_status` (every `POLL_INTERVAL_SECONDS`,
   default 3s, for up to `POLL_TIMEOUT_SECONDS`, default 300s) until your
   click lands, then prints the final signer/document status.

If you let it time out before clicking anything, the eSign session is still
open - reopen the printed URL to finish (don't re-run the script while a
session is pending; `initiate_esign` 409s on top of an active one).

Because `gatewayUrl` is built from `CONSOLE_BASE_URL` (default
`http://localhost:8088/console`, same default as this script's `BASE_URL`),
this works out of the box for a local instance. If your instance runs
somewhere the browser opening this URL can't reach directly (a remote
Docker host, a devcontainer), set `CONSOLE_BASE_URL` on the server to a
hostname that machine can resolve before calling `initiate_esign`.

## Re-running

`create_template` and `generate_document` aren't idempotent - re-running
scripts 1/2 registers fresh templates and documents rather than skipping
existing ones, and `.state.json` is overwritten with the newest IDs each
time. `seal_local`/`initiate_esign` on an already-`SIGNED` document (or an
already-signed named signer) fails with a 409 Conflict by design - delete
`.state.json` and start over from script 1 for a clean re-run.
