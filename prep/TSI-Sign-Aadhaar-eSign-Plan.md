# TSI Aadhaar eSign - Third-Party / Individual Signatures

**Status: implemented (mock adapter).** `resources/db/migration/
V4__esign_sessions.sql`, `src/org/tsicoop/sign/esign/` (new package),
`DocumentSignerRepository`, `EsignCallback`, and `Documents.initiate_esign`/
`get_esign_status` are all in place. Verified end-to-end against the real
deployed container (not just library calls): `initiate_esign` over
X-API-Key → a genuinely separate, unauthenticated HTTP call to the mock
ESP's callback → `pdfsig` reports the sealed PDF's signature Valid, signed
by the mock ESP's own certificate (`CN=TSI Mock Aadhaar eSign CA`, distinct
from Corporate Seal's), with the visible stamp correctly showing "By:
Aadhaar eSign (Mock ESP)" / "Signed by: `<signer name>`" - reusing
`SignaturePlaceholderLocator`/`VisibleSignatureStamper` completely unchanged,
exactly as planned. Deny/retry, double-approve rejection, cross-tenant
authorization, and best-effort webhook dispatch (a broken `webhook_url`
doesn't fail the signing transaction) were all exercised too.

Two real bugs surfaced only during this end-to-end verification, both
fixed:
1. `audit_logs.actor_type` has a `CHECK (... IN ('APP','PLATFORM_USER',
   'SYSTEM'))` and `actor_id` is a `UUID` column - the first cut logged the
   ESP's completion event with `actor_type='ESP'` and `actor_id='mock_
   aadhaar'` (a provider slug, not a UUID), which the CHECK/column type
   both reject. Fixed to `'SYSTEM'` + the signer's real UUID.
2. `get_esign_status` initially had no authorization check at all - a
   TENANT caller could pass *any* `appId` (not just their own) and read
   that App's document status. Fixed to follow the same
   `appContext`-or-`canRead` branch every other dual-mode func
   (`seal_local`, `initiate_esign`) already uses.

## Use Case Classification

**Aadhaar eSign (OTP & Biometric)**

- **Legal Status:** Recognized as an Electronic Signature under Section 3A of
  the IT Act, 2000 (Second Schedule).
- **Certificate Authority:** Issued on-demand by a Controller of Certifying
  Authorities (CCA)-licensed eSign Service Provider (ESP) - e.g. eMudhra,
  C-DAC, NSDL.
- **Leegality Equivalence:** Aadhaar OTP / Biometric eSign.
- **Phase 1 Implementation for tsi-sign:** Direct API integration with a
  CCA-licensed ESP or C-DAC gateway.
- **Flow:** Hash of the PDF sent to ESP → user enters OTP / scans fingerprint
  → ESP returns a signed X.509 certificate → tsi-sign embeds it into the PDF
  structure.
- **Primary Use Cases:** Client onboarding documents, vendor agreements, NDA
  execution, HR letters, loan agreements.

## Context

This is the sibling feature to **TSI Corporate Seal** (`prep/TSI-Sign-
Visible-Signature-Placeholder-Plan.md`, implemented): Corporate Seal proved
the org-level, self-signed, synchronous, zero-human-interaction path.
Aadhaar eSign is the opposite in every one of those dimensions - a
*specific person's* legally binding signature, issued by an *external*
CCA-licensed authority, via an *asynchronous, redirect-based* flow requiring
that person to actually authenticate with OTP or biometrics.

This isn't a from-scratch design - `prep/TSI-Sign-Apps-Implementation-
Plan.md` already anticipated almost exactly this (§7, §9.7 references,
Chunk 10 "eSign Adapter framework + eMudhra adapter *(deferred - external
CA)*"), and the **schema already has most of what's needed, sitting
unused**:

- `document_signers` (one row per party routed for signature: name, email,
  phone, `signature_type` already including `'AADHAAR_OTP'`, `status`
  `PENDING/SIGNED/FAILED`) - has zero Java code touching it today (verified:
  no repository class exists for it).
- `document_seals` already has `provider_id` (`emudhra | cdac | local_pki`),
  `transaction_id`, `pkcs7_signature`, `ca_issuer`, `auth_type` - built for
  exactly this, currently only populated with `local_pki` rows.
- `documents.status` already allows `PENDING` (currently unused by any code
  path - `seal_local` only ever produces `DRAFT`→`SIGNED`) and `EXPIRED`
  (also unused) - `PENDING` is exactly "awaiting the ESP callback",
  `EXPIRED` is exactly "signer never completed OTP in time."
- `apps.webhook_url` is fully stored and editable (console's Signing
  Defaults tab) but **never actually called by any code** - it's the
  ready-made hook for telling an App "your signer finished" once the
  callback lands, since the App's own end-user (not a console operator) is
  the one who went off to the ESP's site.

So this plan is much more "wire up what's already there" than "invent new
architecture," with one real gap: the original plan's sequence diagram
(§7) doesn't go down to the PDF-library level of how you sign a document
*asynchronously* across two separate HTTP requests - that's the one part
that needed real technical verification, done below.

## What's reused vs. what's new

**Reused as-is:**
- `SignaturePlaceholderLocator` and `VisibleSignatureStamper`
  (`src/org/tsicoop/sign/pki/`) - the `[[TSI_SIGNATURE:name]]` marker and
  visible-stamp drawing built for Corporate Seal are signer-agnostic; they
  don't care whether the CMS bytes came from a local BouncyCastle signer or
  an external ESP. **Decision:** this supersedes the schema's older
  `document_signers.anchor_element_id` idea (a "tsi-signature-anchor div"
  concept from the original plan doc that was never built) - one marker
  convention for both Corporate Seal and Aadhaar eSign, not two.
- `document_seals`, `document_signers`, `apps.webhook_url` tables/columns -
  already shaped correctly, just need Java code to populate them.
- The existing `documents` status machine (`DRAFT → PENDING → SIGNED`, or
  `→ EXPIRED` on timeout) - no migration needed there.

**New:**
- An `ESignAdapter` interface + DTOs (`org.tsicoop.sign.esign`), per the
  original plan's §7 design.
- The actual two-phase async signing mechanics (new - see below).
- A **mock adapter** standing in for a real eMudhra/C-DAC integration,
  since this deployment has no CCA-licensed ESP credentials (same reason
  Corporate Seal ships a self-signed dev cert: zero-setup local
  demonstrability). A real adapter is a drop-in later, same interface.
- One new table, `esign_sessions` (below) - transient/operational state
  for the in-flight redirect wait, kept separate from the audit-facing
  `document_signers`/`document_seals`.
- New API funcs + one `PUBLIC` callback endpoint.
- Webhook dispatch to `apps.webhook_url` on completion.

## The hard part: signing across two HTTP requests

Corporate Seal signs synchronously - one method call, BouncyCastle computes
the CMS bytes immediately, done. Aadhaar eSign cannot: the document hash has
to be sent to the ESP, the *signer* (an external individual, not our
server) completes OTP/biometric on the **ESP's own site**, and only then
does the ESP call us back with the signature - seconds to several minutes
later, on a different HTTP request, quite possibly a different server
instance.

I checked PDFBox 3.0.6's own source for the supported mechanism
(`PDDocument.saveIncrementalForExternalSigning()` /
`ExternalSigningSupport`, in `org.apache.pdfbox.pdmodel.interactive.
digitalsignature`). Its documented usage pattern keeps the `PDDocument`,
the `OutputStream`, and the `ExternalSigningSupport` object all alive in
one unbroken call chain (`getContent()` → sign → `setSignature()` →
`close()`) - it's built for a synchronous remote-signing call (e.g. an
in-process HSM round-trip), **not** for surviving a real HTTP redirect
gap. Holding a live `PDDocument` in memory across a user's OTP entry isn't
viable (server restarts, multiple instances, minutes-long real-world
delay).

**The approach that does survive that gap** (the standard technique for
this exact problem, following directly from the PDF/PAdES byte-range
signing spec rather than any PDFBox convenience wrapper):

1. **Prepare** (`initiate_esign`, synchronous): call `document.addSignature
   (signature, signatureOptions)` with a generously-sized reserved
   signature placeholder (`SignatureOptions.setPreferredSignatureSize`),
   write the incremental update to a plain byte array. That array is a
   complete, well-formed PDF with an all-zero placeholder sitting where the
   real CMS signature will eventually go, plus a known `ByteRange`
   (4 integers PDFBox already computed marking exactly where that
   placeholder sits). **Persist that byte array + the 4 `ByteRange`
   integers** - not any live PDFBox object - via the existing
   `DocumentStorageProvider`, keyed to a new `esign_sessions` row. The
   "content to hash" is trivially derivable from those same 4 integers
   (everything but the placeholder span) without needing `PDDocument` open at
   all.
2. Send that hash to the ESP adapter's `initiateSigning()`, get back a
   `transactionId` + `gatewayUrl` (or gateway form fields for a POST
   redirect). Return `{status: INITIATED, gatewayUrl, transactionId}` to
   the calling App - mirrors the original §7 sequence diagram exactly.
   `documents.status` → `PENDING`, a `document_signers` row → `PENDING`.
3. **Finalize** (ESP → our `PUBLIC` callback, later, different request):
   verify the callback's authenticity (the ESP signs its own response;
   verify against the ESP's published certificate/root, per its API
   spec), extract the returned CMS/PKCS7 bytes, load the **persisted**
   prepared byte array (no `PDDocument` needed), hex-encode the CMS bytes,
   right-pad to the exact reserved placeholder length from step 1, and
   splice them into the byte array at the position given by the persisted
   `ByteRange` - pure byte manipulation, robust to restarts/scaling. Write
   the result as the document's `sealed_storage_key`, `documents.status` →
   `SIGNED`, insert the `document_seals` row (`provider_id`, `transaction_id`,
   `pkcs7_signature`, `ca_issuer`, `auth_type`), `document_signers.status`
   → `SIGNED`. POST a completion notification to `apps.webhook_url` if set.
4. If the callback never arrives (signer abandons OTP): a lightweight
   expiry sweep (or lazy check on next `get_esign_status` poll) flips
   `documents.status` → `EXPIRED`, `document_signers.status` → `FAILED`,
   after a configurable timeout.

This is genuinely new engineering (not just wiring), but it's a bounded,
well-precedented technique - not a research problem.

## New database migration (`V4__esign_sessions.sql`)

```sql
CREATE TABLE esign_sessions (
    session_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id           UUID NOT NULL REFERENCES documents(document_id) ON DELETE CASCADE,
    signer_id             UUID NOT NULL REFERENCES document_signers(signer_id) ON DELETE CASCADE,
    provider_id            VARCHAR(50) NOT NULL,        -- emudhra | cdac | mock_aadhaar
    transaction_id          VARCHAR(255) NOT NULL,
    prepared_storage_key    TEXT NOT NULL,               -- placeholder-PDF bytes, via DocumentStorageProvider
    byte_range              INT[4] NOT NULL,              -- PDFBox's reserved-signature ByteRange
    signature_field_name    VARCHAR(100) NOT NULL,
    status                  VARCHAR(30) NOT NULL DEFAULT 'INITIATED'
                            CHECK (status IN ('INITIATED', 'COMPLETED', 'FAILED', 'EXPIRED')),
    gateway_url             TEXT,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at            TIMESTAMPTZ
);
CREATE INDEX idx_esign_sessions_document ON esign_sessions(document_id);
CREATE UNIQUE INDEX idx_esign_sessions_txn ON esign_sessions(provider_id, transaction_id);
```

## New Java

- `org.tsicoop.sign.esign.ESignAdapter` - interface: `SigningSessionResponse
  initiateSigning(SigningSessionRequest request)`,
  `SigningResult processCallback(JsonNode rawCallbackPayload)`.
- `org.tsicoop.sign.esign.SigningSessionRequest` /
  `SigningSessionResponse` / `SigningResult` - DTOs per the original §7
  design (documentId, appId, signer name/email/phone, doc hash, reason /
  transactionId, gatewayUrl / success, pkcs7Signature, caIssuer, authType).
- `org.tsicoop.sign.esign.MockAadhaarEsignAdapter` - Phase 1 sandbox
  adapter: no real network call; synthesizes a `gatewayUrl` pointing at a
  minimal built-in "mock ESP" consent page (clearly labeled as a test
  stand-in), and on that page's submit, self-signs the hash with a
  dedicated **separate** dev keypair (e.g. alias `mock_aadhaar_esign`, own
  CN like `CN=Mock Signer` - deliberately distinct from
  `tsi_corporate_seal`, so a stamp can never be confused between "the org's
  own seal" and "an individual's eSign," even in dev).
- `org.tsicoop.sign.esign.ExternalCmsSpliceService` - the prepare/splice
  mechanics from the section above (`prepare(originalPdfBytes, signerName,
  reason) → PreparedSigning{preparedBytes, byteRange, contentToHash}`;
  `finalizeSignature(preparedBytes, byteRange, cmsSignatureBytes) →
  sealedPdfBytes`). Calls into `SignaturePlaceholderLocator`/
  `VisibleSignatureStamper` exactly like `LocalPkiSigningService` does
  today, for the visible stamp.
- `org.tsicoop.sign.esign.EsignSessionRepository` - `esign_sessions` CRUD.
- `org.tsicoop.sign.service.v1.DocumentSignerRepository` - first real
  repository for the already-existing `document_signers` table.
- `org.tsicoop.sign.service.v1.EsignCallback` - new `Action`, registered
  `PUBLIC` (the ESP calls this directly, no session/API key) - verifies
  the callback, calls `ExternalCmsSpliceService.finalizeSignature`, updates
  `documents`/`document_signers`/`document_seals`, dispatches the webhook.

## New API surface

- `Documents` gains `initiate_esign` (TENANT_OR_CONSOLE, same RBAC pattern
  as `seal_local`): body `{documentId, signerName, signerEmail or
  signerPhone, reason}` → `{status: INITIATED, transactionId, gatewayUrl}`.
- `Documents` gains `get_esign_status`: body `{documentId}` → current
  `documents.status` + `document_signers[]` (for the calling App to poll,
  or the console to display).
- New route in `_processor.tsi`:
  `/api/v1/esign/callback=org.tsicoop.sign.service.v1.EsignCallback|PUBLIC`.

## Console changes

- `document-detail.html`: alongside the existing **Seal / Sign Document**
  (Corporate Seal) button, a **Send for Aadhaar eSign** action (collects
  signer name + email/phone, calls `initiate_esign`), and a status panel
  showing `document_signers` rows with live status while `PENDING` (poll
  `get_esign_status`). Since the actual OTP/biometric step happens on the
  *App's own end-user-facing flow* in real usage (the API returns
  `gatewayUrl` for the **calling App** to redirect its own user to, per the
  original sequence diagram), the console's own button is primarily for
  admin-triggered testing against the mock adapter, not the production
  path.
- `apps.html` / `app-detail.html`: no change needed - `default_provider_id`
  and `webhook_url` fields already exist for this.

## Explicit scope limits

1. **No real eMudhra/C-DAC/NSDL credentials exist.** Getting them requires
   ASP registration with a CCA-licensed ESP - an external business/legal
   process (agreements, compliance review), not something buildable in
   this codebase. Phase 1 ships the adapter framework + mock adapter so the
   entire flow (initiate → redirect → callback → sealed PDF with visible
   stamp) is demonstrable end-to-end today; swapping in `EmudhraAdapter`
   later touches only the adapter, never the callback/splice/webhook
   machinery.
2. **No Aadhaar number ever stored.** Only what the ESP returns post-auth
   (signer's verified name, transaction id, CA issuer, auth type) goes into
   `document_signers`/`document_seals` - never a raw Aadhaar number or
   Virtual ID, which the signer only ever enters on the ESP's own page, not
   ours.
3. **Expiry sweep is a lazy check, not a background job**, in this phase
   (checked on `get_esign_status`/console view) - a real cron-style sweep
   for silently-abandoned sessions is a small later addition, not required
   for the flow to work correctly.

## Files touched

- `resources/db/migration/V4__esign_sessions.sql` - new.
- `src/org/tsicoop/sign/esign/` - new package: `ESignAdapter`,
  `SigningSessionRequest`, `SigningSessionResponse`, `SigningResult`,
  `MockAadhaarEsignAdapter`, `ExternalCmsSpliceService`,
  `EsignSessionRepository`.
- `src/org/tsicoop/sign/service/v1/DocumentSignerRepository.java` - new.
- `src/org/tsicoop/sign/service/v1/EsignCallback.java` - new.
- `src/org/tsicoop/sign/service/v1/Documents.java` - add `initiate_esign`,
  `get_esign_status`.
- `web/WEB-INF/_processor.tsi` - add the `PUBLIC` callback route.
- `web/console/document-detail.html` - add the eSign trigger + status
  panel.
- `README.md` ("How Document Signing Works" section) - once shipped, note
  Aadhaar eSign as implemented (mock adapter) rather than "planned."

## Verification

- Seal a document via `initiate_esign` against `MockAadhaarEsignAdapter`
  end-to-end: confirm `documents.status` goes `DRAFT → PENDING → SIGNED`,
  a `document_signers` row reaches `SIGNED`, a `document_seals` row is
  inserted with `provider_id = mock_aadhaar`, and the downloaded PDF's
  visible stamp shows the individual signer's name (not the org key
  alias) - reusing the exact `[[TSI_SIGNATURE]]` marker template from
  Corporate Seal.
- Run `pdfsig` on the result and confirm `Signature Validation: Signature
  is Valid.` - proves the byte-splice approach produces a correctly
  hashed/signed PDF, not just a visually-plausible one.
- Kill and restart the app server (or just don't reuse the same JVM
  request) between `initiate_esign` and the callback, to prove the
  approach genuinely doesn't depend on any in-memory state surviving the
  gap - only the persisted `esign_sessions` row + prepared bytes.
- Configure an App's `webhook_url` (already supported today) to a test
  receiver (e.g. a local `nc`/webhook.site) and confirm it fires on
  completion.
- Abandon a session deliberately (never call the mock callback) and
  confirm `get_esign_status`/console eventually reflects `EXPIRED` /
  `FAILED` rather than hanging forever in `PENDING`.
