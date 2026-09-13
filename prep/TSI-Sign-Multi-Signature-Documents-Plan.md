# Multi-Signature Documents

## Context

Every signing path built so far - Corporate Seal, Aadhaar eSign - assumes
**one document gets exactly one cryptographic signature, ever.** Both
`seal_local` and `initiate_esign` reject a second call once a document
leaves `DRAFT`. But several of the use cases already documented for these
two products are inherently multi-party: a loan agreement needs the
**borrower's** Aadhaar eSign *and* the **bank officer's** Corporate Seal
countersignature; an HR letter might need the **employee's** eSign *and*
an **HR officer's** seal; a vendor agreement needs **both parties**. This
doc works out how to let a document collect more than one independent
signature over time.

## The one distinction that matters

There are two different things that could be called "multiple signatures,"
and conflating them leads nowhere:

1. **One signer, stamped in more than one place, in one operation.** This
   already works today - a template with two `[[TSI_SIGNATURE:name]]`
   markers gets both stamped by the *same* `seal_local`/`initiate_esign`
   call: one marker becomes the real cryptographic widget, the other(s)
   get the identical visual stamp as plain overlay images
   (`LocalPkiSigningService`/`ExternalCmsSpliceService`, already shipped).
   Nothing to design here.
2. **Multiple independent signers, each with their own cryptographic
   signature, acting at different times.** Borrower signs today via
   Aadhaar eSign; bank officer countersigns next week via Corporate Seal.
   **This is the real gap** - today's code cannot do this at all, because
   `seal_local`/`initiate_esign` both hard-reject any document that isn't
   still `DRAFT`. This plan is about (2).

## Why this is feasible - PDF already supports it natively

A PDF can hold more than one `/Sig` dictionary, each covering a different
`ByteRange`, added by separate incremental saves over time - this is how
every real multi-party PDF signing product (DocuSign, Leegality, Adobe
Sign) works at the format level. PDFBox's own model already treats this as
first-class: `PDDocument.getSignatureDictionaries()` returns a `List
<PDSignature>` (not a single optional one), and `getLastSignatureDictionary
()`'s javadoc explicitly discusses documents with multiple signature
fields signed in a different order than they were created. Signing an
already-signed PDF is just calling `addSignature`/`saveIncremental` again
on the current (already-once-incrementally-saved) bytes - the same
mechanism `LocalPkiSigningService`/`ExternalCmsSpliceService` already use,
called a second time.

One useful, non-obvious property this gives for free: signer 2's
`ByteRange` necessarily spans the entire file as it exists at that
moment - which **includes** signer 1's signature. So every subsequent
signature cryptographically re-attests that nothing before it (including
prior signatures) was tampered with. That's the correct, expected
behavior for sequential multi-party signing, not a bug to work around.

## What's already built and gets reused untouched

- **`document_signers`** (`db/01_init.sql`, unused by any Java code until
  the Aadhaar eSign work) already has `signer_order INT NOT NULL DEFAULT
  1` and `anchor_element_id VARCHAR(100)` ("ties to the template's
  tsi-signature-anchor div" - literally written for this). One row per
  signer, exactly the model needed.
- **`document_seals`** already allows any number of rows per
  `document_id` - no schema change needed to record N independent seals.
- **`SignaturePlaceholderLocator`/`VisibleSignatureStamper`** - the
  `[[TSI_SIGNATURE:name]]` marker convention already supports multiple
  named markers per template and already draws a per-signer visible stamp
  (signer identity, reason, date). Fully reusable.

## What's actually missing

### 1. A `PARTIALLY_SIGNED` document status

`documents.status` (`DRAFT/PENDING/SIGNED/EXPIRED`) has no "some signers
done, others still pending" state. `PENDING` is already claimed for "one
Aadhaar eSign session is in flight" (a different, narrower meaning) - reusing
it for this would conflate two concerns. New migration:

```sql
-- db/05_partially_signed_status.sql
ALTER TABLE documents DROP CONSTRAINT documents_status_check;
ALTER TABLE documents ADD CONSTRAINT documents_status_check
    CHECK (status IN ('DRAFT', 'PENDING', 'PARTIALLY_SIGNED', 'SIGNED', 'EXPIRED'));
```

Transition: `DRAFT` -(first signer completes)-> `PARTIALLY_SIGNED` ->
(last outstanding signer completes) -> `SIGNED`. `generate_legal_certificate`
continues to require `SIGNED` (fully executed), unchanged.

### 2. `seal_local` / `initiate_esign` must target *one* placeholder, and seal on top of the *latest* bytes

Both currently always load `document.originalStorageKey()` and (when no
placeholder is given) stamp every marker found. For sequential signing,
each call needs to:

- Load the **current** bytes: `sealedStorageKey` if one already exists,
  else `originalStorageKey`.
- Accept an optional `signerName` (maps to `document_signers.
  anchor_element_id`, matching a specific `[[TSI_SIGNATURE:name]]` marker).
  If omitted, behavior is **exactly what it is today** (locate every
  marker, stamp them all as one signer's operation) - fully backward
  compatible for the existing single-signer Corporate Seal/eSign flows.
  If given, sign **only** that one marker for real and leave every other
  marker completely untouched (no overlay, no change) so it's still
  available for a later signer's turn.
- `LocalPkiSigningService.seal(...)` and `ExternalCmsSpliceService.prepare
  (...)` both gain an optional `targetPlaceholderName` parameter
  implementing exactly that branch.

### 3. Resolving "who signs next"

`document_signers.anchor_element_id` gets populated with the marker name
at signer-creation time (`initiate_esign` and a new `add_local_seal_signer`-
style entry point for Corporate Seal's side of a multi-party document both
insert a row here, instead of only Aadhaar eSign doing so as today).
`get_esign_status`/a new `get_signing_status` returns every signer row for
the document with status, so the console (or the calling App) can show
"Borrower: SIGNED, Bank Officer: PENDING" and offer only the pending one's
action.

**Ordering, kept simple for Phase 1:** no enforced ordering - whichever
signer's turn is invoked next (via `seal_local`/`initiate_esign` naming
their marker) goes next, in whatever order calls happen to arrive.
`signer_order` is still recorded (so the UI/audit trail can show intended
sequence), but not yet enforced. A stricter mode (reject signer 2's action
until signer 1 is `SIGNED`, using the existing `signer_order` column as
the actual gate) is a small, clearly-separable follow-on once real usage
shows whether anyone needs it enforced rather than just displayed.

### 4. Guards need to widen, carefully

Today's guard (`Documents.sealLocal`/`initiateEsign`): "must be `DRAFT`."
New guard: "must be `DRAFT` or `PARTIALLY_SIGNED`, **and** the specific
targeted marker's signer (if any exists yet) must not already be `SIGNED`,
**and** no other signer on this document currently has an eSign session
`INITIATED`" (that last clause is the same protection the earlier
Corporate-Seal-vs-eSign race fix already established - it generalizes
directly).

### 5. Concurrency: two signers acting at once

Two people completing their turn at nearly the same moment could both read
the same "current" sealed bytes and race to append their own incremental
update - a lost-update bug (second write silently clobbers the first
signer's work). Mitigation: an optimistic check - read `sealed_hash`
immediately before sealing, and make the final `UPDATE documents SET
sealed_storage_key = ..., sealed_hash = ...` conditional on `sealed_hash`
still matching what was just read (`WHERE sealed_hash IS NOT DISTINCT FROM
$previousHash`); on a mismatch, fail with a clear "another signature was
just applied - retry" error rather than silently losing one signature.
Simple, no new locking infrastructure, and the failure mode is safe
(nothing is lost, the caller just retries against the now-current bytes).

## Console changes

`document-detail.html`'s single "Apply Corporate Seal" / "Send for Aadhaar
eSign" pair becomes a **per-signer row list** (name, expected type,
status), each pending row getting its own action button scoped to that
`anchor_element_id`. A document with no markers at all keeps behaving
exactly as today (one implicit signer, whichever action is clicked first).

## Explicit scope limits

1. **No enforced signing order in Phase 1** - `signer_order` is recorded
   and displayable, not gated. Enforcing it is a small, separate follow-up
   once there's a real workflow that needs it.
2. **Legal certificate enrichment deferred** - `generate_legal_certificate`
   keeps working (requires full `SIGNED` status) but Part A/B still
   describes "a" seal rather than enumerating every signer/seal row; doing
   that properly is a follow-on to this plan, not blocking it.
3. **No per-signer notification wiring** in this phase (e.g. auto-emailing
   signer 2 once signer 1 completes) - the existing `apps.webhook_url`
   dispatch already fires on each individual signer's completion, which is
   enough for an App to build that notification itself.

## Files touched

- `db/05_partially_signed_status.sql` - new (status CHECK constraint).
- `src/org/tsicoop/sign/pki/LocalPkiSigningService.java` - `seal(...)`
  gains `targetPlaceholderName`; loads latest (sealed-or-original) bytes.
- `src/org/tsicoop/sign/esign/ExternalCmsSpliceService.java` - `prepare
  (...)` gains the same parameter and same latest-bytes behavior.
- `src/org/tsicoop/sign/service/v1/Documents.java` - `sealLocal`/
  `initiateEsign` accept optional `signerName`; guards widen per §4; status
  transition logic (`PARTIALLY_SIGNED` vs `SIGNED`) after each successful
  seal; new `get_signing_status` (or extend `get_esign_status`) returning
  every signer row regardless of type.
- `web/console/document-detail.html` - per-signer row list + scoped
  actions.

## Verification

- A template with two markers (`[[TSI_SIGNATURE:borrower]]`,
  `[[TSI_SIGNATURE:officer]]`): sign `borrower` via the mock Aadhaar eSign
  adapter, confirm `documents.status` is `PARTIALLY_SIGNED` and the
  downloaded PDF shows exactly one visible stamp (officer's marker still
  blank/untouched). Then sign `officer` via `seal_local`, confirm status
  becomes `SIGNED`, both stamps now present, and `pdfsig` reports **two**
  valid signatures - each covering everything before it (officer's
  `ByteRange` spans borrower's signature too).
- Attempt to sign an already-`SIGNED` marker again - rejected.
- Simulate the race in §5 (two sealing calls against the same
  `sealed_hash` snapshot) and confirm the second one fails cleanly with a
  retry-able error instead of silently discarding the first signature.
- A single-marker (or no-marker) document keeps sealing in exactly one
  call, unchanged - regression check that existing Corporate Seal/Aadhaar
  eSign flows aren't affected by any of the above.
