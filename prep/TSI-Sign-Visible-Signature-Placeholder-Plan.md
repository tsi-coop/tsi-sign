# Corporate Seal — System-Generated Org-Level PAdES Stamp

**Status: implemented.** `SignaturePlaceholderLocator`, `VisibleSignatureStamper`,
and the updated `LocalPkiSigningService.seal()` are in `src/org/tsicoop/sign/pki/`.
Verified: signature stays cryptographically valid (`pdfsig` reports "Signature
is Valid") with the stamp embedded, multi-placeholder stamping works, and a
template with no marker still seals with today's fully invisible signature
(regression-checked). One implementation detail worth knowing versus the
original write-up below: the QR payload uses the **original (pre-seal)
document hash**, not the final sealed-file hash - the sealed hash isn't known
yet at the point the stamp is drawn (it's embedded inside the very file whose
hash it would need to describe), and the original content hash is the more
meaningful fingerprint anyway (it's what was actually locked in at signing
time).

## Use Case Classification

**System-Generated Corporate Seal (Org-Level PAdES Stamp)**

- **Legal Status:** Digital Signature (Server-Side Certificate under company
  name).
- **Leegality Equivalence:** Document Sealing / Automated Corporate Stamp.
- **Phase 1 Implementation for tsi-sign:** Automated background job where
  tsi-sign applies a cryptographic PAdES signature using an enterprise's
  centralized HSM (Hardware Security Module) or local encrypted `.pfx`
  keystore.
- **Primary Use Cases:** Automated invoice sealing, e-way bills,
  system-generated statements, offer letters.

This plan is the concrete design for that use case as it applies to
tsi-sign today, and calls out explicitly where today's engine already
matches the target and where it doesn't yet.

## Where tsi-sign already matches Phase 1, and where it doesn't

**Already matches:**
- Signing is already **server-side, no human signature capture, under the
  org's own certificate** — `LocalPkiSigningService.seal()` signs with a
  key from a **local encrypted keystore** (`LocalKeyStoreProvider`, a
  `PKCS12` file — the `.p12`/`.pfx` format named in the Phase 1 spec) using
  the org's own cert (the Dockerfile's dev keypair CN is `TSI Sign Local
  Dev`). **Decision:** Corporate Seal stays strictly self-signed `.pfx` —
  a production deployment swaps in the org's own self-generated cert (real
  org name/details instead of the dev placeholder), never a CA-issued one.
  A CA-issued or licensed-CA certificate is deliberately out of scope for
  Corporate Seal; that kind of externally-verified trust belongs to TSI
  Aadhaar eSign instead (see "How Document Signing Works in TSI Sign" in
  `README.md`), which is a
  different product for a different purpose (one named individual's legal
  signature via a CCA-licensed provider), not a variant of the org-level
  seal.
- Signature standard is already PAdES-B-B (`PDSignature.SUBFILTER_ETSI_
  CADES_DETACHED` in `LocalPkiSigningService`), matching "PAdES Stamp."
- The template → generate → seal pipeline already fits every listed primary
  use case (invoices, e-way bills, statements, offer letters are all just
  Mustache HTML templates rendered to PDF via `OpenHtmlToPdfGeneratorServiceImpl`,
  then sealed via `seal_local`) - no new document type is needed.

**Not yet matching - open gaps this plan does not close, called out so
they're a deliberate decision rather than an oversight:**
1. **"Automated background job" vs. today's on-demand call.** Today,
   sealing only happens when something explicitly calls `seal_local`
   (a console click, or an App's own API call after `generate_document`/
   `upload_document`). There is no background worker that scans for
   newly-generated invoices/e-way bills/statements and seals them
   automatically without a triggering call. Making it a true background job
   (e.g. auto-seal immediately after `generate_document` for templates
   flagged as "auto-seal", or a polling worker over `DRAFT` documents) is a
   separate, small follow-on change - not included here, since it changes
   when signing happens (immediately vs. on request), which is a workflow
   decision, not a stamp-appearance one.
2. **HSM support.** Only a local `PKCS12` file is supported today
   (`LocalKeyStoreProvider` reads `KEYSTORE_PATH`/`KEYSTORE_PASSWORD` off
   disk). Centralized HSM-backed signing (PKCS#11, or a cloud HSM/KMS) would
   mean a new `KeyStoreProvider` implementation and is not part of this
   plan - the signing call site (`LocalPkiSigningService.seal`) is already
   HSM-agnostic in shape (it only needs a `KeyStore.PrivateKeyEntry`), so
   this is additive later, not a rework.

**What this plan actually delivers:** the visible half of the "PAdES
Stamp" - today's PAdES signature is cryptographically real but **invisible**
on the page. For invoices/e-way bills/statements/offer letters, a human
opening the PDF should be able to see, at a glance, that it carries the
company's corporate seal (signer, reason, timestamp, and a QR code), not
just have it provable via a signature panel a reader has to go looking for.

## Scope decisions confirmed with the user

- **Multiple named placeholders** per template (e.g. `borrower`, `cosigner`),
  not just one.
- **Text block + QR code** in the stamp appearance, not text-only.

Two honest limits on that scope, because they affect what "multi-signer"
and "QR" actually mean here:

1. `seal_local` is still one cryptographic signature per call (one signer/
   key alias, one timestamp) - `documents.status` only has `DRAFT/PENDING/
   SIGNED/EXPIRED` (`resources/db/migration/V1__init_schema.sql`), no
   partial-signed state. So multiple named placeholders in one template all
   get **the same stamp** (useful for a "Corporate Seal" box plus a
   "Countersigned by" box both attested by the one org signer) - true
   independent sequential multi-party signing (different people filling
   different boxes at different times) is a separate, bigger feature (new
   status, per-placeholder seal tracking) and is **not** part of this plan.
2. There is no public document-verification endpoint in this system today.
   The QR encodes a self-contained, scannable, labeled text payload
   (document title, document ID, original SHA-256 hash, key alias, reason,
   timestamp - the same "offline-verifiable, human-readable" spirit as the
   GST e-way bill QR spec, one of Corporate Seal's own named use cases,
   just without that spec's GSTIN-specific fields) - not a clickable
   verification URL. Adding a public verification endpoint later (so
   scanning takes you to a live "yes, this matches" page) is a deliberate,
   separate decision - it means exposing some document integrity data
   without auth - and shouldn't be smuggled in as a side effect of a UI
   stamp.

## Approach

Reuse the existing pipeline exactly as-is up to rendering: Mustache merge
(`OpenHtmlToPdfGeneratorServiceImpl`) → OpenHTMLtoPDF render → PDFBox. The
Corporate Seal marker is plain literal text the template author types
directly into the HTML (not a Mustache `{{ }}` tag, so it passes through
untouched):

```html
<span class="tsi-signature-marker">[[TSI_SIGNATURE:borrower]]</span>
```

Recommended (documented) CSS so it doesn't show up as garbage text next to
the stamp:
```css
.tsi-signature-marker { color: #ffffff; font-size: 1px; }
```
(white-on-white / near-invisible - documented as "works on a white page
background", which is the template default today).

`[[TSI_SIGNATURE]]` (no name) is shorthand for `[[TSI_SIGNATURE:default]]`
- the one most invoices/e-way bills/statements/offer letters will use,
since they only need a single corporate seal, not named co-signer boxes.

### New signing-time steps (in `org.tsicoop.sign.pki`)

1. **`SignaturePlaceholderLocator`** (new) - a `PDFTextStripper` subclass
   that scans the whole rendered PDF for `[[TSI_SIGNATURE:<name>]]` tokens
   and records, per name found, `{pageIndex, x, y, width, height}` from the
   matching `TextPosition`s (override `writeString` to pattern-match, track
   page index via `startPage`). Returns an ordered `Map<String, Placement>`.

2. **`VisibleSignatureStamper`** (new) - given one `Placement` and stamp
   content (signer/key alias, reason, sealed-at timestamp, QR payload
   string), builds the visible Corporate Seal appearance: a fixed-size box
   (e.g. 220×70pt) anchored at the placement's top-left, left side plain
   text drawn via `PDPageContentStream.showText` (Digitally Signed / By /
   Reason / Date), right side a QR module image. QR image comes from
   ZXing's `QRCodeWriter` → `BitMatrix`, rasterized to a `BufferedImage` by
   hand (no need for the heavier `zxing-javase` helper module - just
   `zxing-core`), then embedded as a `PDImageXObject`.

3. **`LocalPkiSigningService.seal(...)`** - after `PDDocument.load(...)`:
   - Run `SignaturePlaceholderLocator`. If it finds **no** markers, behavior
     is byte-for-byte what it is today (invisible signature only) - this is
     the backward-compatible path for every existing template.
   - If it finds one or more markers: build the visible appearance for
     **every** located placeholder (same stamp content, since there's one
     signer per call). Exactly one of them becomes the real interactive
     `PDSignature` widget carrying the cryptographic signature - passed to
     PDFBox via `SignatureOptions.setVisualSignature(templateStream)` +
     `.setPage(pageIndex)` (PDFBox's standard "template PDF with one
     pre-built widget/appearance" mechanism, so PDFBox itself merges the
     widget into the real target page as part of the same incremental save
     that carries the CMS signature - no manual COS-tree surgery). Any
     additional named placeholders are stamped as plain (non-signature)
     appearance content drawn directly onto their page - purely visual,
     since the CMS signature already covers the entire document regardless
     of how many visible stamps are drawn.
   - Everything else in `seal()` (CMS/PKCS7 generation via `signCms`,
     `document.saveIncremental`) is unchanged.

4. `Documents.sealLocal(...)` needs no new required request fields - it
   already collects `reason`/`location`, which feed the stamp text.

### Dependency

Add `com.google.zxing:core` to `pom.xml` (small, no AWT/Swing pulled in via
the `javase` module - rasterize the `BitMatrix` manually).

## Files touched

- `pom.xml` - add ZXing `core` dependency + version property.
- `src/org/tsicoop/sign/pki/SignaturePlaceholderLocator.java` - new.
- `src/org/tsicoop/sign/pki/VisibleSignatureStamper.java` - new.
- `src/org/tsicoop/sign/pki/LocalPkiSigningService.java` - `seal()` extended
  as above; `signCms`/imports otherwise untouched.
- `README.md` (or a new `docs/template-signature-placeholder.md`) - document
  the `[[TSI_SIGNATURE:name]]` marker syntax and the invisible-marker CSS
  snippet, since template authors write these directly into the HTML in the
  Templates console page (`web/console/templates.html`, unchanged by this
  work - no UI change needed, the marker is just HTML the author types into
  the existing "HTML content" textarea).

No DB migration, no new `_func`, no console UI changes required. The
background-job and HSM gaps noted above are explicitly out of scope for
this plan.

## Verification

- Create a template containing `[[TSI_SIGNATURE:borrower]]` (and a second
  named marker to confirm multi-placeholder stamping), generate a test
  document (e.g. an offer letter), seal it via `seal_local`, download the
  sealed PDF, and visually confirm both stamps render with correct
  signer/reason/date and a scannable QR.
- Run `pdfsig <file>` on the sealed PDF and confirm `Signature Validation:
  Signature is Valid.` - proves the visible appearance didn't corrupt the
  byte ranges the CMS signature covers.
- Seal a document from an existing template with **no** marker at all and
  confirm it still seals successfully with today's invisible-only result -
  regression check for every template that predates this feature.
