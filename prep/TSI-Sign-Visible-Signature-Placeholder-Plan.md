# Visible Signature Placeholder in Templates

## Context

TSI Sign currently seals PDFs with a fully **invisible** PAdES-B-B signature
(`LocalPkiSigningService.seal()` calls `document.addSignature(signature,
signatureInterface, signatureOptions)` with no rectangle/appearance set —
confirmed by reading the class in full). The document is cryptographically
tamper-evident, but nothing on the page itself shows that it was signed. The
goal is for template authors to be able to mark a spot in an HTML template
where a visible "signed" stamp (signer, reason, timestamp, and a QR code)
appears once the document is sealed.

Two scope choices, confirmed directly with the user:
- **Multiple named placeholders** per template (e.g. `borrower`, `cosigner`),
  not just one.
- **Text block + QR code** in the stamp appearance, not text-only.

Two honest limits on that scope, called out up front because they affect
what "multi-signer" and "QR" actually mean here:

1. `seal_local` is still one cryptographic signature per call (one signer/key
   alias, one timestamp) — `documents.status` only has `DRAFT/PENDING/SIGNED/
   EXPIRED` (`resources/db/migration/V1__init_schema.sql`), no partial-signed
   state. So multiple named placeholders in one template all get **the same
   stamp** (useful for "Borrower Signature" + "Witness Signature" boxes both
   attested by the one signer) — true independent sequential multi-party
   signing (different people filling different boxes at different times) is
   a separate, bigger feature (new status, per-placeholder seal tracking)
   and is **not** part of this plan.
2. There is no public document-verification endpoint in this system today.
   The QR encodes a self-contained, scannable text payload (hash, key alias,
   timestamp) — not a clickable verification URL. Adding a public
   verification endpoint later is a deliberate, separate decision (it means
   exposing some document integrity data without auth) and shouldn't be
   smuggled in as a side effect of a UI stamp.

## Approach

Reuse the existing pipeline exactly as-is up to rendering: Mustache merge
(`OpenHtmlToPdfGeneratorServiceImpl`) → OpenHTMLtoPDF render → PDFBox. The
signature marker is plain literal text the template author types directly
into the HTML (not a Mustache `{{ }}` tag, so it passes through untouched):

```html
<span class="tsi-signature-marker">[[TSI_SIGNATURE:borrower]]</span>
```

Recommended (documented) CSS so it doesn't show up as garbage text next to
the stamp:
```css
.tsi-signature-marker { color: #ffffff; font-size: 1px; }
```
(white-on-white / near-invisible — documented as "works on a white page
background", which is the template default today).

`[[TSI_SIGNATURE]]` (no name) is shorthand for `[[TSI_SIGNATURE:default]]`.

### New signing-time steps (in `org.tsicoop.sign.pki`)

1. **`SignaturePlaceholderLocator`** (new) — a `PDFTextStripper` subclass
   that scans the whole rendered PDF for `[[TSI_SIGNATURE:<name>]]` tokens
   and records, per name found, `{pageIndex, x, y, width, height}` from the
   matching `TextPosition`s (override `writeString` to pattern-match, track
   page index via `startPage`). Returns an ordered `Map<String, Placement>`.

2. **`VisibleSignatureStamper`** (new) — given one `Placement` and stamp
   content (signer/key alias, reason, sealed-at timestamp, QR payload
   string), builds the visible appearance: a fixed-size box (e.g. 220×70pt)
   anchored at the placement's top-left, left side plain text drawn via
   `PDPageContentStream.showText` (Digitally Signed / By / Reason / Date),
   right side a QR module image. QR image comes from ZXing's `QRCodeWriter`
   → `BitMatrix`, rasterized to a `BufferedImage` by hand (no need for the
   heavier `zxing-javase` helper module — just `zxing-core`), then embedded
   as a `PDImageXObject`.

3. **`LocalPkiSigningService.seal(...)`** — after `PDDocument.load(...)`:
   - Run `SignaturePlaceholderLocator`. If it finds **no** markers, behavior
     is byte-for-byte what it is today (invisible signature only) — this is
     the backward-compatible path for every existing template.
   - If it finds one or more markers: build the visible appearance for
     **every** located placeholder (same stamp content, since there's one
     signer per call). Exactly one of them becomes the real interactive
     `PDSignature` widget carrying the cryptographic signature — passed to
     PDFBox via `SignatureOptions.setVisualSignature(templateStream)` +
     `.setPage(pageIndex)` (PDFBox's standard "template PDF with one
     pre-built widget/appearance" mechanism, so PDFBox itself merges the
     widget into the real target page as part of the same incremental
     save that carries the CMS signature — no manual COS-tree surgery).
     Any additional named placeholders are stamped as plain (non-signature)
     appearance content drawn directly onto their page — purely visual,
     since the CMS signature already covers the entire document regardless
     of how many visible stamps are drawn.
   - Everything else in `seal()` (CMS/PKCS7 generation via `signCms`,
     `document.saveIncremental`) is unchanged.

4. `Documents.sealLocal(...)` needs no new required request fields — it
   already collects `reason`/`location`, which feed the stamp text.

### Dependency

Add `com.google.zxing:core` to `pom.xml` (small, no AWT/Swing pulled in via
the `javase` module — rasterize the `BitMatrix` manually).

## Files touched

- `pom.xml` — add ZXing `core` dependency + version property.
- `src/org/tsicoop/sign/pki/SignaturePlaceholderLocator.java` — new.
- `src/org/tsicoop/sign/pki/VisibleSignatureStamper.java` — new.
- `src/org/tsicoop/sign/pki/LocalPkiSigningService.java` — `seal()` extended
  as above; `signCms`/imports otherwise untouched.
- `README.md` (or a new `docs/template-signature-placeholder.md`) — document
  the `[[TSI_SIGNATURE:name]]` marker syntax and the invisible-marker CSS
  snippet, since template authors write these directly into the HTML in the
  Templates console page (`web/console/templates.html`, unchanged by this
  work — no UI change needed, the marker is just HTML the author types into
  the existing "HTML content" textarea).

No DB migration, no new `_func`, no console UI changes required.

## Verification

- Create a template containing `[[TSI_SIGNATURE:borrower]]` (and a second
  named marker to confirm multi-placeholder stamping), generate a test
  document, seal it via `seal_local`, download the sealed PDF, and visually
  confirm both stamps render with correct signer/reason/date and a scannable
  QR.
- Run `pdfsig <file>` on the sealed PDF and confirm `Signature Validation:
  Signature is Valid.` — proves the visible appearance didn't corrupt the
  byte ranges the CMS signature covers.
- Seal a document from an existing template with **no** marker at all and
  confirm it still seals successfully with today's invisible-only result —
  regression check for every template that predates this feature.
