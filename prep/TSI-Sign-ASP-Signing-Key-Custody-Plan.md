# ASP Request-Signing Key Custody (for the real eMudhra/C-DAC adapter)

**Status: design note only — nothing implemented.** No real ESP adapter
exists yet; `prep/TSI-Sign-Aadhaar-eSign-Plan.md` explicitly defers
`EmudhraAdapter`, blocked on ASP registration with a CCA-licensed ESP (an
external business/legal process, not engineering work). This doc captures a
design question raised while discussing that eventual work, so the answer
isn't lost before the real adapter gets built. **Revisit this doc when that
blocker clears and `EmudhraAdapter` work actually starts** — don't build
against it before then.

## The question

When TSI Sign (as the ASP) sends an eSign request to a real ESP like
eMudhra, does the outbound request need to be signed with a key held in a
KMS/HSM/Vault, rather than a local keystore file?

## The two signing operations at play — don't conflate them

1. **The borrower's Aadhaar eSign signature.** The ESP generates a key pair
   inside *their own* HSM at signing time, uses it once, destroys it
   immediately after. TSI Sign never sees or holds this key — nothing to
   design here, and `ExternalCmsSpliceService` (already shipped) is
   unaffected by anything in this doc.
2. **The ASP request-signing certificate.** Per the CCA's eSign API
   specification, every XML request an ASP sends to the ESP must itself be
   digitally signed with a certificate issued *to the ASP* by a licensed
   Certifying Authority — separate from the borrower's own signature. This
   is TSI Sign's own key, and it's what this doc is actually about.

## Why not just reuse `LocalKeyStoreProvider`

`LocalKeyStoreProvider` (`src/org/tsicoop/sign/pki/`) — a flat `.p12` file
+ env-var password, loaded once into a static holder — is what Corporate
Seal already uses, and it's the right tool for that job: an internal,
self-issued org key with no external counterparty. The ASP-signing
certificate is a different trust boundary:

- **Rotation** — a KMS/Vault-backed key can be rotated and re-pointed live;
  a keystore file means a new file + redeploy every time (the eMudhra
  article's own point: "monitored for expiry, and rotated without
  downtime").
- **Audit** — KMS/Vault give per-use access logging for free; a file on an
  app server's filesystem gives none.
- **Blast radius** — this key signs *on behalf of the regulated entity* to
  a government-licensed CA. A bank/NBFC's own auditors will reasonably
  expect it protected by an HSM-backed store, not sitting as bytes next to
  the Corporate Seal dev keystore.

So: keep `LocalKeyStoreProvider` exactly as-is for Corporate Seal, and give
the ASP-signing key its own, separately-sourced implementation when the
real adapter gets built — don't retrofit the existing one to try to cover
both.

## Proposed shape (sketch, not a committed design)

- Extract a narrow interface (or widen the existing key-source contract)
  that `LocalKeyStoreProvider` already implicitly satisfies —
  `getPrivateKeyEntry(alias)` / "sign this hash" — and add a second
  implementation backed by AWS KMS asymmetric signing keys, HashiCorp
  Vault's Transit engine, or a PKCS#11-attached HSM, depending on what
  eMudhra's ASP onboarding actually issues (see open decisions below).
- This lives entirely inside `EmudhraAdapter.initiateSigning`, wrapping the
  outbound XML request — it never touches `ExternalCmsSpliceService` or the
  callback/splice machinery, which only deal with the borrower's signature
  landing on the PDF.
- Config: most likely the same env-var-driven pattern the rest of this app
  uses, or — now that Chunk 12's System Settings screen established a
  "DB row with env-var fallback, live-editable from console" pattern for
  storage backend config — that same shape could carry ASP-signing-key
  config too, if it needs to be changeable without a redeploy.

## Open decisions (answer when this work actually starts)

- **What does eMudhra's ASP onboarding actually hand you?** A `.pfx` file
  to import, or HSM-compatible provisioning? This determines whether "put
  it in a KMS" means "generate/hold the key in KMS directly" or "import the
  CA-issued certificate into a KMS/HSM you control" as a follow-up step.
- **Does AWS KMS/Vault sign XML-DSig directly, or just a hash?** Almost
  certainly the latter — KMS/Vault typically expose "sign this digest with
  key X," not "produce a complete XML-DSig envelope." The XML
  canonicalization + envelope assembly would likely still be app-side code,
  with only the raw signing operation delegated to KMS/Vault.
- **Which CCA API track applies?** The CCA maintains multiple spec
  families (an e-KYC account-based series, an online Aadhaar series, a
  remote-key-storage series) — which one eMudhra puts you on affects the
  exact request format being signed, upstream of the key-custody question
  but needs resolving alongside it.
- **Shared abstraction with the storage-drivers KMS question?**
  `prep/TSI-Sign-Storage-Drivers-Plan.md` already flags an undesigned
  "where does the KMS/HSM abstraction live" question for client-side
  envelope encryption of stored documents. That's encryption, this is
  signing — different operations — but both want a KMS/Vault backend.
  Worth deciding once whether they share a `KmsProvider`-style abstraction
  or stay fully separate, rather than building two independently.

## Explicit scope limits

- Nothing here is implemented. No interface, no KMS client, no config.
- Doesn't change `LocalKeyStoreProvider`, Corporate Seal, or any shipped
  code — this is additive, scoped entirely to the not-yet-built real ESP
  adapter.

## Verification (once built)

- A real ASP-signed request against eMudhra's staging/sandbox environment,
  confirming the ESP accepts the signature (this is the only test that
  actually validates the XML-DSig format/CCA-track decisions above — can't
  be verified against the mock adapter).
- Key rotation exercised live (new key version in KMS/Vault) with zero
  redeploy and zero signing downtime.
- Confirm no ASP private key material ever appears in application logs,
  error messages, or the existing `document_seals`/`audit_logs` tables.
