# TSI Sign

An open-source, privacy-by-design document execution engine. Bring your own CCA-licensed CA for eSign.

> **Note:** TSI Sign is experimental at this stage and still evolving.

TSI Sign generates documents from HTML templates, routes them for signature (a local organisation seal, or an Aadhaar eSign through *whichever* CCA-licensed CA you contract with), and records everything in a hash-chained audit trail. It is structured around **Apps** (e.g. a Loan App, an HRMS App) that each get their own API key, template namespace, and signer pool on one shared engine.

* **Software is open, compliance is pluggable.** PDF generation, signature placement, hashing, storage, and audit run in your own infrastructure under Apache 2.0. The CA is configuration, not a dependency: eMudhra, C-DAC, Protean, VSign, and others speak the same CCA eSign API.
* **Only a SHA-256 hash leaves your network - built for DPDP and data localisation.** Documents, names and other PII stay inside your own VPC. The CA receives just the hash of the bytes to be signed, never the document or its content.
* **No middleware rent on the software.** Unlimited organisation seals and eSign requests through TSI Sign cost ₹0 in software fees; the only per-signature charge is whatever your CA bills you directly.
* **You contract with the CA; we don't sit in the middle.** You need your own ASP agreement with a CA to do real Aadhaar eSign.

### Three steps

1. **Deploy** in your VPC: `docker compose up -d`.
2. **Plug in a CA**: put your ASP ID, ASP request-signing key, and the CA's certificates in the `ESIGN_<PROVIDER>_*` settings ([details](#esign-providers-bring-your-own-ca)) - or keep the bundled *mock* sandbox to try it out.
3. **Sign**: individuals through Aadhaar eSign via your CA, and system-generated documents with your own organisation seal - each with an audit trail.

### Current status

* **Corporate Seal** is a local `.p12` seal from a self-signed or private-CA certificate. It proves the document came from your system and hasn't changed (IT Act s.3); it does **not** bind a legal identity, and it is **not** a Class 3 certificate. Hardware-token/HSM sealing is not supported.
* **Aadhaar eSign** is implemented once, generically, against the CCA eSign API and verified end to end **only against the bundled mock sandbox**. It has not been tested against any real CA yet - see the [provider status table](#esign-providers-bring-your-own-ca).
* Signatures are PAdES-B-B (B-T with a time-stamp authority configured). Long-term validation is not implemented.



## Quick start

**Prerequisites:** Docker and Docker Compose, or Java 17 + Maven for a local build.

```bash
docker compose up -d
```

On first start against a fresh Postgres volume, the numbered scripts in `db/` run automatically (mounted onto Postgres's own `/docker-entrypoint-initdb.d`, the same mechanism every sibling TSI product uses - no migration-tracking library involved). Open **http://localhost:8088/console/** to complete first-run setup (creates the first Platform Admin) and use the admin console - create an App, issue an API key, author a template, and generate/seal/certify documents entirely from the browser.

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `POSTGRES_DB` | `tsi_sign` | Database name |
| `POSTGRES_USER` | `tsi_sign_admin` | Database user |
| `POSTGRES_PASSWD` | `secure_dev_password` | Database password |
| `TSI_SIGN_ENV` | `local` | Deployment environment tag |
| `STORAGE_LOCAL_FS_PATH` | `/data/tsi-sign/documents` | Mount path for the local_fs document storage backend (§5.1) |
| `KEYSTORE_PATH` | `/etc/tsi-sign/keystore.p12` | Local PKI KeyStore for `seal_local` (§7); the image bakes in a self-signed dev keypair here |
| `KEYSTORE_TYPE` | `PKCS12` | KeyStore format |
| `KEYSTORE_PASSWORD` | `changeit` | KeyStore/key password (**change for anything beyond local evaluation**) |
| `DEFAULT_KEY_ALIAS` | `tsi_corporate_seal` | Fallback keyAlias for `seal_local` when neither the request nor the App's Signing Defaults specify one - lets a fresh install seal with zero per-App setup. Set to an empty string to require every App to configure its own key explicitly. |
| `JWT_SECRET` | `dev_insecure_jwt_secret_change_in_production` | Signs admin-console session JWTs (§10, matches tsi-compass's `JWTUtil`) - a stateless session that survives a server restart, unlike a plain `HttpSession`. **Change for anything beyond local evaluation**; the app fails fast at first login if unset. |
| `PUBLIC_BASE_URL` | `http://localhost:8088` | Browser-reachable URL of this server. The eSign redirect page and the CA's return URL are built from it - the signer's browser carries both legs of an eSign. |
| `DEFAULT_ESIGN_PROVIDER_ID` | `sandbox` | eSign provider used when neither the request nor the App names one (see [eSign providers](#esign-providers-bring-your-own-ca)) |
| `ESIGN_<PROVIDER>_*` | - | Per-CA settings: `URL`, `ASP_ID`, `TRUST_CERTS`, `ESP_CERT`, ... (see below) |
| `TSA_URL`, `TSA_TRUST_CERTS`, `TSA_REQUIRED` | unset | Optional RFC 3161 time-stamping: upgrades signatures from PAdES-B-B to B-T |
| `APP_PORT_MAP` | `8088:8080` | Host:container port mapping |
| `SANDBOX_PORT_MAP` | `8091:8091` | Host:container port mapping of the bundled eSign sandbox |
| `DB_PORT_MAP` | `5440:5432` | PostgreSQL port mapping |

Ports default to 8088/5440 rather than the usual 8080/5432 so TSI Sign can run alongside other TSI products on the same evaluation host without colliding.

## How Document Signing Works in TSI Sign

### Overview
Signing a document with TSI Sign applies a cryptographic lock to the file. If any data changes after it is sealed, the cryptographic hash breaks instantly, alerting any viewer (such as Adobe Acrobat Reader) that the document has been tampered with.

The underlying mechanism - calculating a document fingerprint, encrypting it with a private key, and embedding an X.509 certificate - is identical across all signing flows. What distinguishes **TSI Corporate Seal** from **TSI Aadhaar eSign** is whose identity is bound to the certificate embedded in the PDF.

---

### 1. TSI Corporate Seal (Organizational PFX / PKI Seal)

#### What It Is
An automated, server-side digital seal applied by the system using an organization-owned certificate stored in an encrypted `.pfx` / `.p12` key store. The embedded certificate identifies the **organization**, not an individual employee.

#### Legal & Technical Mechanics
* **Legal Basis:** Governed by **Section 3 of the IT Act, 2000** (Digital Signatures / PKI Architecture).
* **Certificate Authority:** Utilizes an organization-managed, self-signed (or private CA) certificate.
* **Integrity & Evidentiary Value:** Cryptographically identical in tamper-evidence to any commercial certificate. The byte-range hash guarantees that the payload has not been modified since issuance.
* **Trust Representation:** Standard PDF viewers will flag self-signed certificates as "Unknown Issuer" unless the organization's root certificate is trusted by the client environment. This is an intended design trade-off for zero-cost, high-volume internal processing.

#### Primary Use Cases
Invoices, e-way bills, system-generated statements, internal staff-signed forms, vendor purchase orders, and automated system outputs where the core requirement is proving *origin and immutability* rather than personal identity verification.

---

### 2. TSI Aadhaar eSign (Third-Party / Individual Signatures)

#### What It Is
An electronic signature legally bound to a **specific, verified individual**. The certificate embedded in the PDF carries a named person's identity verified against government records.

#### Legal & Technical Mechanics
* **Legal Basis:** Governed by **Section 3A of the IT Act, 2000** and the **IT (Electronic Signature) Rules, 2015** (Second Schedule). It carries statutory presumptions of validity under **Sections 85 & 86 of the Bharatiya Sakshya Adhiniyam, 2023**.
* **Certificate Authority:** Issued on-demand by a Controller of Certifying Authorities (CCA)-licensed eSign Service Provider (ESP) **of your choice** (eMudhra, C-DAC, Protean/NSDL, VSign, ...). You need your own ASP agreement with that CA.
* **Execution Flow:**
  1. `tsi-sign` computes the SHA-256 of the exact PDF bytes to be signed, wraps only that hash in a CCA eSign API request, signs the request with your ASP key, and sends the signer's browser to the CA.
  2. The individual authenticates with Aadhaar OTP or biometrics **on the CA's site** - `tsi-sign` never sees the Aadhaar number.
  3. The licensed CA generates a short-lived X.509 certificate in the signer's name, signs the hash, and sends a signed response back through the signer's browser to `POST /esign/return/{provider}/{transaction}`.
  4. `tsi-sign` authenticates the response (below), embeds the CMS signature in the reserved space in the PDF, and records it. The signature is **PAdES-B-B**, or **PAdES-B-T** when a TSA is configured. Long-term validation (PAdES-B-LT/LTA: embedded OCSP/CRL data and a document time-stamp) is **not implemented**.

#### Primary Use Cases
External client onboarding, multi-party vendor contracts, NDAs, loan agreements, and high-liability agreements requiring legally binding proof of individual intent.

## eSign providers (bring your own CA)

Every eSign provider is the same engine speaking the CCA eSign API 2.1; they differ only in configuration. Set the `ESIGN_<PROVIDER>_*` variables for the CA you contracted with. The provider for a new signing is chosen in this order: the `"providerId"` passed to `initiate_esign`, else the App's *Default provider ID* in the console (ignored if it isn't an eSign provider - that field is shared with the local-seal flow), else `DEFAULT_ESIGN_PROVIDER_ID`. An in-flight signing always finishes with the provider it started with.

| Variable | Required | Meaning |
|---|---|---|
| `ESIGN_<P>_URL` | yes | The CA's eSign form endpoint (the signer's browser is POSTed there) |
| `ESIGN_<P>_ASP_ID` | yes | Your ASP ID, issued by that CA |
| `ESIGN_<P>_ESP_CERT` | yes | PEM of the CA's response-signing certificate. **Pinned**: a response must be signed by exactly this certificate - chaining to the CA is not enough, since every customer of that CA holds a certificate that does |
| `ESIGN_<P>_TRUST_CERTS` | yes | PEM of the CA/CCA certificate(s) the signer's certificate must chain to |
| `ESIGN_<P>_ASP_KEY_ALIAS` | no (`tsi_asp_signing`) | Your ASP request-signing key in `KEYSTORE_PATH` (or `ESIGN_<P>_ASP_KEYSTORE_PATH` / `_TYPE` / `_PASSWORD`) |
| `ESIGN_<P>_VERSION`, `_AUTH_MODE` | no (`2.1`, `1` = OTP) | Protocol version / Aadhaar auth mode |

`<P>` is the upper-cased provider ID. A provider that is known but missing required settings is refused with an error naming the missing variables.

| Provider ID | Label on the signature stamp | Verification status |
|---|---|---|
| `sandbox` | Aadhaar eSign (TSI Sandbox) | Tested end to end against the bundled sandbox (a **mock** - no real Aadhaar authentication) |
| `cca_generic` | Aadhaar eSign | Generic CCA eSign API profile - **not tested against any real CA** |
| `emudhra`, `cdac`, `protean`, `vsign`, `capricorn`, `xtratrust` | Aadhaar eSign (\<CA\>) | Config-only profiles of the same adapter - **not yet tested against the real CA**. Expect to discover CA-specific quirks (endpoint version, callback shape) on first contact with that CA's own sandbox. |

Nothing in this repository has been tested against a real CCA-licensed CA. The sandbox proves the protocol mechanics, not compatibility with any real CA.

**Trust model.** The return endpoint is unauthenticated by necessity (it is a browser POST), so nothing it receives is acted on until the adapter has verified: the response's XML signature is by the pinned ESP certificate; the PKCS#7 signs *exactly* the hash we sent; and the signer's certificate chains to the trusted CA and verifies the signature. An unverifiable callback changes no state (it is only audit-logged as `ESIGN_CALLBACK_REJECTED`); only an authenticated failure from the CA (cancelled, wrong OTP) fails a session. Not done: OCSP/CRL revocation checking of the signer certificate (they are ~30-minute, single-use certificates).

### The eSign sandbox

`sandbox/` is a small standalone service (`docker compose up` starts it as `esign_sandbox`, port 8091) that plays a CCA-licensed ESP *and its CA*: it verifies your signed request, shows an OTP consent page (OTP `123456`), issues a short-lived signer certificate from its own root CA, signs the hash, and returns a signed response. It also runs an RFC 3161 time-stamp authority at `/tsa`. On the consent page you can simulate: user cancels, expired transaction, ESP error, and two *attacks* the engine must reject (the ESP signing a different hash; a response signed by a certificate that merely chains to the CA). Its root and ESP certificates are published at `/ca/root.pem` / `/ca/esp.pem` (and to a shared volume in compose) for the `sandbox` provider to trust and pin.

**It is a development fixture, not a CA anyone should trust.** Its signatures show as "issuer isn't trusted" in PDF viewers by design. Remove the `esign_sandbox` service and `DEFAULT_ESIGN_PROVIDER_ID` before pointing a deployment at a real CA.

```bash
# adapter <-> sandbox integration tests (skipped unless SANDBOX_URL is set)
(cd sandbox && mvn package)            # runs the sandbox's own tests, builds the jar
java -jar sandbox/target/tsi_esign_sandbox.jar &
SANDBOX_URL=http://localhost:8091 mvn test
```

Upgrading an existing database: `docker exec -i tsi_sign_postgres psql -U tsi_sign_admin tsi_sign < db/10_esign_gateway_payload.sql` (and `db/11_audit_hash_chain.sql`) - the numbered scripts only run automatically on a fresh volume.

## Audit trail

Each App's `audit_logs` rows are hash-chained (`entry_hash` covers the row's contents and the previous row's hash). Console → Audit → *Verify integrity* recomputes an App's chain and reports the first edited, removed, reordered, or injected entry. It cannot detect removal of the *newest* entries, or a database administrator rewriting the entire chain - store the head hash it prints somewhere outside the database to close that gap. Entries written before the chain existed are outside it.

## Architecture

See [docs/architecture.md](docs/architecture.md) for the full design: tenancy, data model, storage, signing (Corporate Seal, Aadhaar eSign, multi-signature), audit and legal evidence, and what is not built.

## API convention

TSI Sign follows the TSI Coop framework standard shared with `tsi-ledger`, `tsi-dpdp-cms`, and `tsi-privacy-vault`: every `/api/v1/*` call is **POST** with a JSON body carrying a `"_func"` field - never a REST verb or a `{id}` URL segment. A single `InterceptingFilter` resolves auth (an App's `X-API-Key` + `X-API-Secret` pair, or a `platform_user`'s console session) and dispatches to an `Action` class via the `web/WEB-INF/_processor.tsi` registry; the `Action` itself switches on `_func`.

```bash
curl -X POST http://localhost:8088/api/v1/templates \
  -H "X-API-Key: key_..." \
  -H "X-API-Secret: sk_..." \
  -d '{"_func":"generate_document","templateId":"...","documentTitle":"Offer.pdf","payloadData":{"name":"Jane"}}'
```

See `examples/integration/` for runnable scripts that register a template,
generate a document, and seal it end to end over this API.

One deliberate exception: the CA's return leg (`POST /esign/return/{provider}/{transaction}`) is a form-encoded browser POST dictated by the CCA spec, so it is a plain servlet (`EsignReturnServlet`) rather than an `_func` Action.

## Project structure

```
pom.xml                          Maven build (WAR packaging, Jetty target)
db/                              Numbered schema scripts (01_init.sql, ...), auto-run once by
                                 Postgres itself against a fresh volume - no migration library
web/WEB-INF/_processor.tsi       Resource-path -> Action class + auth-mode registry
src/org/tsicoop/sign/
  framework/                     InterceptingFilter, Action, InputProcessor/OutputProcessor, DB pool, config
  service/v1/                    Tenant-facing Actions (Ping, Templates, Documents)
  service/v1/admin/               Admin console Actions (session-authenticated)
  app/, template/, document/,
  legal/, pki/, esign/, storage/, audit/,
  admin/                          Repositories and business logic (HTTP-agnostic)
  seed/                           One-off App-provisioning script (Chunk 1 fallback)
sandbox/                         Mock CCA eSign ESP + CA + TSA for development (standalone Maven module, not part of the WAR)
web/console/                     Admin console (plain HTML/JS, no build step)
docker-compose.yml, Dockerfile   Local/self-hosted deployment
```
