# tsi-sign

An open-source, self-hosted document execution engine.

TSI Sign generates documents from HTML templates, routes them for signature (local PKI or an external eSign CA), and seals them with a tamper-evident audit trail. It is structured around **Apps** (e.g. a Loan App, an HRMS App) that each get their own API key, template namespace, and signer pool on one shared engine. 



## Quick start

**Prerequisites:** Docker and Docker Compose, or Java 17 + Maven for a local build.

```bash
docker compose up -d
```

This starts Postgres and applies the schema via Flyway on app boot. Open **http://localhost:8088/console/** to complete first-run setup (creates the first Platform Admin) and use the admin console - create an App, issue an API key, author a template, and generate/seal/certify documents entirely from the browser.

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
| `APP_PORT_MAP` | `8088:8080` | Host:container port mapping |
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
* **Certificate Authority:** Issued on-demand by a Controller of Certifying Authorities (CCA)-licensed eSign Service Provider (ESP) (e.g., eMudhra, C-DAC, NSDL).
* **Execution Flow:**
  1. `tsi-sign` dispatches the document SHA-256 hash (never raw PII) to the licensed ESP gateway.
  2. The individual authenticates via OTP sent to their registered mobile number or via a biometric scan.
  3. The licensed CA generates a short-lived X.509 certificate in the signer's name, signs the hash, and returns the CMS signature payload.
  4. `tsi-sign` embeds the PAdES-LTV signature into the final PDF.

#### Primary Use Cases
External client onboarding, multi-party vendor contracts, NDAs, loan agreements, and high-liability agreements requiring legally binding proof of individual intent.

## API convention

TSI Sign follows the TSI Coop framework standard shared with `tsi-ledger`, `tsi-dpdp-cms`, and `tsi-privacy-vault`: every `/api/v1/*` call is **POST** with a JSON body carrying a `"_func"` field - never a REST verb or a `{id}` URL segment. A single `InterceptingFilter` resolves auth (an App's `X-API-Key`, or a `platform_user`'s console session) and dispatches to an `Action` class via the `web/WEB-INF/_processor.tsi` registry; the `Action` itself switches on `_func`.

```bash
curl -X POST http://localhost:8088/api/v1/templates \
  -H "X-API-Key: sk_..." \
  -d '{"_func":"generate_document","templateId":"...","documentTitle":"Offer.pdf","payloadData":{"name":"Jane"}}'
```

## Project structure

```
pom.xml                          Maven build (WAR packaging, Jetty target)
resources/db/migration/          Flyway schema migrations
web/WEB-INF/_processor.tsi       Resource-path -> Action class + auth-mode registry
src/org/tsicoop/sign/
  framework/                     InterceptingFilter, Action, InputProcessor/OutputProcessor, DB pool, config
  service/v1/                    Tenant-facing Actions (Ping, Templates, Documents)
  service/v1/admin/               Admin console Actions (session-authenticated)
  app/, template/, document/,
  legal/, pki/, storage/, audit/,
  admin/                          Repositories and business logic (HTTP-agnostic)
  seed/                           One-off App-provisioning script (Chunk 1 fallback)
web/console/                     Admin console (plain HTML/JS, no build step)
docker-compose.yml, Dockerfile   Local/self-hosted deployment
```
