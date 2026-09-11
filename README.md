# tsi-sign

An open-source, self-hosted document execution engine.

TSI Sign generates documents from HTML templates, routes them for signature (local PKI or an external eSign CA), and seals them with a tamper-evident audit trail. It is structured around **Apps** — isolated consumers (e.g. a Loan App, an HRMS App) that each get their own API key, template namespace, and signer pool on one shared engine. See `prep/TSI-Sign-Apps-Implementation-Plan.md` for the full design and build plan.

**Status:** Chunks 1-9 complete — a fully self-signed (Local PKI) document execution engine with an admin console, RBAC, and BSA §63 legal certificates. External CA integration (eMudhra, Chunks 10-11) is not yet built.

## Quick start

**Prerequisites:** Docker and Docker Compose, or Java 17 + Maven for a local build.

```bash
docker compose up -d
```

This starts Postgres and applies the schema via Flyway on app boot. Open **http://localhost:8088/console/** to complete first-run setup (creates the first Platform Admin) and use the admin console — create an App, issue an API key, author a template, and generate/seal/certify documents entirely from the browser.

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

## API convention

TSI Sign follows the TSI Coop framework standard shared with `tsi-ledger`, `tsi-dpdp-cms`, and `tsi-privacy-vault`: every `/api/v1/*` call is **POST** with a JSON body carrying a `"_func"` field — never a REST verb or a `{id}` URL segment. A single `InterceptingFilter` resolves auth (an App's `X-API-Key`, or a `platform_user`'s console session) and dispatches to an `Action` class via the `web/WEB-INF/_processor.tsi` registry; the `Action` itself switches on `_func`.

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
