# tsi-sign

An open-source, self-hosted document execution engine.

TSI Sign generates documents from HTML templates, routes them for signature (local PKI or an external eSign CA), and seals them with a tamper-evident audit trail. It is structured around **Apps** — isolated consumers (e.g. a Loan App, an HRMS App) that each get their own API key, template namespace, and signer pool on one shared engine. See `prep/TSI-Sign-Apps-Implementation-Plan.md` for the full design and build plan.

**Status:** Chunk 1 of the build plan — project scaffold and core data model. No API endpoints yet (Chunk 2 adds the first one).

## Quick start

**Prerequisites:** Docker and Docker Compose, or Java 17 + Maven for a local build.

```bash
docker compose up -d
```

This starts Postgres and applies the schema via Flyway on app boot. Since no admin API exists yet, provision a test App directly:

```bash
mvn compile exec:java -Dexec.args="'Demo App' demo-app"
```

This prints the App's `app_id` and its raw API key (shown once).

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `POSTGRES_DB` | `tsi_sign` | Database name |
| `POSTGRES_USER` | `tsi_sign_admin` | Database user |
| `POSTGRES_PASSWD` | `secure_dev_password` | Database password |
| `TSI_SIGN_ENV` | `local` | Deployment environment tag |
| `STORAGE_LOCAL_FS_PATH` | `/data/tsi-sign/documents` | Mount path for the local_fs document storage backend (§5.1) |
| `KEYSTORE_PATH` | `/etc/tsi-sign/keystore.p12` | Local PKI KeyStore for `seal-local` (§7); the image bakes in a self-signed dev keypair here |
| `KEYSTORE_TYPE` | `PKCS12` | KeyStore format |
| `KEYSTORE_PASSWORD` | `changeit` | KeyStore/key password (**change for anything beyond local evaluation**) |
| `APP_PORT_MAP` | `8088:8080` | Host:container port mapping |
| `DB_PORT_MAP` | `5440:5432` | PostgreSQL port mapping |

Ports default to 8088/5440 rather than the usual 8080/5432 so TSI Sign can run alongside other TSI products on the same evaluation host without colliding.

## Project structure

```
pom.xml                        Maven build (WAR packaging, Jetty target)
resources/db/migration/        Flyway schema migrations
src/org/tsicoop/sign/
  framework/                   DB pool, config, API key hashing, boot listener
  seed/                        One-off App-provisioning script (Chunk 1 only)
web/                           WAR web root (WEB-INF/web.xml, static index)
docker-compose.yml, Dockerfile Local/self-hosted deployment
```
