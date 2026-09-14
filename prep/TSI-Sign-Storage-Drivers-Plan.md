# Storage Driver Roadmap (Chunk 12 expansion)

## Context

`TSI-Sign-Apps-Implementation-Plan.md` §5 already establishes a pluggable
`DocumentStorageProvider` interface and scopes Chunk 12 to exactly two
additional backends: `s3` and `privacy_vault`, alongside the `local_fs`
default shipped in Phase 1. This doc captures a broader ask raised
separately: should the driver matrix widen to cover GCS, Azure Blob,
Postgres BYTEA, and — more importantly — three enterprise-grade
capabilities (zero-disk retention, client-side KMS envelope encryption,
WORM/object-lock) that §5 doesn't currently address at all. Nothing here
is implemented yet; this is a planning note to reconcile the ask against
what's already built and decide what actually belongs in Chunk 12 vs. a
later phase.

## What's already built (as of this writing)

- `org.tsicoop.sign.storage.DocumentStorageProvider` — interface, **already
  implemented and shipped**, `byte[]`-in/`byte[]`-out (not `InputStream`):
  ```java
  public interface DocumentStorageProvider {
      String getProviderId();
      StorageObjectRef store(String appSlug, String documentId, String variant, byte[] content) throws StorageException;
      byte[] retrieve(StorageObjectRef ref) throws StorageException;
      void delete(StorageObjectRef ref) throws StorageException;
  }
  ```
- `StorageObjectRef(providerId, storageKey, sha256Checksum)` — record, ships a checksum by default (every write is content-addressed/verifiable, not just an incidental nice-to-have).
- `LocalFilesystemStorageProvider` — the only implementation so far. Key convention `{app_slug}/{yyyy}/{mm}/{documentId}/{variant}.pdf`, path-traversal guard (`resolveWithinBase`), atomic write via temp-file + `ATOMIC_MOVE`.
- `variant` is always `"original"` or `"sealed"` — two independently addressable objects per document, not a single mutable file. This already gives WORM-*adjacent* behavior for free at the application level (the code path that would overwrite `"sealed"` in place doesn't exist), independent of whatever the backend's own immutability features are.
- `apps.storage_provider_id` (nullable override) + `documents.storage_provider_id`/`original_storage_key`/`sealed_storage_key` (denormalized at write time) — per-App backend choice, and switching a deployment's default backend never strands documents written under the old one.

## Reconciling the proposed interface with the shipped one

The proposal's interface signature is `InputStream`-based
(`storeDocument(tenantId, documentId, InputStream pdfStream, long
contentLength, String contentType)` / `retrieveDocument` returning
`InputStream`). The shipped interface is `byte[]`-based. This is a real
design fork, not a naming difference:

- **`byte[]` (current)** — simpler, and every caller today already has the
  full PDF in memory anyway (PDFBox's incremental-save signing path
  (`LocalPkiSigningService`/`ExternalCmsSpliceService`) produces a
  complete byte array, not a stream). Matches `sha256Checksum` being
  computed inline at `store()` time (`HashUtil.sha256Hex(content)` — trivial
  on a `byte[]`, awkward on a single-pass `InputStream` without buffering
  it anyway).
- **`InputStream` (proposed)** — only pays off if TSI Sign starts handling
  documents too large to hold comfortably in memory, or wants to stream
  straight from an HTTP request body to the backend without ever
  materializing the whole file. Not a real constraint for signed PDFs at
  today's expected sizes.

**Recommendation:** keep `byte[]` unless/until a concrete large-file case
shows up — don't widen the interface speculatively. Flagging this so the
mismatch between the proposal and the shipped code isn't lost.

## Proposed driver matrix vs. what Chunk 12 currently scopes

| Provider | Proposal | Current §5.1 scope | Notes |
|---|---|---|---|
| Local filesystem / POSIX | `LocalFileSystemStorageProvider` | ✅ shipped (`local_fs`) | Already done. |
| S3-compatible (MinIO, Ceph, R2) | `S3CompatibleStorageProvider` | ✅ planned Chunk 12 (`s3`) | §5.1 already notes "same AWS SDK v2 client works against AWS S3 *or* a self-hosted S3-compatible store" — one provider, not two. |
| AWS S3 (native, S3 Express One Zone, KMS envelope) | `AwsS3StorageProvider` | folded into `s3` above | See "one S3 driver, not two" below. |
| Google Cloud Storage | `GcsStorageProvider` | ❌ not scoped | New ask. GCS has an S3-interoperability API — worth checking whether that closes the gap via the existing `s3` driver before building a native GCS client. |
| Azure Blob Storage | `AzureBlobStorageProvider` | ❌ not scoped | New ask. No S3-compatible facade; would be a genuinely separate driver if ever built. |
| Postgres BYTEA | `PgByteaStorageProvider` | ❌ not scoped | New ask, low complexity. Trades "everything in one backup/restore story" for bloating the primary DB with binary payloads — worth an explicit call before building. |
| TSI Privacy Vault | (not in proposal) | ✅ planned Chunk 12 (`privacy_vault`) | Already scoped, org-internal product, not a generic cloud target — keep as-is. |

### One S3 driver, not two

The proposal lists `S3CompatibleStorageProvider` and `AwsS3StorageProvider`
as separate drivers. §5.1 already made the call to use one AWS SDK v2
client configured against either AWS's endpoint or a self-hosted
S3-compatible endpoint (MinIO, Ceph RGW, SeaweedFS) — config-only
difference (endpoint URL, path-style addressing for MinIO), not two code
paths. This is the same conclusion the proposal's own closing
recommendation reaches ("plugging in an S3-compatible driver
automatically covers AWS S3, MinIO, ... with a single codebase") — so no
actual disagreement here, just: don't split it into two provider classes.
AWS-specific features (S3 Express One Zone, SSE-KMS) become **config
flags on the one `s3` provider**, not a reason for a second class.

### On the "unified abstraction library" suggestion (jclouds / Spring Cloud AWS+GCP)

Worth an explicit decision rather than defaulting into it: §5's
`DocumentStorageProvider` is already the abstraction layer — a ~30-line
interface with one implementation per backend. Pulling in Apache jclouds
or Spring Cloud's AWS/GCP modules would mean adopting a much larger
dependency surface (and, for jclouds specifically, a project with a much
slower release cadence) to get multi-cloud coverage that a native AWS SDK
v2 `s3` client already gets for free across AWS/MinIO/Ceph/R2, and that a
native GCS/Azure SDK client gets just as directly for those two. Given
TSI Sign's whole footprint is currently 3 providers (soon 4-5), a thin
hand-rolled `DocumentStorageProvider` per backend keeps the dependency
tree smaller and the abstraction exactly as wide as TSI Sign actually
needs — recommend **not** adopting jclouds/Spring Cloud Storage unless the
provider count grows enough that reimplementing each SDK's quirks
stops being worth it.

## Three capabilities §5 doesn't cover yet

These are the part of the proposal that's a genuine gap, independent of
which specific cloud providers get drivers:

### 1. Ephemeral / zero-disk retention mode

Some deployments (the proposal cites banks) may require TSI Sign to never
persist the signed PDF at all — sign in memory, stream the response or
fire a webhook, discard. This isn't a new `DocumentStorageProvider`
implementation — it's a **third state alongside "store," orthogonal to
which backend is configured**: `apps.retention_mode` (`PERSISTED`
(default) | `EPHEMERAL`), checked by the signing service before it ever
calls `store()` on the `"sealed"` variant. Needs a decision on what
`documents.sealed_storage_key` means when retention is ephemeral (likely:
stays `NULL` forever, and `document_seals`/`audit_logs` become the only
durable record that a signing event happened).

### 2. Client-side envelope encryption before the backend ever sees bytes

Distinct from backend-side SSE (S3 SSE-KMS, GCS CMEK, Azure Key Vault
integration — which protect against someone stealing the *bucket*, not
against a compromised TSI Sign deployment or cloud provider access).
Client-side envelope encryption wraps the PDF bytes in a DEK before
`store()`, with the DEK itself wrapped by a customer-controlled KMS
(AWS KMS, Azure Key Vault, HashiCorp Vault, or PKCS#11 HSM) — so a
breached bucket yields ciphertext with no way to unwrap it without the
customer's own key material. §5.4 already sketches "AES-256 envelope
encryption at the storage-provider layer" for `local_fs`/`s3` but doesn't
specify a customer-managed-key model — this would need to be pulled up a
layer, applied uniformly across all backends (encrypt/decrypt wrapping
`store()`/`retrieve()` in `DocumentStorageProvider`, not per-implementation),
with the key-management backend itself pluggable the same way storage is.

### 3. WORM / object-lock support

For statutory retention (SEBI/RBI/IT Act, 7+ years, non-repudiation):
`s3` should be able to set AWS S3 Object Lock (compliance mode) on write
for the `"sealed"` variant, and a future `gcs` driver Bucket Lock. This is
a backend capability flag, not a new interface method — most naturally
expressed as config on the `s3`/`gcs` provider (bucket must already have
Object Lock enabled at creation; TSI Sign sets the retention period per
`PutObject` call) rather than something `DocumentStorageProvider` itself
needs to abstract over, since `local_fs` and `privacy_vault` have no
equivalent primitive to expose.

## Suggested sequencing

Doesn't have to be decided now, but a reasonable order given the above:

1. **Chunk 12 as already scoped**: `s3` (config-driven, covers AWS S3 +
   MinIO + Ceph + R2 day one), `privacy_vault`.
2. **Chunk 12 extension, same complexity class**: ephemeral retention
   mode (§1 above) — it's an `apps`-level flag + one conditional in the
   signing service, not a new provider.
3. **Later, only if a customer actually needs it**: `gcs` (check the S3
   interop API first — may not need a native driver at all), client-side
   KMS envelope encryption pulled into the `DocumentStorageProvider`
   layer, S3 Object Lock config on the `s3` provider.
4. **Only on explicit customer ask**: `azure`, `pg_bytea` — neither has a
   forcing use case yet; building either speculatively adds maintenance
   surface with no validated demand.

## Open decisions

- Does GCS's S3-interoperability API actually cover what a GCS-hosted
  customer needs (including CMEK), or does CMEK support require a native
  `GcsStorageProvider` regardless? Needs a spike, not a guess.
- Is `pg_bytea` worth building at all, or is "keep it simple, use
  `local_fs`" already the low-complexity option the proposal was gesturing
  at? Putting PDF binaries in the primary transactional DB has real
  backup/restore and DB-size blast-radius costs that `local_fs` doesn't.
- Where does the KMS/HSM abstraction live — a new
  `EnvelopeEncryptionProvider` interface parallel to
  `DocumentStorageProvider`, wrapping any backend? That seems right but
  isn't designed yet.
- Confirm `InputStream` vs `byte[]` stays `byte[]` (see above) before
  anyone starts Chunk 12 implementation work against the proposal's
  signature instead of the shipped one.

## Sovereignty pitch, unaffected

None of the above changes the core promise: local disk and self-hosted
S3-compatible storage stay first-class, so a fully air-gapped or
sovereign-VPC deployment never has to touch an external vendor's cloud —
the new drivers (GCS, Azure, native features) are additive options for
customers who *are* on a given cloud and want native integration, not a
replacement for the self-hosted path.
