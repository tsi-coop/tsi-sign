# Release Notes

### Unreleased
**Security**
- Fixed the admin console HTML pages being served to any HTTP client with no server-side login check - the only gate was client-side JavaScript that redirects after the page has already been delivered, so a plain `curl` request received the full page source (internal API endpoints, function names, request schemas) with no credentials. Console pages now require a valid server-side session, carried in a new `HttpOnly; SameSite=Strict` login cookie that is set at login and cleared at logout, separate from the existing API bearer token. Every page is gated by default except the login flow (`login`, `index`, `password-reset`) and the signer-facing `esign-redirect` page, so a newly added page is protected automatically. Users already logged in will be sent to the login page once.
- Fixed the first-run admin setup endpoint (`/api/v1/admin/setup`, `setup`) accepting unauthenticated requests for as long as no admin existed - a fresh or reset deployment could have its Platform Admin account claimed by whoever reached the endpoint first. Setup now requires a deployment-configured `TSI_BOOTSTRAP_TOKEN` (see the [README](README.md#environment-variables)); with it unset, setup is refused (`503`) rather than left open, and a wrong token returns `401` before any database access. The existence check and the insert now also run in a single `SERIALIZABLE` transaction, so two simultaneous setup requests can no longer both create an admin. **Action required:** set `TSI_BOOTSTRAP_TOKEN` before first boot of any new deployment.
- Disabled directory listing on the static file servlet. Jetty's bundled defaults auto-list any directory that has no welcome file; welcome-file resolution (e.g. `/console/`) is unaffected.

**Standards**
- Added `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` and this file.
