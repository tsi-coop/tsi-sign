#!/usr/bin/env bash
# Shared helpers for the TSI Sign integration demo scripts in this folder.
# Every script here talks to a *running* instance (docker compose up -d) over
# the same HTTP API any integrating App would use - no shortcuts into the
# database. The App's API_KEY/API_SECRET are supplied by you via environment
# variables; nothing here creates or stores them beyond the local state file
# used to pass IDs between these scripts.

set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8088}"
STATE_FILE="${STATE_FILE:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.state.json}"

command -v jq >/dev/null 2>&1 || { echo "jq is required: https://jqlang.github.io/jq/" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "curl is required." >&2; exit 1; }

: "${API_KEY:?Set API_KEY to the App key from the console Apps page, then re-run.}"
: "${API_SECRET:?Set API_SECRET to the App secret, then re-run.}"

log() { echo "-> $*" >&2; }

# Maps each sample document's key to its valid signerName(s): "default" is
# what SignaturePlaceholderLocator names an anonymous, single [[TSI_SIGNATURE]]
# marker (the four HR/legal single-signer templates); the two multisig
# templates' named [[TSI_SIGNATURE:name]] markers use their real names.
declare -A DOCUMENT_SIGNERS=(
  [nda-mutual]="party_a party_b"
  [loan-agreement]="lender borrower"
  [experience-certificate]="default"
  [offer-letter]="default"
  [rental-agreement]="default"
  [consulting-services-agreement]="default"
)

list_available_documents() {
  echo "Available documents (key: signerName options):" >&2
  for k in "${!DOCUMENT_SIGNERS[@]}"; do
    echo "  $k: ${DOCUMENT_SIGNERS[$k]}" >&2
  done
}

# require_document_key KEY - validates KEY is one of DOCUMENT_SIGNERS,
# printing usage/available-documents and exiting otherwise.
require_document_key() {
  local key="$1"
  if [[ -z "$key" || -z "${DOCUMENT_SIGNERS[$key]:-}" ]]; then
    echo "Usage: $0 <document-key> [signerName]" >&2
    list_available_documents
    exit 1
  fi
}

# open_in_browser URL - best-effort only. A remote/headless shell (SSH, a
# container, WSL without a browser bridge) has no display to open one on,
# so the caller must always print the URL too rather than rely on this.
open_in_browser() {
  local url="$1"
  if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$url" >/dev/null 2>&1 &
  elif command -v wslview >/dev/null 2>&1; then
    wslview "$url" >/dev/null 2>&1 &
  elif command -v open >/dev/null 2>&1; then
    open "$url" >/dev/null 2>&1 &
  fi
}

# api MODULE JSON_BODY
# POSTs to /api/v1/{module}, authenticated as an App via X-API-Key/
# X-API-Secret (TENANT auth, InputProcessor.getAppContext) - the same path
# any integrating App, not just the admin console, uses. The specific
# operation is the "_func" field inside JSON_BODY, never a URL path segment.
# Prints the response body on stdout and returns non-zero on a non-2xx status.
api() {
  local module="$1" body="$2"
  local resp status body_out
  resp="$(curl -sS -w '\n%{http_code}' -X POST "$BASE_URL/api/v1/$module" \
    -H "X-API-Key: $API_KEY" -H "X-API-Secret: $API_SECRET" -H 'Content-Type: application/json' \
    -d "$body")"
  status="${resp##*$'\n'}"
  body_out="${resp%$'\n'*}"
  echo "$body_out"
  [[ "$status" =~ ^2 ]] || { echo "call to '$module' failed (HTTP $status): $body_out" >&2; return 1; }
}

# state_set KEY VALUE - writes one string field into the shared state file
# (created if missing), so a later script can pick up an ID an earlier one
# produced (e.g. a documentId that 3_sign_documents.sh needs from
# 2_create_documents.sh).
state_set() {
  local key="$1" value="$2"
  [[ -f "$STATE_FILE" ]] || echo '{}' > "$STATE_FILE"
  local tmp
  tmp="$(mktemp)"
  jq --arg k "$key" --arg v "$value" '.[$k] = $v' "$STATE_FILE" > "$tmp" && mv "$tmp" "$STATE_FILE"
}

# state_get KEY - reads one field, failing loudly if it's missing (meaning an
# earlier script in the sequence hasn't been run yet).
state_get() {
  local key="$1"
  [[ -f "$STATE_FILE" ]] || { echo "No state file at $STATE_FILE yet - run the earlier scripts first." >&2; return 1; }
  local value
  value="$(jq -r --arg k "$key" '.[$k] // empty' "$STATE_FILE")"
  [[ -n "$value" ]] || { echo "No '$key' in $STATE_FILE - run the earlier scripts first." >&2; return 1; }
  echo "$value"
}
