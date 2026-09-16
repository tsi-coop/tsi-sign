#!/usr/bin/env bash
# Signs ONE document you choose via Aadhaar eSign instead of Corporate Seal -
# org.tsicoop.sign.service.v1.Documents. Run 2_create_documents.sh first
# (and, for a multisig document, optionally 3_sign_documents.sh on its
# *other* signer, to see a mixed-signature document). This deliberately
# signs one document/signer at a time rather than all of them at once - run
# it again with different arguments to try another.
#
# Usage:
#   ./4_sign_via_aadhaar_esign.sh <document-key> [signerName]
#
# signerName is required for the two multisig documents (nda-mutual:
# party_a/party_b; loan-agreement: lender/borrower). For the four
# single-signer documents it defaults to "default" - the name
# SignaturePlaceholderLocator gives an anonymous [[TSI_SIGNATURE]] marker -
# since initiate_esign, unlike seal_local, always requires a signerName.
#
# Unlike seal_local, this is a genuinely human-in-the-loop flow:
#   1. initiate_esign (TENANT, documents) -> a gatewayUrl + transactionId.
#   2. This script prints that gatewayUrl and tries to open it in your
#      browser - go there and click Approve (or Deny) on the consent screen
#      (web/console/mock-esign-consent.html in this deployment; a real ESP
#      would show its own real OTP/biometric screen instead).
#   3. This script polls get_esign_status (TENANT, documents) until your
#      browser action lands.
#
#   API_KEY    = your App's key (same App as scripts 1-3)
#   API_SECRET = that App's secret
#   POLL_INTERVAL_SECONDS, POLL_TIMEOUT_SECONDS - override the defaults below.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source lib/common.sh

POLL_INTERVAL_SECONDS="${POLL_INTERVAL_SECONDS:-3}"
POLL_TIMEOUT_SECONDS="${POLL_TIMEOUT_SECONDS:-300}"

key="${1:-}"
signer="${2:-}"
require_document_key "$key"
valid_signers="${DOCUMENT_SIGNERS[$key]}"

if [[ "$valid_signers" == "default" ]]; then
  signer="default"
elif [[ -z "$signer" ]]; then
  echo "'$key' is a multisig document - pass a signerName: one of [$valid_signers]" >&2
  exit 1
elif ! grep -qw "$signer" <<< "$valid_signers"; then
  echo "'$signer' is not a valid signer for '$key' - one of [$valid_signers]" >&2
  exit 1
fi

document_id="$(state_get "${key}.documentId")"

log "initiate_esign: $key ($signer)"
body="$(jq -n --arg d "$document_id" --arg s "$signer" --arg r "Execution of ${key}" \
  '{_func:"initiate_esign", documentId:$d, signerName:$s, reason:$r}')"
resp="$(api documents "$body")"
echo "$resp" | jq '{status, transactionId}'
gateway_url="$(echo "$resp" | jq -r '.gatewayUrl')"

echo "" >&2
echo "Open this URL to complete the Aadhaar eSign consent step as '$signer':" >&2
echo "  $gateway_url" >&2
echo "" >&2
open_in_browser "$gateway_url"

log "Waiting for you to Approve or Deny in the browser (polling every ${POLL_INTERVAL_SECONDS}s, up to ${POLL_TIMEOUT_SECONDS}s)..."
status_body="$(jq -n --arg d "$document_id" '{_func:"get_esign_status", documentId:$d}')"
elapsed=0
while true; do
  status_resp="$(api documents "$status_body")"
  signer_status="$(echo "$status_resp" | jq -r --arg s "$signer" '.signers[] | select(.signerName == $s) | .status')"
  case "$signer_status" in
    SIGNED)
      log "'$signer' completed Aadhaar eSign."
      echo "$status_resp" | jq --arg s "$signer" '{documentStatus, signer: (.signers[] | select(.signerName == $s))}'
      exit 0
      ;;
    FAILED)
      echo "Aadhaar eSign for '$signer' was denied or failed." >&2
      exit 1
      ;;
  esac
  if (( elapsed >= POLL_TIMEOUT_SECONDS )); then
    echo "Timed out after ${POLL_TIMEOUT_SECONDS}s waiting for '$signer' to complete consent." >&2
    echo "The session is still open - reopen the URL above to finish (don't re-run this script while it's pending; initiate_esign 409s on an active session)." >&2
    exit 1
  fi
  sleep "$POLL_INTERVAL_SECONDS"
  elapsed=$((elapsed + POLL_INTERVAL_SECONDS))
done
