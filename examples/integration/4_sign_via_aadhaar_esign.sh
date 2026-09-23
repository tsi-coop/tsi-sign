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
#      browser. The page sends you on to the configured CA (in a fresh
#      install: the bundled TSI eSign Sandbox, a MOCK CA - OTP 123456; a real
#      CA would show its own Aadhaar OTP/biometric screen), and the CA sends
#      you back to /esign/return/... once you're done.
#   3. This script polls get_esign_status (TENANT, documents) until that
#      lands.
#
# Headless mode (CI/demos): ESIGN_AUTOMATE=1 plays the signer's browser
# itself against the TSI eSign Sandbox - no clicking. It only works with the
# sandbox (it drives the sandbox's JSON mode). SIMULATE picks the sandbox
# outcome: ok (default) | deny | expired | esp_error | tampered_hash |
# bad_signature (the last two are attacks the engine must reject).
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
transaction_id="$(echo "$resp" | jq -r '.transactionId')"

# Plays the signer's browser against the TSI eSign Sandbox (ESIGN_AUTOMATE=1).
automate_sandbox_signing() {
  local provider payload action msg signdoc txn_key consent response_url return_msg
  provider="$(echo "$gateway_url" | sed -n 's/.*provider=\([^&]*\).*/\1/p')"
  payload="$(curl -sS -X POST "$BASE_URL/api/v1/esign/callback" -H 'Content-Type: application/json' \
    -d "$(jq -n --arg p "$provider" --arg t "$transaction_id" '{_func:"gateway_payload", provider:$p, transactionId:$t}')")"
  action="$(echo "$payload" | jq -r '.actionUrl')"
  msg="$(echo "$payload" | jq -r '.fields.msg')"
  log "sandbox: submitting the signed request (hash only) to $action"
  signdoc="$(curl -sS -X POST "$action" -H 'Accept: application/json' --data-urlencode "msg=$msg")"
  txn_key="$(echo "$signdoc" | jq -er '.txnKey')" || { echo "Sandbox rejected the request: $signdoc" >&2; return 1; }
  log "sandbox: consent (OTP 123456, outcome: ${SIMULATE:-ok})"
  consent="$(curl -sS -X POST "${action%/form/signdoc}/consent" -H 'Accept: application/json' \
    --data-urlencode "txnKey=$txn_key" --data-urlencode "otp=123456" --data-urlencode "simulate=${SIMULATE:-ok}" \
    --data-urlencode "signerName=$signer")"
  response_url="$(echo "$consent" | jq -r '.responseUrl')"
  return_msg="$(echo "$consent" | jq -r '.msg')"
  log "sandbox: returning the signed response to $response_url"
  curl -sS -X POST "$response_url" --data-urlencode "msg=$return_msg" | sed -e 's/<[^>]*>/ /g' | tr -s ' \n' ' ' >&2
  echo "" >&2
}

if [[ "${ESIGN_AUTOMATE:-0}" == "1" ]]; then
  automate_sandbox_signing
else

  echo "" >&2
  echo "Open this URL to complete the Aadhaar eSign step as '$signer':" >&2
  echo "  $gateway_url" >&2
  echo "" >&2
  open_in_browser "$gateway_url"
fi

log "Waiting for the signing to complete (polling every ${POLL_INTERVAL_SECONDS}s, up to ${POLL_TIMEOUT_SECONDS}s)..."
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
      echo "Aadhaar eSign for '$signer' was denied, cancelled or failed." >&2
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
