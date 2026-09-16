#!/usr/bin/env bash
# Seals ONE document you choose via seal_local (Corporate Seal) -
# org.tsicoop.sign.service.v1.Documents. Run 2_create_documents.sh first.
# This deliberately signs one document at a time rather than all of them at
# once - run it again with a different <document-key> to try another.
#
# Usage:
#   ./3_sign_documents.sh <document-key> [signerName]
#
# signerName is required for the two multisig documents (nda-mutual:
# party_a/party_b; loan-agreement: lender/borrower) - each seals
# independently and the document moves DRAFT -> PARTIALLY_SIGNED -> SIGNED.
# Omit it for the four single-signer documents, whose one anonymous
# [[TSI_SIGNATURE]] marker needs no name.
#
# No keyAlias is passed here: with none supplied and no default_key_alias
# configured on the App, seal_local falls back to the dev keystore's
# "tsi_corporate_seal" alias, so this works with zero per-App PKI setup.
#   API_KEY    = your App's key (same App as scripts 1-2)
#   API_SECRET = that App's secret
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source lib/common.sh

key="${1:-}"
signer="${2:-}"
require_document_key "$key"
valid_signers="${DOCUMENT_SIGNERS[$key]}"

if [[ "$valid_signers" == "default" ]]; then
  if [[ -n "$signer" ]]; then
    echo "'$key' is a single-signer document - no signerName needed." >&2
    exit 1
  fi
elif [[ -z "$signer" ]]; then
  echo "'$key' is a multisig document - pass a signerName: one of [$valid_signers]" >&2
  exit 1
elif ! grep -qw "$signer" <<< "$valid_signers"; then
  echo "'$signer' is not a valid signer for '$key' - one of [$valid_signers]" >&2
  exit 1
fi

document_id="$(state_get "${key}.documentId")"

if [[ -n "$signer" ]]; then
  log "seal_local: $key ($signer)"
  body="$(jq -n --arg d "$document_id" --arg s "$signer" '{_func:"seal_local", documentId:$d, signerName:$s}')"
else
  log "seal_local: $key"
  body="$(jq -n --arg d "$document_id" '{_func:"seal_local", documentId:$d}')"
fi
resp="$(api documents "$body")"
echo "$resp" | jq '{status, signatureStandard, sealedAt}'
