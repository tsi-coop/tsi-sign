#!/usr/bin/env bash
# Generates one document per registered template via generate_document,
# rendering ../payloads/<key>.json into ../templates/<key>.html (Mustache
# placeholders + [[TSI_SIGNATURE:name]] markers - see ../README.md). Run
# 1_register_templates.sh first: this reads the templateIds it wrote to the
# shared state file.
#   API_KEY    = your App's key (same App as script 1)
#   API_SECRET = that App's secret
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source lib/common.sh

EXAMPLES_DIR="$(cd .. && pwd)"

# key|document title
DOCUMENTS=(
  "nda-mutual|NDA - Suryoday Innovations & Meridian Analytics.pdf"
  "loan-agreement|Loan Agreement - Northbridge Finance & Rohan Mehta.pdf"
  "experience-certificate|Experience Certificate - Priya Sharma.pdf"
  "offer-letter|Offer Letter - Ananya Rao.pdf"
  "rental-agreement|Rental Agreement - Flat 4B HSR Layout.pdf"
  "consulting-services-agreement|Consulting Agreement - Meridian Analytics.pdf"
)

for row in "${DOCUMENTS[@]}"; do
  IFS='|' read -r key title <<< "$row"
  template_id="$(state_get "${key}.templateId")"
  payload="$(cat "$EXAMPLES_DIR/payloads/${key}.json")"
  log "generate_document: $title"
  body="$(jq -n --arg t "$template_id" --arg d "$title" --argjson p "$payload" \
    '{_func:"generate_document", templateId:$t, documentTitle:$d, payloadData:$p}')"
  resp="$(api templates "$body")"
  document_id="$(echo "$resp" | jq -r '.documentId')"
  state_set "${key}.documentId" "$document_id"
  echo "$resp" | jq '{documentId, status, originalHashSha256}'
done

log "Documents created (status DRAFT). Run 3_sign_documents.sh next."
