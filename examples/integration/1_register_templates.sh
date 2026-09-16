#!/usr/bin/env bash
# Registers every sample template in ../templates/ against your App, via
# create_template (org.tsicoop.sign.service.v1.Templates) over the TENANT
# API - the same call any integrating App makes, authenticated with its own
# API_KEY/API_SECRET. No console session or appId body field needed here:
# a TENANT caller's App is resolved from the API key itself.
#   API_KEY    = your App's key from the console's Apps page
#   API_SECRET = that App's secret
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source lib/common.sh

EXAMPLES_DIR="$(cd .. && pwd)"

# key|display name|category|html file
TEMPLATES=(
  "nda-mutual|Mutual NDA|LEGAL|nda-mutual.html"
  "loan-agreement|Loan Agreement|LEGAL|loan-agreement.html"
  "experience-certificate|Experience Certificate|HR|experience-certificate.html"
  "offer-letter|Offer Letter|HR|offer-letter.html"
  "rental-agreement|Rental Agreement|LEGAL|rental-agreement.html"
  "consulting-services-agreement|Consulting Services Agreement|LEGAL|consulting-services-agreement.html"
)

for row in "${TEMPLATES[@]}"; do
  IFS='|' read -r key name category file <<< "$row"
  log "create_template: $name"
  html_content="$(cat "$EXAMPLES_DIR/templates/$file")"
  body="$(jq -n --arg n "$name" --arg c "$category" --arg h "$html_content" \
    '{_func:"create_template", templateName:$n, category:$c, htmlContent:$h}')"
  resp="$(api templates "$body")"
  template_id="$(echo "$resp" | jq -r '.templateId')"
  state_set "${key}.templateId" "$template_id"
  echo "$resp" | jq '{templateId, templateName, version}'
done

log "Templates registered. Run 2_create_documents.sh next."
