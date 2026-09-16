# Example Templates

Ready-to-use document templates for TSI Sign, demonstrating the Mustache
placeholder + `[[TSI_SIGNATURE:name]]` marker conventions used by
`create_template` / `generate_document` (`src/org/tsicoop/sign/service/v1/Templates.java`).

| Template | File | Signers |
|---|---|---|
| Mutual NDA | `templates/nda-mutual.html` | 2 (multisig: `party_a`, `party_b`) |
| Loan Agreement | `templates/loan-agreement.html` | 2 (multisig: `lender`, `borrower`) |
| Experience Certificate | `templates/experience-certificate.html` | 1 |
| Offer Letter | `templates/offer-letter.html` | 1 |
| Rental Agreement | `templates/rental-agreement.html` | 1 |
| Consulting Services Agreement | `templates/consulting-services-agreement.html` | 1 |

Each template has a matching sample payload of the same base name under
`payloads/`.

## Conventions

- Placeholders use Mustache syntax: `{{field}}`, and `{{#list}}...{{/list}}`
  for loops (see `loan-agreement.html`'s repayment schedule).
- A signature anchor is a literal `[[TSI_SIGNATURE]]` (single signer) or
  `[[TSI_SIGNATURE:name]]` (named signer, for multisig documents) inside an
  invisible span (`color:#ffffff; font-size:1px;`). Each named marker
  registers its own row in `document_signers`, so multisig templates must
  use a distinct name per signer.
- `<br>` and other void elements must be self-closed (`<br/>`) — the PDF
  renderer parses templates as strict XHTML.

## Usage

1. Create the template (console: Templates → New Template, or API):
   ```
   POST /api/v1/templates  { "_func": "create_template", "appId": "...",
     "templateName": "Mutual NDA", "category": "LEGAL",
     "htmlContent": "<contents of templates/nda-mutual.html>" }
   ```
2. Generate a document from it using the matching payload:
   ```
   POST /api/v1/templates  { "_func": "generate_document", "appId": "...",
     "templateId": "...", "documentTitle": "NDA - Acme & Bright Path.pdf",
     "payloadData": <contents of payloads/nda-mutual.json> }
   ```
3. For the multisig examples, the console's Document Detail page will show
   one row per named signer (`party_a`/`party_b`, `lender`/`borrower`),
   each sealed independently.

See `integration/` for runnable scripts that do all of the above (register
every template here, generate a document from each, then seal them) end to
end over the API.
