# How Document Signing Works 

## The short version

Signing a document with TSI Sign is like putting an unbreakable wax seal on
it. If anyone changes even one character after it's sealed, the seal
breaks and that's easy to spot. It doesn't just show that someone meant to
sign - it makes the document tamper-proof from that point on.

## How it works, step by step

1. **Sealing** - When a document is signed, the system calculates a unique
   digital fingerprint of the exact document content and locks it to a
   private key that only the organization holds. If even one word changes
   later, the fingerprint no longer matches.

2. **Verifying** - Anyone opening the signed PDF (Adobe Reader, or any
   standard PDF tool) can recompute that fingerprint and compare it to the
   one saved at signing time. A match proves the document is exactly the
   same as what was signed. A mismatch means it was changed after signing.

3. **Who sealed it** - The seal also carries a certificate, like an ID card
   that says who created it. This part can carry more or less outside trust,
   depending on the type of certificate used (see below).

## Self-signed vs. CA-issued certificates

The seal itself works the same way either way, tampering is always
detectable. The difference is who else will trust the identity behind the
seal without being told to.

| | Self-signed certificate | CA-issued certificate |
|---|---|---|
| **What it is** | An ID card we make ourselves | An ID card issued by a recognized, independent authority (for example DigiCert, GlobalSign, or a licensed eSign provider) |
| **Tamper-proofing** | Full, same guarantee | Full, same guarantee |
| **Trust for outsiders** | A stranger has no easy way to confirm the ID card is really us | Anyone can verify it automatically, without asking us |
| **Cost / setup** | Free, instant | Costs money, needs a verification process with the provider |

**Recommended approach:**

- **Internal documents** (approvals, internal memos, employee paperwork):
  use a self-signed certificate. Tamper-proofing is still guaranteed, and
  since the people checking it already know and trust the organization,
  an outside-issued ID card doesn't add much value.
- **External documents** (anything shared with customers, partners,
  regulators, or the public): use a CA-issued certificate. Outside parties
  have no reason to trust an ID card we made ourselves, so having it backed
  by a recognized authority removes that doubt and avoids "unknown signer"
  warnings in PDF viewers.

## One more thing worth knowing

A CA-issued certificate makes the signature trusted by software (no warning
icons). That's a different question from whether a signature is legally
binding under law (for example, India's IT Act, through a licensed
Certifying Authority such as eMudhra). TSI Sign's current signing method
supports the first case: it works with any certificate, self-signed or
CA-issued. Connecting to a licensed eSign provider for legally binding
signatures is planned but not built yet.
