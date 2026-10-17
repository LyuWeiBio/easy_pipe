# ADR 0015: Sign release-evidence bundles with the approval HMAC key

- **Status:** Accepted
- **Date:** 2026-10-16
- **Scope:** M6 release-evidence authenticity; `approval_hmac_key` reuse as the bundle attestation key

## Context

A sealed release-evidence bundle proved *structural* integrity only: the exact
file set plus a SHA-256 aggregate manifest.  Anyone able to write the bundle
directory could replace every file, recompute the manifest, and the bundle
still "verified".  Verification success therefore said nothing about
*authorship* -- whether the bundle was sealed by the release authority.

Two options were considered:

1. **HMAC-SHA256 attestation.** Sign the manifest bytes with the 32-byte
   `approval_hmac_key` at seal time; verify with the same key.  Unsigned
   legacy bundles keep verifying structurally but are reported as
   `unsigned-legacy`.
2. **Handbook-only hardening.** Keep bundles unsigned and harden the human
   review checklist instead.

## Decision

Option 1.  Rationale:

- The key infrastructure already exists and is reviewed: the approval key is
  a 32-byte hex value in an owner-only file, loaded through the same
  private-file checks as run authorizations (`execution/signing.py`).
- The invasion is bounded: one optional bundle file (`attestation.json`),
  one optional parameter on create/seal/verify, one new model field.  No
  existing unsigned bundle stops verifying.
- The threat it closes is real for the release workflow: a bundle directory
  is ordinary filesystem state, and manifest recomputation is trivial.  An
  HMAC binds the manifest to a secret the release operator holds.
- A public-key scheme would let third parties verify without the secret, but
  introduces key distribution and algorithm negotiation the project does not
  need yet; the release operator verifies their own bundles.  If external
  verification becomes a requirement, this ADR should be revisited.

## Design

- `attestation.json` = canonical JSON `{"format", "key_id", "signature"}`;
  `signature = HMAC-SHA256(key, DOMAIN || manifest_bytes)` with domain
  separation (`b"biopipe-evidence-attestation/1\x00"`), compared with
  `hmac.compare_digest`.  The attestation covers the manifest bytes, which
  cover every other file; the attestation file itself is excluded from the
  manifest (it cannot cover itself).
- The attestation binds `key_id`: verification rejects an attestation sealed
  under a different key identifier (key-confusion resistance).
- `EvidenceVerification.signature_status` is `"signed"` or
  `"unsigned-legacy"`.  A bundle carrying an attestation *requires* the key
  to verify -- without it verification fails closed rather than silently
  skipping the signature check.
- CLI: `--approval-key-file` / `--approval-key-id` on `create`, `checksums`
  (seal), and `verify`; both flags or neither.

## Consequences

- Release operators should seal with the approval key; CI should verify with
  it and reject `unsigned-legacy` for release candidates.
- Key rotation follows the same procedure as run authorizations; old bundles
  keep their attestations (verification needs the key that sealed them).
- Downgrade note: deleting `attestation.json` from a signed bundle does not
  forge content -- the bundle still verifies structurally -- but the
  downgrade is visible as `signature_status="unsigned-legacy"`.  The
  signature therefore proves authorship only when the verifier requires
  `"signed"`; policy, not cryptography, rejects the downgrade.
