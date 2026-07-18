# Release evidence workspace

This directory tracks documentation and explicitly incomplete templates only.
Candidate evidence generated below this directory is ignored by Git so that a
bundle cannot accidentally be committed and then misrepresented as evidence
for the new commit that contains it.

The files under `template/` are `DRAFT`, `PENDING`, and `BLOCKED`. They are not
test results, environment locks, real-host acceptance, reviewer sign-off, or a
release decision. Never remove those status markers merely to make a bundle
look complete, and never put credentials, hostnames, internal paths, sample
names, read identifiers, or complete operational reports in them.

Use the repository-local release-evidence tool from a clean checkout of the
exact source candidate. Keep resulting candidate bundles in access-controlled
external evidence storage or as reviewed CI/release artifacts. Do not use
`git add -f` to commit generated bundles here.

See [the release-evidence workflow](../docs/release-evidence.md) for the trust
boundary, fixed artifact roles, checksum semantics, and work that remains
operator- or reviewer-only.
