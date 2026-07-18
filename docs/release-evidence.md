# Release evidence workflow

Release evidence binds a candidate's source identity to reproducible artifact
hashes and retained review records. It does not expand the supported workflow,
the frozen public JSON Schema v1 catalog, either remote protocol, or the
real-data approval boundary.

The repository-local workflow is intentionally create-only and local-only. See
the available operations before collecting evidence:

```bash
python scripts/create_release_evidence.py --help
python scripts/create_release_evidence.py create --help
python scripts/create_release_evidence.py checklist --help
python scripts/create_release_evidence.py checksums --help
python scripts/create_release_evidence.py verify --help
```

Run collection from a clean checkout of the exact candidate. Build the required
artifacts separately, review every selected input, and pass only the fixed roles
accepted by the tool. A failed collection must not be treated as a partial
bundle. An existing, empty, non-empty, or symlink destination is not a valid
target; choose a new destination instead of replacing evidence. The destination
parent must already exist, contain no symlink component, and not be writable by
the group or other users.

## Source-commit identity and the self-reference boundary

`candidate.json.git_commit` identifies the source candidate returned by
`git rev-parse HEAD` at collection time. It does not identify a later commit
that contains the generated evidence.

The candidate checkout's tracked `src/biopipe` Git tree object must match the
clean checkout that supplies the running repository-local release tool. This
prevents a clean but unrelated checkout from borrowing another installation's
version, registry, or schema identity. Binding uses Git tree-object identity; it
does not walk or read ignored or untracked files under `src/biopipe`.
Immediately before publication, the tool checks the candidate's clean `HEAD`
again and requires the same commit; a source-tree mismatch or intervening
repository change aborts without publishing the destination.

A file cannot contain the hash of the Git commit that contains that file: adding
or changing the file changes the commit hash. Consequently, actual candidate
bundles are ignored under `release-evidence/` and must not be force-added and
then described as evidence for the resulting commit. Generate evidence only
after selecting the final source candidate, and retain the bundle externally as
an access-controlled CI artifact, release artifact, or other immutable record
linked to that exact source commit.

The files in `release-evidence/template/` are tracked scaffolding. They remain
explicitly `DRAFT`, `PENDING`, and `BLOCKED`; they are not candidate evidence.

## Fixed artifact roles

Collection accepts only reviewed inputs assigned to fixed logical roles. The
evidence records logical names and SHA-256 values, not supplied artifact paths
or directory names.

| Role | Evidence purpose |
|---|---|
| Source archive | Exact source distribution/archive bytes selected for the candidate |
| Wheel | Exact locally reviewed wheel bytes; not a claim of publication |
| Source distribution | Exact locally reviewed sdist bytes; not a claim of publication |
| `bioprobe.pyz` | Exact read-only Remote Probe artifact |
| `bioexec.pyz` | Exact fixed-operation Remote Executor artifact |
| Schema catalog | Exact frozen `catalog.json` resource and its catalog metadata |

The SHA-256 of the exact `catalog.json` file and the catalog's internal
`catalog_sha256` have different meanings. The first binds the catalog file
bytes. The second binds the catalog's ordered schema set. Preserve and label
both; never substitute one for the other.

Environment exports, test and coverage summaries, anonymous acceptance, real
host acceptance, reviewer sign-off, and rollback/key-rotation readiness are
separate evidence roles. The tracked files with those names are incomplete
templates only. The collector must not discover arbitrary reports, walk an
operator directory, copy operational output, or infer values from the current
hostname, username, home directory, SSH configuration, or environment.

Evidence must never contain SSH private keys, approval HMAC keys, tokens,
hostnames, internal raw-data paths, sample names, complete read identifiers, raw
FASTQ content, or full operational reports. Keep even a correctly redacted
bundle under the release evidence retention policy.

## Aggregate checksum semantics

The deterministic aggregate checksum manifest covers every fixed evidence file
in the bundle except the aggregate manifest itself. Self-exclusion is required:
including a checksum file's own digest would create an unsatisfiable recursive
definition. Per-role source and remote checksum manifests are themselves inputs
to, and covered by, the aggregate checksum.

Entries use fixed safe relative names and deterministic ordering. Offline
verification must reject a modified, missing, renamed, duplicate, symlinked, or
unexpected file. It must not contact Git, a network service, or an external
host, and it must not modify the bundle. After adding `SHA256SUMS`, sealing
re-reads and verifies the published disk bundle rather than trusting an earlier
in-memory snapshot.

Checksum verification proves only that the retained bytes match the manifest.
It does not authenticate who produced them, attest to the host, prove that a
command ran, validate scientific correctness, or make the candidate releasable.
Authenticity and release authorization still require protected source history,
reviewed CI/release retention, the operator records below, an independent
reviewer, and the project's tag policy.

## Integrity is not sign-off

The generated `release-checklist.completed.md` is an instantiated checklist,
not a completed release decision. It begins with `DRAFT_UNREVIEWED` and
`BLOCKED`; its 67 canonical review boxes remain unchecked. The generator may
record release identity, the source commit, generation time, and generation
actor as facts, but the generation actor is not implicitly a reviewer.

These items cannot be generated or claimed by Codex or by checksum collection:

- real OpenSSH, ForceCommand, Remote Executor, Nextflow, container-runtime, and
  workflow-tool acceptance on an isolated host;
- independent review of the exact candidate and retained evidence;
- acceptance of residual risk and resolution of blocking issues;
- publication, signed or annotated release tag, and protected-branch decision;
- rollback, HMAC/SSH key rotation, backup, retention, monitoring, capacity,
  incident-response, and secure-disposal ownership.

Operator and reviewer records must remain `PENDING`, `DRAFT`, and `BLOCKED`
until the named people actually complete and review them. Do not turn an
unchecked box into a checked box merely because a command started, a file
exists, or aggregate integrity verifies.

## Scope of the M6.1 release-evidence PR

This small PR provides local release-evidence scaffolding: candidate identity,
fixed-role artifact hashing, deterministic aggregate checksums, create-only
publication, offline verification, explicitly incomplete templates, and their
documentation and tests.

It does not provide or claim:

- platform-specific mamba/conda lock generation or dependency/license review;
- release-acceptance GitHub Actions, macOS CI, action SHA pinning, or artifact
  publication;
- real-host deployment or acceptance execution;
- reviewer or operator sign-off, a release tag, or owner assignments;
- `run --dry-run` gate hardening;
- Slurm, another workflow, networking, or LLM functionality.

Those remain separate PRs and operator-only steps in the post-M6 roadmap. The
release remains blocked until the canonical
[release checklist](release-checklist.md) is supported by fresh evidence from
the exact candidate and every mandatory item is independently reviewed.
