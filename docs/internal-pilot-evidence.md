# Internal pilot evidence compiler

This repository includes a local compiler for an operator-prepared, sanitized
M6.2 pilot record. It creates a deterministic review draft; it does not execute
a pilot, inspect a generated project, read reports or audit history, connect to
a remote host, authenticate evidence, perform independent review, or authorize
production use.

Every generated bundle is fixed to these conservative states, even when all
recorded criteria are present:

```text
record_state: OPERATOR_RECORDED_UNREVIEWED
independent_review_status: PENDING_INDEPENDENT_REVIEW
milestone_decision: BLOCKED
production_authorization: false
```

The derived `READY_FOR_INDEPENDENT_REVIEW` state means only that the sanitized
record contains the required categories. It is never a passed, accepted, or
completed pilot claim.

## Two-record boundary

Keep two distinct records:

1. The site-controlled record contains actual operator/approver identities,
   hostnames, paths, dataset authorization, run IDs, reports, audit lines,
   capacity worksheets, incident references, and evidence locations. It stays
   in the organization's restricted evidence system.
2. The sanitized record contains only anonymous fixed-format IDs, enums,
   bounded counts, coarse usage buckets, canonical UTC timestamps, stable
   codes, and SHA-256 pointers. This is the only pilot record accepted by the
   compiler.

Do not rename the site-controlled record to make it look sanitized. Construct
a new minimal projection and review that projection for disclosure before
using this tool.

## Initialize an honest blocked record

The private helper can create a deterministic authoring record with all six
case slots and all ten drill slots present but explicitly `unexecuted`. Every
owner and capacity/retention decision is pending, the M6.1 entry gate and
friction review are not recorded, backup restore is not run, documentation
operation is not observed, and the next recommendation is `remain_blocked`.

Initialization accepts only anonymous IDs, canonical UTC, the release ID,
source commit, and three expected manifest SHA-256 values. It does not inspect
Git or any M6.1 bundle and does not authenticate those pointers. The
`--repository` argument is used only to reject an input/output location inside
the selected worktree, including filesystem aliases.

Use an existing operator-controlled directory outside the repository. Its
destination parent must not be group- or world-writable and must not carry an
extended ACL. The command is create-only and writes a single-link file with
mode `0600` and no extended ACL; it never replaces an earlier record:

```bash
umask 077

python scripts/collect_internal_pilot_evidence.py init-record \
  --repository . \
  --output /restricted/pilot/pilot-20260719-001.sanitized.json \
  --pilot-id pilot-20260719-001 \
  --environment-id env-001 \
  --recorded-at 2026-07-19T08:00:00Z \
  --release-id 0.1.0-rc1 \
  --source-git-commit 0000000000000000000000000000000000000000 \
  --candidate-manifest-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --release-acceptance-manifest-sha256 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  --real-host-manifest-sha256 cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
```

The values above are format examples, not release evidence. Replace them only
with exact pointers copied through the site's controlled process. Update the
record only inside that restricted authoring system; do not commit it. Preserve
an earlier snapshot by using a new file rather than asking the helper to
overwrite it.

Validate the edited strict record offline before compiling a review draft:

```bash
python scripts/collect_internal_pilot_evidence.py validate-record \
  --repository . \
  --sanitized-record /restricted/pilot/pilot-20260719-001.sanitized.json
```

Validation is read-only and accepts semantically valid non-canonical JSON
without rewriting it. It reports both the exact-file and normalized SHA-256
and whether the bytes were already canonical. Those hashes identify content;
they are not signatures or evidence authenticity. Every result remains fixed
to:

```text
record_state: STRICT_FORMAT_VALIDATED_ONLY
source_evidence_authentication_status: NOT_PERFORMED
independent_review_status: NOT_PERFORMED
milestone_decision: BLOCKED
production_authorization: false
```

Keep an edited or externally prepared sanitized-record leaf at mode `0600`,
with exactly one hard link and no extended ACL. Both `validate-record` and
review-draft `create` reject a symlink, any group/other permission bit, multiple
hard links, or an extended ACL. Re-establish these properties after a
site-controlled editor, copy tool, or evidence system exports the file.

Neither authoring command reads a generated project, report, audit history,
private state, host identity, or environment credential.
Neither invokes a network client or initiates a socket connection; transport
below an operator-supplied mounted filesystem is outside the helper's view.

## What review-draft creation verifies

Creation verifies:

- the sealed M6.1 candidate bundle;
- the release-acceptance CI bundle and real-host bundle identities;
- agreement of their release ID, source commit, and evidence-manifest hashes
  with the sanitized record;
- a clean exact repository commit and the running tool's repository binding;
- the strict input allowlist, cross-field state rules, fixed limits, and
  normalized deterministic representation; and
- private, create-only bundle publication.

Creation does not verify the content behind case/report/audit SHA-256 values.
Those are operator-recorded pointers for an independent reviewer. In
particular, the compiler never decides that three case IDs are genuinely three
independent executions.

## Private output location

Run from the exact reviewed checkout. Put the sanitized input and generated
bundle outside the Git worktree in an existing directory accessible only to
the evidence operator. The output path must not already exist; the tool never
updates or replaces a previous snapshot.

The compiler rejects the sanitized record, all three source-evidence roots,
and the output when any is inside the selected repository. It also rejects an
output that contains, equals, or is nested beneath a source-evidence root, so a
new draft cannot change the exact file set of a sealed input bundle.

```bash
umask 077

python scripts/collect_internal_pilot_evidence.py create \
  --repository . \
  --candidate-evidence /restricted/evidence/0.1.0-rc1 \
  --release-acceptance-evidence /restricted/evidence/release-acceptance \
  --real-host-evidence /restricted/evidence/real-host \
  --sanitized-record /restricted/pilot/pilot-20260719-001.sanitized.json \
  --output /restricted/pilot/pilot-20260719-001-review-draft \
  --created-at 2026-07-19T09:00:00Z
```

The paths above are role examples, not supported defaults. Do not paste real
site paths into source control, tickets, or a lower-trust report.

The bundle contains exactly:

```text
internal-pilot-summary.json
internal-pilot-review-draft.md
SHA256SUMS
```

`internal-pilot-review-draft.md` is a deterministic projection of the JSON,
not a second editable fact source. The offline verifier re-renders it and
requires exact bytes in addition to validating the checksum manifest.

## Inspect the strict input schema

The sanitized-record format is internal M6.2 tooling, not part of the frozen
public schema-v1 catalog. Print its current strict JSON Schema without reading
any private data:

```bash
python scripts/collect_internal_pilot_evidence.py schema
```

Generate a site-controlled record from that schema. Do not add note, message,
hostname, path, sample, read-name, stdout, stderr, raw-log, actor, owner-name,
or arbitrary metadata fields; unknown fields are rejected without echoing
their values.

## Sanitized-record identity

The top-level identity is deliberately narrow:

| Field | Requirement |
|---|---|
| `format_version` | Exactly `1.0` |
| `collection_policy_version` | Exactly `1.0` |
| `pilot_id` | Anonymous `pilot-YYYYMMDD-NNN` |
| `environment_id` | Anonymous `env-NNN` |
| `recorded_at` | UTC whole seconds as `YYYY-MM-DDTHH:MM:SSZ` |
| `data_boundary` | Exactly `non_sensitive_only` |
| `expected_evidence` | Exact release ID, 40-hex commit, and three 64-hex M6.1 manifest hashes |

The compiler derives all tool and contract versions from the verified release
candidate. It does not trust input versions.

## Required case slots

The input must contain exactly one anonymous slot for each scenario:

- `plain_fastq_single_end`
- `gzip_paired_end`
- `paired_end_multi_lane`
- `missing_mate`
- `ambiguous_naming`
- `synthetic_execution_failure`

Each `case_id` is only `case-NNN`. A required slot may honestly be
`unexecuted` or `evidence_missing`; the compiler can still create an incomplete
review draft. Missing a required slot is a malformed record, not shorthand for
an unexecuted case.

| Case state | Meaning and required evidence |
|---|---|
| `unexecuted` | No timestamp, counts, gates, transitions, hashes, usage, errors, or audit result may be present |
| `evidence_missing` | Activity is known or suspected, but controlled evidence is unavailable; it never counts as success |
| `succeeded` | Only the first three scenarios; all gates passed, terminal return code zero, audit checks recorded passed, counts/usage and fixed-role hashes present |
| `blocked` | The missing-mate scenario stopped before execution with an allowlisted missing-mate code |
| `resolved` | The ambiguity scenario has a restricted attributable-override record SHA-256 |
| `failed_queryable` | The synthetic failure reached a terminal nonzero state and has run-ID/status-report hashes |
| `failed` | An unexpected or unqueryable failure; never counts toward readiness |

Allowed case observations are limited to scan file count/duration, manifest
sample/lane counts, validation/test/preflight status and code, ordered run
state transitions and return code, work/output usage buckets, external-command
timeout/error-code counts, four reported audit-check states, and fixed-role
SHA-256 values.

The fixed-role hashes include the resolved manifest, pipeline spec, execution
plan, software lock, execution profile, controlled reports, audit record,
project/bundle/command/environment identity. When all five core artifact hashes
are present, the compiler recomputes their project hash for internal
consistency. It still does not read or authenticate the source artifacts.

The three recorded successful cases must have distinct project, bundle, and
hashed run identities before the draft can be ready for review. Distinct hashes
are only an internal consistency check; an independent reviewer must still
prove that the underlying runs and output targets were genuinely independent.

Use `run_id_sha256`, never a raw run ID, in the lower-trust record.

## Failure drills

The record may contain at most one anonymous entry for each reviewed drill
type. `drill_id` is only `drill-NNN`; codes are selected from a type-specific
allowlist. An executed drill needs a canonical UTC time, stable observed code,
`control_relaxed: false`, and a controlled-evidence SHA-256.

Allowed types are:

- `host_key_mismatch`
- `source_unreachable`
- `path_outside_allowlist`
- `unsafe_writable_input`
- `container_unavailable`
- `existing_output`
- `stale_preflight`
- `approval_omitted`
- `lost_submit_response`
- `low_disk_space`

`unexecuted`, `evidence_missing`, `blocked_expected`, `recovered`, and `failed`
are distinct. Only `recovered` counts toward the minimum three recorded
failure/recovery drills; `blocked_expected` proves no recovery. The source
evidence remains subject to independent review.

## Governance-only fields

Owner identities never enter this record. Each of the `backup`, `capacity`,
`incident`, `key_rotation`, and `retention` roles records only `pending`, or
`recorded_in_restricted_system` plus the restricted record SHA-256.

Capacity contains only deploy/work/output/cache usage buckets and decision
states. Exact bytes, inodes, quotas, filesystem names, or locations stay in the
restricted worksheet. An observed backup restore must include its restricted
record SHA-256. An observed documentation-only operation also requires its
restricted record SHA-256. Control deviation, friction, corrective action, and
next recommendation all use fixed enums and anonymous IDs. There are no
free-text description fields.

`friction_review_status` distinguishes `not_recorded`, `recorded_none`, and
`recorded_with_findings`. An empty list can reach readiness only when the
operator explicitly records that the review found no friction; omission is not
treated as a clean result.

The entry gate is also a restricted-record pointer. `not_recorded` and
`recorded_pending_independent_review` remain incomplete. Readiness requires
`recorded_complete_in_restricted_system`, meaning the site record attests that
the M6.1 signed checklist, independently reviewed real-host evidence, and exact
tag required by the pilot runbook already exist. The compiler verifies only
the pointer's format and cannot authenticate that operator attestation.

An unrecorded friction review, unresolved blocking friction, any control deviation, missing ownership,
pending capacity/retention decisions, an untested restore, assisted operation,
fewer than three recorded drills, incomplete cases, or a recommendation other
than `request_independent_m62_review` keeps the criteria state
`INCOMPLETE_OR_BLOCKED`.

## Offline verification

Verification reads only the fixed three-file bundle. It does not use Git,
network, subprocesses, the current repository, a generated project, or private
state:

```bash
python scripts/collect_internal_pilot_evidence.py verify \
  --directory /restricted/pilot/pilot-20260719-001-review-draft
```

A successful verifier result means only that the strict summary, deterministic
Markdown projection, and checksum manifest are internally consistent. It does
not authenticate the producer or source evidence and does not change the
fixed `BLOCKED` decision.

## Remaining operator and reviewer work

The tool cannot complete any of the following:

- M6.1 independent sign-off and release tag;
- dataset classification and organizational authorization;
- account, key, host, root, runtime, container, retention, backup, capacity,
  incident, or rotation provisioning;
- execution of the six pilot cases or failure/recovery drills;
- inspection of full reports, audit history, output, or scientific results;
- verification that executions were independent;
- recording actual operator friction and corrective ownership; or
- independent M6.2 review and organizational authorization.

Follow the [internal pilot runbook](internal-pilot-runbook.md) and companion
operations runbooks. Never commit an executed bundle or real site record to
this repository.
