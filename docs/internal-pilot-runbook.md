# Non-sensitive internal pilot runbook

> Status: **PROCEDURE_ONLY — UNEXECUTED TEMPLATE**.
>
> This document is not evidence that an internal pilot, real-host acceptance,
> release review, or security approval occurred. Keep every checkbox unchecked
> in the repository. Record executed copies in the site's controlled evidence
> system, never by adding real hosts, paths, sample names, or secrets here.

This runbook prepares the M6.2 non-sensitive internal pilot. It does not change
the M6.1 release gate: the signed release checklist, isolated real-host
acceptance, independent review, and exact release tag must exist before an
organizational pilot begins.

The pilot exercises only the reviewed FASTQ-QC workflow. It is not a production
release, clinical validation, patient-data workflow, Slurm test, or permission
to weaken a blocking control.

## Pilot record

Complete these fields in the controlled copy before execution:

- Pilot ID: `________________`
- Exact commit/tag: `________________`
- Release-evidence checksum: `________________`
- Pilot owner: `________________`
- Operator: `________________`
- Real-data approver, if different: `________________`
- Data owner: `________________`
- Security/incident contact: `________________`
- Capacity owner: `________________`
- Retention/backup owner: `________________`
- Start/end time in UTC: `________________`
- Evidence location and access class: `________________`

Do not put an SSH private key, approval HMAC key, complete hostname, raw path,
full manifest, samplesheet, read name, or unsanitized QC output in this record.

## Entry gate

- [ ] The M6.1 checklist is independently signed for the exact commit/tag.
- [ ] Exact-main CI and release acceptance passed for that commit.
- [ ] Isolated real SSH/ForceCommand acceptance passed and its sanitized
      evidence was independently reviewed.
- [ ] The dataset is synthetic, public and permitted, or formally approved as
      non-sensitive test data; it contains no patient or clinical data.
- [ ] Probe and executor accounts, constrained keys, host keys, roots, runtime,
      containers, approval key, and owners are provisioned under site policy.
- [ ] Backup, retention, incident, capacity, and key-rotation decisions are
      recorded before any run.
- [ ] The operator has read the [operations guide](operations.md),
      [security model](security-model.md), and
      [known limitations](known-limitations.md).

The controlled pilot record must also name the owners and approved procedures
from the [key-rotation](key-rotation-runbook.md),
[backup/retention](backup-retention-runbook.md),
[incident-response](incident-response-runbook.md), and
[capacity/quota](capacity-and-quota-runbook.md) runbooks.

If any entry item is missing, stop. Preparing this repository or passing local
CI does not satisfy the gate.

## Required pilot cases

Use a new project name and new work/output target for every case. A failed case
must never be repaired by editing a finalized artifact or reusing an existing
output.

| Case | Expected result | Evidence to retain |
|---|---|---|
| Plain FASTQ single-end | Complete successful run | Sanitized counts, fixed statuses, hashes |
| Gzip paired-end | Complete successful run | Sanitized counts, fixed statuses, hashes |
| Paired-end multi-lane | Complete successful run | Sanitized counts, fixed statuses, hashes |
| Missing mate | Inspection/manifest remains blocked | Stable error/finding code and remediation |
| Ambiguous naming | Attributable override creates a new resolved manifest | Override actor and artifact hashes, not names |
| Synthetic execution failure | Exact run reaches failed status and remains queryable | Run ID, status transition, return/command/environment hashes |

The first three rows provide the minimum three independent successful runs.
Do not count repeated invocations of the same project/output as independent.

## Prepare one case

Work from a clean reviewed checkout and the pinned supported environment:

```bash
git status --short --branch
git rev-parse HEAD
python scripts/generate_supply_chain_inventory.py verify
biopipe version --json
biopipe schema list --json
```

Record only the exact commit and non-sensitive version/digest fields. Confirm
the intended source and execution profiles without exporting their complete
contents into the pilot record:

```bash
biopipe source show pilot-source --json
biopipe source verify pilot-source --dry-run --json
biopipe source verify pilot-source --json
biopipe execution-profile show pilot-executor \
  --profile-dir execution-profiles \
  --json
```

An unknown or changed host key is a blocking incident. Follow the authenticated
host-key process; never bypass strict checking.

## Discover, plan, and validate

Use one anonymous case identifier in display-safe notes. The real source path
belongs only in the controlled command environment and generated full
artifacts. A metadata-only request can be reviewed separately, but preview the
exact format-summary request—including its sampling bound and output—before
executing it:

```bash
biopipe inspect pilot-source:/approved/non-sensitive/case-001 \
  --policy metadata-only \
  --dry-run \
  --json

biopipe inspect pilot-source:/approved/non-sensitive/case-001 \
  --policy format-summary \
  --sample-fastq-records 1000 \
  --output pilot/case-001/dataset.manifest.json \
  --dry-run \
  --json

biopipe inspect pilot-source:/approved/non-sensitive/case-001 \
  --policy format-summary \
  --sample-fastq-records 1000 \
  --output pilot/case-001/dataset.manifest.json \
  --json

biopipe manifest show pilot/case-001/dataset.manifest.json --json
```

Every case that proceeds to planning needs a reviewed version-1 override and a
new resolved bundle. For an unambiguous valid manifest, use empty
`rename_samples`, `exclude_files`, and `manual_pairs` collections and record
that the manifest was reviewed unchanged. For the naming-ambiguity case, put
only the reviewed rename/pairing decision in the controlled override. A missing
mate that remains unresolved must stop before planning. Never edit the original
manifest:

```yaml
override_version: "1.0"
rename_samples: {}
exclude_files: []
manual_pairs: []
reason: Reviewed unchanged for the non-sensitive pilot.
approved_by: pilot_operator
```

Save that controlled content as `pilot/case-001/manifest.overrides.yaml`, then
preview and apply it:

```bash
biopipe manifest apply-overrides \
  pilot/case-001/dataset.manifest.json \
  --overrides pilot/case-001/manifest.overrides.yaml \
  --output-dir pilot/case-001/resolved \
  --name dataset \
  --dry-run \
  --json

biopipe manifest apply-overrides \
  pilot/case-001/dataset.manifest.json \
  --overrides pilot/case-001/manifest.overrides.yaml \
  --output-dir pilot/case-001/resolved \
  --name dataset \
  --json
```

Plan with unique reviewed work/results paths, then generate, validate, and test:

```bash
biopipe plan \
  --manifest pilot/case-001/resolved/dataset.manifest.resolved.json \
  --goal fastq-qc \
  --project-name pilot-case-001 \
  --source-host pilot-source \
  --execution-host pilot-source \
  --work-dir /srv/biopipe/work/pilot-case-001 \
  --results-dir /srv/biopipe/results/pilot-case-001 \
  --container-cache /srv/biopipe/container-cache/pilot-case-001 \
  --executor local \
  --container-engine docker \
  --output pilot/case-001/planned/pipeline.spec.yaml \
  --dry-run \
  --json

biopipe plan \
  --manifest pilot/case-001/resolved/dataset.manifest.resolved.json \
  --goal fastq-qc \
  --project-name pilot-case-001 \
  --source-host pilot-source \
  --execution-host pilot-source \
  --work-dir /srv/biopipe/work/pilot-case-001 \
  --results-dir /srv/biopipe/results/pilot-case-001 \
  --container-cache /srv/biopipe/container-cache/pilot-case-001 \
  --executor local \
  --container-engine docker \
  --output pilot/case-001/planned/pipeline.spec.yaml \
  --json

biopipe generate \
  --spec pilot/case-001/planned/pipeline.spec.yaml \
  --output pilot/case-001/generated \
  --dry-run \
  --json
biopipe generate \
  --spec pilot/case-001/planned/pipeline.spec.yaml \
  --output pilot/case-001/generated \
  --json
biopipe validate pilot/case-001/generated --dry-run --json
biopipe validate pilot/case-001/generated --json
biopipe test pilot/case-001/generated --profile test --dry-run --json
biopipe test pilot/case-001/generated --profile test --json
```

Both controlled reports must be wholly passed. `degraded`, a missing real tool,
or an edited report is blocking. This example selects Docker; if the reviewed
profile uses Apptainer, both plan invocations must instead explicitly select
`--container-engine apptainer` and the profile must bind every locked SIF.

## Controlled execution-failure case

There is no generic fault-injection or cancel command. Before this case, the
host/runtime owner must approve a site-local method that targets only the exact
synthetic/non-sensitive pilot run and causes its Nextflow child to exit nonzero
while the executor supervisor remains able to record terminal state. Use a
dedicated account or cgroup and isolated work/output roots, and bind the action
to the returned run ID.

Do not edit generated artifacts, locks, containers, raw inputs, reports, audit,
or private state; do not kill an ambiguous process or shared runtime daemon.
Query the exact run ID until it reports `failed`, then retain only the allowed
status/code and hashes. If the site cannot prove exact targeting and reliable
supervisor reporting, do not improvise: leave this pilot case and M6.2
acceptance incomplete.

## Preflight, approval, and status

Preflight and submission use the immutable profile selected for this case:

```bash
biopipe preflight pilot/case-001/generated \
  --execution-profile execution-profiles/pilot-executor.json \
  --dry-run \
  --json

biopipe preflight pilot/case-001/generated \
  --execution-profile execution-profiles/pilot-executor.json \
  --json

biopipe run pilot/case-001/generated \
  --execution-profile execution-profiles/pilot-executor.json \
  --actor pilot_operator \
  --approve-real-data \
  --dry-run \
  --json
```

Review the exact frozen artifacts, successful reports, fresh preflight,
deployment target, actor, and dataset authorization before removing
`--dry-run`. A dry-run is not approval and does not reserve a submission.

```bash
biopipe run pilot/case-001/generated \
  --execution-profile execution-profiles/pilot-executor.json \
  --actor pilot_operator \
  --approve-real-data \
  --json

biopipe run pilot/case-001/generated \
  --execution-profile execution-profiles/pilot-executor.json \
  --status run-0123456789abcdef0123456789abcdef \
  --json
```

Keep the exact returned run ID in the controlled record. Do not infer that a
timeout means no run started; follow the response-loss procedure in the
[troubleshooting guide](troubleshooting.md).

## Failure drills

Execute at least three reviewed drills without weakening a control. Prefer a
dedicated synthetic fixture or isolated test account. A normal preflight
failure is recorded in stdout and `reports/preflight.json` as a failed named
check; it is not necessarily a stderr error envelope.

| Drill | Expected blocking evidence | Recovery authority |
|---|---|---|
| Host-key mismatch | `SSH_HOST_KEY_MISMATCH` | Site SSH administrator verifies fingerprint |
| Source unreachable | `SSH_CONNECTION_FAILED` or `SSH_TIMEOUT` | Network/host owner restores service |
| Path outside root | Controller `VALIDATION_FAILED`, or probe `PROBE_REMOTE_FAILED` with `probe_code=PATH_OUTSIDE_ALLOWLIST` | Data owner selects an approved path; root widening requires review |
| Unsafe writable input | Failed `rawdata_readable` check / `UNTRUSTED_PATH_PERMISSIONS` for an unsafe file or parent chain | Data administrator creates a trusted read-only projection |
| Container absent | Failed `container` check / Docker `IMAGE_UNAVAILABLE` or missing-SIF `PATH_UNAVAILABLE` | Runtime owner preloads the exact locked image/SIF |
| Existing output | Controller `DEPLOYMENT_FAILED` with `PATH_OUTPUT_CONFLICT`; a remote race reports `TARGET_ALREADY_EXISTS` through `RUN_SUBMISSION_FAILED` | Operator creates a newly reviewed project target |
| Stale preflight | `PREFLIGHT_STALE` | Operator runs a fresh preflight and approval |
| Approval omitted | `APPROVAL_REQUIRED` | Approver reviews and supplies a new attributable approval |
| Lost submit response | Original transport error such as `SSH_TIMEOUT`, with `run_id` and `status_query_required=true`; resubmission while pending is `RUN_SUBMISSION_FAILED` | Operator queries the exact run ID before reconciliation |
| Low disk space | Failed `disk_space` check / `INSUFFICIENT_SPACE` | Capacity owner frees/allocates reviewed capacity, then reruns preflight |

Record expected and observed stable codes, timestamps, exact commit, and a
sanitized evidence checksum. Do not store full SSH diagnostics or command logs.

## Internal pilot report template

Produce the report only from controlled case records. Keep this repository
template blank:

| Field | Controlled summary |
|---|---|
| Exact commit/tag and evidence checksum | `________________` |
| Successful independent cases | Anonymous case IDs and fixed terminal status |
| Failed/recovery drills | Anonymous drill IDs, expected/observed code, recovery result |
| Operator friction | Friction ID, affected step, impact category, no host/path/sample detail |
| Control deviations | `none`, or stop the pilot and link a restricted incident/change record |
| Capacity/retention findings | Approved buckets and owner decision |
| Corrective actions | Action ID, owner, priority, due date, verification method |
| Next recommendation | Repeat pilot, remain blocked, or request independent M6.2 review |

Do not recommend wider roots, weaker permissions, disabled host-key checking,
lowered free-space thresholds, floating containers, skipped gates, or duplicate
submission as an operator convenience. Unresolved blocking friction keeps the
pilot incomplete.

## Evidence and closeout

Allowed pilot summary fields include case ID, exact source identity, tool and
contract versions, counts, fixed statuses/codes, timestamps, run ID, and
SHA-256 values. Full manifests, paths, sample names, QC reports, raw logs,
private state, keys, tokens, and signatures stay inside their original access
boundary.

After the controlled record is complete, create a distinct strict sanitized
projection and use the [internal pilot evidence compiler](internal-pilot-evidence.md)
to produce a create-only review draft outside this worktree. The compiler uses
hashed run identities rather than raw run IDs and cannot execute or validate
the pilot source records. Its fixed `BLOCKED`/unreviewed output does not check
any box below.

- [ ] Three independent approved non-sensitive runs reached terminal success.
- [ ] At least three failure/recovery drills produced the expected blocking
      evidence without relaxed controls.
- [ ] Audit order and hashes were checked for each successful run.
- [ ] Work/output capacity and retention decisions were recorded.
- [ ] Backup restoration was tested in an isolated non-live location.
- [ ] Operator friction, deviations, and remediation owners were recorded.
- [ ] An independent reviewer linked every conclusion to the exact commit and
      controlled evidence checksum.
- [ ] No real host, path, sample identifier, secret, token, signature, or raw
      command output entered source control or a lower-trust report.

Use the companion [key-rotation](key-rotation-runbook.md),
[backup/retention](backup-retention-runbook.md),
[incident-response](incident-response-runbook.md), and
[capacity/quota](capacity-and-quota-runbook.md) runbooks for operational
ownership. An executed pilot remains non-production evidence and does not
expand the supported workflow or security claims.
