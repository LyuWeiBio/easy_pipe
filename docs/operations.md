# Operations guide

This is the day-to-day runbook for the completed MVP. Installation, remote
account hardening, and initial key/config provisioning are covered by the
[remote deployment guide](remote-deployment.md).

## Before each project

Confirm the controller and public contracts:

```bash
biopipe version --json
biopipe schema list --json
```

Verify that the selected SourceProfile and immutable execution profile identify
the intended hosts and roots. `source verify` sends only the fixed probe health
operation. `execution-profile show` is local and does not contact the executor:

```bash
biopipe source show hpc01 --json
biopipe source verify hpc01 --json
biopipe execution-profile show hpc01-local \
  --profile-dir execution-profiles \
  --json
```

Unknown or changed host keys are blocking. Resolve them through the site's
authenticated host-key process; never bypass strict checking.

## Discover and review data

Start with metadata-only inspection when the delivery boundary is unfamiliar:

```bash
biopipe inspect hpc01:/data/raw/run42 \
  --policy metadata-only \
  --dry-run \
  --json
```

Then create the FASTQ manifest bundle:

```bash
biopipe inspect hpc01:/data/raw/run42 \
  --policy format-summary \
  --sample-fastq-records 1000 \
  --output projects/run42/dataset.manifest.json \
  --json

biopipe manifest show projects/run42/dataset.manifest.json --json
```

Inspection is bounded and read-only. The full manifest and samplesheet contain
real names and paths; keep them inside the controller's data boundary. Review
pairing warnings/errors and compare them with the delivery record without
copying FASTQ content into notes.

If a reviewed rename, exclusion, or manual pair is required, create an
attributable override and preview/apply it:

```bash
biopipe manifest apply-overrides \
  projects/run42/dataset.manifest.json \
  --overrides projects/run42/manifest.overrides.yaml \
  --output-dir projects/run42/resolved \
  --name dataset \
  --dry-run \
  --json

biopipe manifest apply-overrides \
  projects/run42/dataset.manifest.json \
  --overrides projects/run42/manifest.overrides.yaml \
  --output-dir projects/run42/resolved \
  --name dataset \
  --json
```

Overrides create new artifacts and never change the scan facts. See the
[manifest workflow](manifest-workflow.md).

## Plan, generate, validate, and test

Choose execution-host paths that fall below the execution profile's reviewed
work, output, and cache roots and do not overlap raw data:

```bash
biopipe plan \
  --manifest projects/run42/resolved/dataset.manifest.resolved.json \
  --goal fastq-qc \
  --project-name run42-fastq-qc \
  --source-host hpc01 \
  --execution-host hpc01 \
  --work-dir /srv/biopipe/work/run42-fastq-qc \
  --results-dir /srv/biopipe/results/run42-fastq-qc \
  --container-cache /srv/biopipe/container-cache/run42-fastq-qc \
  --output projects/run42/planned/pipeline.spec.yaml \
  --dry-run \
  --json

biopipe plan \
  --manifest projects/run42/resolved/dataset.manifest.resolved.json \
  --goal fastq-qc \
  --project-name run42-fastq-qc \
  --source-host hpc01 \
  --execution-host hpc01 \
  --work-dir /srv/biopipe/work/run42-fastq-qc \
  --results-dir /srv/biopipe/results/run42-fastq-qc \
  --container-cache /srv/biopipe/container-cache/run42-fastq-qc \
  --output projects/run42/planned/pipeline.spec.yaml \
  --json

biopipe generate \
  --spec projects/run42/planned/pipeline.spec.yaml \
  --output projects/run42/generated \
  --json

biopipe validate projects/run42/generated --json
biopipe test projects/run42/generated --profile test --json
```

Add `--trimming --minimum-length 30` during planning only after reviewing that
policy. Planning/generation are create-only. Validation and test may replace
only their allowlisted report files; they do not alter generated sources.

Both `reports/validation.json` and `reports/test.json` must say `passed`.
`degraded` is a nonzero blocking outcome, not partial approval. Review the
[validation guide](m4-validation-testing.md) for exact checks and output
assertions.

## Preflight and submission

Preview and execute preflight after validation/test:

```bash
biopipe preflight projects/run42/generated \
  --execution-profile execution-profiles/hpc01-local.json \
  --dry-run \
  --json

biopipe preflight projects/run42/generated \
  --execution-profile execution-profiles/hpc01-local.json \
  --json
```

Review `reports/preflight.json`, including all ten fixed checks, exact profile
and project hashes, mapped input count/hash, container evidence, writable
targets, and freshness deadline. Preflight does not deploy or submit.

Use a dry-run immediately before approval:

```bash
biopipe run projects/run42/generated \
  --execution-profile execution-profiles/hpc01-local.json \
  --actor operator_id \
  --approve-real-data \
  --dry-run \
  --json
```

After an attributable review, remove only `--dry-run`:

```bash
biopipe run projects/run42/generated \
  --execution-profile execution-profiles/hpc01-local.json \
  --actor operator_id \
  --approve-real-data \
  --json
```

Keep the returned `run_id`. The fixed status mode is:

```bash
biopipe run projects/run42/generated \
  --execution-profile execution-profiles/hpc01-local.json \
  --status run-0123456789abcdef0123456789abcdef \
  --json
```

Do not assume an SSH error means a submission did not start. The controller
persists recoverable pending state before the request. Query/retry the exact run
ID and follow the returned remediation. `--abandon-pending` is only a delayed,
signed response-loss reconciliation and is never a cancel command.

## Resume

Resume only a recorded compatible terminal run. Run a fresh resume preflight,
review it, then provide a new approval:

```bash
biopipe preflight projects/run42/generated \
  --execution-profile execution-profiles/hpc01-local.json \
  --resume run-0123456789abcdef0123456789abcdef \
  --json

biopipe run projects/run42/generated \
  --execution-profile execution-profiles/hpc01-local.json \
  --resume run-0123456789abcdef0123456789abcdef \
  --actor operator_id \
  --approve-real-data \
  --json
```

Changed core inputs, deployment, profile, containers, path identities, or prior
authorization make resume incompatible. Start a newly planned output target
instead of weakening that check.

## Artifact and retention map

| Location | Contents | Operational rule |
|---|---|---|
| Controller SourceProfile directory | SSH aliases and probe limits | No SSH credentials; remove only local registration |
| Project planning/generated directories | Full manifest, samplesheet, spec, lock, source | Treat as potentially sensitive and immutable |
| `PROJECT/reports/` | Validation, test, preflight, run/status evidence and owner-only recovery state | Preserve with the project; do not edit hidden state |
| `PROJECT/audit/events.jsonl` | Append-only lifecycle events | Restrict access; export/anchor under local policy |
| Remote deployment root | Bounded production snapshot | Never overwritten automatically |
| Remote work/output roots | Nextflow state and results | Never deleted automatically; site retention applies |
| Remote private state | Tokens, reservations, leases, bindings | Mode 0700; executor account only |

Hidden private controller report-state filenames are implementation details and
must not be used as a public API. Use CLI status/resume/reconciliation rather
than editing state.

## Routine controls

- Monitor free space on deploy, work, output, cache, and state filesystems.
- Monitor executor account processes, container daemon/cgroups, and host egress.
- Back up project/audit evidence according to data classification and retention
  requirements.
- Rotate constrained SSH and approval keys through a new reviewed profile and
  executor config; old preflights/approvals must not survive rotation.
- Re-run source verify after probe changes and preflight after any runtime,
  profile, path, image, JAR, or generated-artifact change.
- Never manually “fix” finalized artifact hashes or state files.

For failures, use the [troubleshooting guide](troubleshooting.md). For security
events, stop new approvals and follow [SECURITY.md](../SECURITY.md).
