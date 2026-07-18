# CLI reference

This reference covers every public MVP leaf command. Run `biopipe COMMAND
--help` for the complete option ranges. All examples assume execution from a
reviewed checkout or installed environment.

## Output, dry-run, and exit contract

Every leaf command accepts `--json`. Without it, results are indented JSON;
with it, results are compact deterministic JSON suitable for machine parsing.
After argument parsing succeeds, application errors are one stable JSON envelope
on stderr. Typer/Click usage errors (for example, a missing required argument)
remain human-readable help on stderr and still exit `2`; callers must construct
the command correctly before relying on the JSON application contract.

The frozen CLI contract uses:

| Exit | Meaning |
|---:|---|
| `0` | Command completed successfully |
| `2` | Argument, validation, blocked workflow, approval, remote, or operational failure |

Inspect the structured `status`, `code`, or `error.code`; do not infer a
specific failure category from exit `2` alone.

Commands that can write, invoke SSH, execute an external tool, read an approval
key, sign, deploy, or mutate remote state accept `--dry-run`. A successful
dry-run returns this common contract:

```json
{
  "cli_contract_version": "1.0",
  "command": "...",
  "details": {},
  "dry_run": true,
  "remote_operations": [],
  "side_effects_performed": false,
  "status": "would_...",
  "would_write": []
}
```

Dry-run may read and strictly validate existing local inputs. `validate` and
`test` dry-runs perform static project checks; `preflight` performs local static
checks; none invokes the external workflow/runtime or writes a report. A dry-run
is not a preflight result or real-data approval.

`run` submit and resume dry-runs additionally require an attributable actor and
the explicit `--approve-real-data` mode flag, then revalidate the complete frozen
generated project, execution profile, successful validation/test reports, and
the bound fresh public preflight report. It deterministically hashes the frozen
production snapshot without compiling or packaging a deployment, then binds the
private preflight ID, timestamp, report, bundle hash, and deterministic
deployment location. It validates the opaque capability token's local shape;
only the real remote operation can verify that token's live acceptance. The
local gate also rejects pending submissions, an unrecorded or non-terminal
resume source, incompatible prior authorization inputs, and a preflight
timestamp later than the hypothetical approval. Only after those checks pass
does the envelope include `"local_gate_validation":"passed"`.
This is a point-in-time local evidence result: it does not read the HMAC key,
create an authorization, build a deployment, consume or write private state,
contact SSH, or reserve a future submission. The real command repeats its full
validation and may still fail. Status and pending-abandon dry-runs are operation
previews and do not require a fresh submission preflight.

## Global help and versions

Show the command tree or the short controller version:

```bash
biopipe --help
biopipe --version
```

### `biopipe version`

Report all compatibility identities and stable exit codes:

```bash
biopipe version --json
```

The output names `controller_version`, `probe_version`,
`remote_executor_version`, `registry_version`, `compiler_version`,
`schema_version`, and `cli_contract_version`. The package release and public
schema versions are deliberately independent.

## JSON Schema catalog

The frozen MVP catalog uses JSON Schema draft 2020-12 and schema version `1.0`.
It covers 21 public controller artifacts and persisted reports: source/probe,
manifest/override/override-diff, planning/lock/registry, execution
profile/preflight/authorization/run/status/reconciliation, static/runtime
validation, the outer `validation.json` and `test.json` command reports, and
audit contracts.

### `biopipe schema list`

List names, stable `$id` values, file names, per-schema SHA-256 values, and the
aggregate catalog hash:

```bash
biopipe schema list --json
```

### `biopipe schema show`

Print one schema selected by model name or schema filename:

```bash
biopipe schema show DatasetManifest --json
biopipe schema show ExecutionProfile.schema.json --json
```

### `biopipe schema export`

Preview and export every schema plus `catalog.json`:

```bash
biopipe schema export --output build/schema-v1 --dry-run --json
biopipe schema export --output build/schema-v1 --json
```

Choose a dedicated output directory and treat an intentional re-export as a
release operation. The command copies exact, committed package resources rather
than regenerating public schemas from the installed Pydantic version. Exported
documents contain `x-biopipe-schema-version: "1.0"`.

## Source profiles

Source profiles live by default below `~/.config/biopipe/sources`. They contain
SSH routing and probe limits, never SSH passwords or private keys.

### `biopipe source add`

Preview, then register one SSH alias and one or more absolute raw-data roots:

```bash
biopipe source add hpc01 \
  --host hpc01-probe \
  --allowed-root /data/raw \
  --remote-probe-path '~/.local/bin/bioprobe.pyz' \
  --dry-run \
  --json

biopipe source add hpc01 \
  --host hpc01-probe \
  --allowed-root /data/raw \
  --remote-probe-path '~/.local/bin/bioprobe.pyz' \
  --json
```

Repeat `--allowed-root` for separately approved trees. Optional `--username`
and `--port` become fixed SSH arguments. The registry is create-only.

### `biopipe source list`

```bash
biopipe source list --json
```

### `biopipe source show`

```bash
biopipe source show hpc01 --json
```

### `biopipe source verify`

Preview the selected local profile, then send only the fixed probe `health`
operation:

```bash
biopipe source verify hpc01 --dry-run --json
biopipe source verify hpc01 --json
```

Verification proves the constrained transport/probe responds with a configured
allowlist. It does not inspect a dataset.

### `biopipe source remove`

Preview and remove only the local SourceProfile:

```bash
biopipe source remove hpc01 --dry-run --json
biopipe source remove hpc01 --json
```

This never contacts the Source Host or removes its account, probe, config, or
data.

## Remote inspection

### `biopipe inspect`

Preview a metadata-only request without SSH:

```bash
biopipe inspect hpc01:/data/raw/run42 \
  --policy metadata-only \
  --dry-run \
  --json
```

Run metadata-only inspection without writing an artifact:

```bash
biopipe inspect hpc01:/data/raw/run42 \
  --policy metadata-only \
  --json
```

Build the full/sanitized FASTQ manifest bundle and optional candidate
samplesheet:

```bash
biopipe inspect hpc01:/data/raw/run42 \
  --policy format-summary \
  --sample-fastq-records 1000 \
  --output projects/run42/dataset.manifest.json \
  --json
```

`target` must use `SOURCE_ID:/absolute/path`. Policy is exactly
`metadata-only` or `format-summary`. Output artifacts are create-only; reads are
not copied to the controller.

## Dataset manifests

### `biopipe manifest show`

Verify the embedded digest and print a sample/lane/pairing/error summary:

```bash
biopipe manifest show projects/run42/dataset.manifest.json --json
```

### `biopipe manifest apply-overrides`

Resolve a version-1 attributable JSON/YAML override in memory, then create the
resolved bundle:

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

The original manifest/override are never modified. A samplesheet is omitted if
blocking errors remain.

## Planning and generation

### `biopipe plan`

Preview and create the fixed FASTQ-QC planning bundle:

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
  --container-engine apptainer \
  --max-cpus 4 \
  --max-memory-gb 16 \
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
  --container-engine apptainer \
  --max-cpus 4 \
  --max-memory-gb 16 \
  --output projects/run42/planned/pipeline.spec.yaml \
  --json
```

Enable the fixed fastp stage only with controlled input:

```bash
biopipe plan \
  --manifest projects/run42/resolved/dataset.manifest.resolved.json \
  --output projects/run42/trimmed/pipeline.spec.yaml \
  --trimming \
  --minimum-length 30 \
  --json
```

Only `fastq-qc` is supported. `local` is the only M5-executable profile;
`slurm` generation is a site placeholder. If hosts differ, provide
`--execution-root` and a matching execution profile path mapping.

### `biopipe generate`

Preview and compile from the reviewed sibling manifest, plan, and lock:

```bash
biopipe generate \
  --spec projects/run42/planned/pipeline.spec.yaml \
  --output projects/run42/generated \
  --dry-run \
  --json

biopipe generate \
  --spec projects/run42/planned/pipeline.spec.yaml \
  --output projects/run42/generated \
  --json
```

Use `--manifest`, `--execution-plan`, and `--software-lock` only to select
explicit alternatives that are validated together. The output directory must
not exist.

## Validation and synthetic test

### `biopipe validate`

Static-only dry-run, then full validation:

```bash
biopipe validate projects/run42/generated --dry-run --json
biopipe validate projects/run42/generated \
  --timeout-seconds 300 \
  --output-limit-bytes 262144 \
  --json
```

The full command writes `reports/validation.json`. `--fixture-root` may select a
reviewed layout-matched synthetic fixture. Any `failed`, `blocked`, or
`degraded` result exits `2`.

### `biopipe test`

Static-only dry-run, then the only supported test profile:

```bash
biopipe test projects/run42/generated --profile test --dry-run --json
biopipe test projects/run42/generated \
  --profile test \
  --timeout-seconds 300 \
  --output-limit-bytes 262144 \
  --json
```

The full command runs stub and tiny native-tool E2E layers and writes
`reports/test.json`. It never accepts a real-data fixture.

## Execution profiles

### `biopipe execution-profile create`

This example creates a Docker profile. Preview does not read the approval key
or write the profile; the real command validates the owner-only key first:

```bash
biopipe execution-profile create hpc01-local \
  --source-host hpc01 \
  --execution-host hpc01 \
  --ssh-alias hpc01-exec \
  --software-lock projects/run42/generated/software.lock.yaml \
  --output-dir execution-profiles \
  --deploy-root /srv/biopipe/deployments \
  --work-root /srv/biopipe/work \
  --output-root /srv/biopipe/results \
  --cache-root /srv/biopipe/container-cache \
  --container-engine docker \
  --approval-key-id controller-2026-01 \
  --approval-key-file /secure/biopipe/controller-2026-01.hex \
  --dry-run \
  --json
```

Remove `--dry-run` to register the immutable profile. For Apptainer, repeat
`--sif NAME=/absolute/image.sif` and `--sif-sha256 NAME=SHA256` for every tool
in the selected software lock. Repeat `--path-mapping SOURCE=EXECUTION` for
reviewed shared-filesystem mappings. See [remote deployment](remote-deployment.md).

### `biopipe execution-profile show`

```bash
biopipe execution-profile show hpc01-local \
  --profile-dir execution-profiles \
  --json
```

## Preflight and controlled execution

### `biopipe preflight`

Run local static checks without SSH/report writes, then execute the fixed remote
preflight:

```bash
biopipe preflight projects/run42/generated \
  --execution-profile execution-profiles/hpc01-local.json \
  --dry-run \
  --json

biopipe preflight projects/run42/generated \
  --execution-profile execution-profiles/hpc01-local.json \
  --json
```

The full command writes `reports/preflight.json` plus owner-only one-use state.
It does not deploy or run the workflow. For resume evidence:

```bash
biopipe preflight projects/run42/generated \
  --execution-profile execution-profiles/hpc01-local.json \
  --resume run-0123456789abcdef0123456789abcdef \
  --json
```

### `biopipe run`: submit

Previewing submission first validates the current local submission gate,
including a read-only deterministic hash of the frozen production files. It
reads no approval key, signs nothing, compiles or packages no deployment, writes
nothing, and contacts no SSH host:

```bash
biopipe run projects/run42/generated \
  --execution-profile execution-profiles/hpc01-local.json \
  --actor operator_id \
  --approve-real-data \
  --dry-run \
  --json
```

A successful preview preserves the common contract and adds:

```json
{
  "local_gate_validation": "passed",
  "side_effects_performed": false,
  "status": "would_submit"
}
```

`--approve-real-data` is required here to validate the requested submission
mode, but a dry-run is never approval: it creates no authorization or signature
and changes no state. Omitting the flag returns `APPROVAL_REQUIRED` before local
evidence is read, just as omitting the actor does.

After review, the real initial submission requires both attribution and the
explicit approval flag:

```bash
biopipe run projects/run42/generated \
  --execution-profile execution-profiles/hpc01-local.json \
  --actor operator_id \
  --approve-real-data \
  --json
```

### `biopipe run`: status

```bash
biopipe run projects/run42/generated \
  --execution-profile execution-profiles/hpc01-local.json \
  --status run-0123456789abcdef0123456789abcdef \
  --json
```

Status cannot be combined with actor, approval, or resume. A remote failed
status exits `2`.

### `biopipe run`: resume

After the matching `preflight --resume`, provide a new explicit approval:

```bash
biopipe run projects/run42/generated \
  --execution-profile execution-profiles/hpc01-local.json \
  --resume run-0123456789abcdef0123456789abcdef \
  --actor operator_id \
  --approve-real-data \
  --json
```

### `biopipe run`: reconcile a pending response loss

Only a recorded pending run, after the fixed safety delay, can be abandoned:

```bash
biopipe run projects/run42/generated \
  --execution-profile execution-profiles/hpc01-local.json \
  --abandon-pending run-0123456789abcdef0123456789abcdef \
  --dry-run \
  --json

biopipe run projects/run42/generated \
  --execution-profile execution-profiles/hpc01-local.json \
  --abandon-pending run-0123456789abcdef0123456789abcdef \
  --json
```

This signs a fixed remote tombstone. It is not cancellation, deletion, or
confirmation that an arbitrary remote process is absent.
