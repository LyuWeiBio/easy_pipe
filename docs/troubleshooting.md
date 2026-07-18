# Troubleshooting

Start with the first failing boundary. Do not bypass host-key checks, widen an
allowlist, change permissions, edit a generated artifact, disable a digest
check, or add real-data approval simply to make an error disappear.

## Collect safe evidence

Prefer compact JSON and record only non-sensitive fields:

```bash
biopipe version --json
biopipe source show hpc01 --json
biopipe execution-profile show hpc01-local \
  --profile-dir execution-profiles \
  --json
```

Use `--dry-run --json` on a mutating or external-effect command before retrying.
Controller operational failures are emitted as one JSON error envelope on
stderr:

```json
{
  "error": {
    "code": "PREFLIGHT_FAILED",
    "severity": "blocking",
    "message": "...",
    "context": {},
    "remediation": ["..."]
  }
}
```

Follow the returned `remediation` values. Do not publish full manifests,
samplesheets, reports, audit logs, SSH diagnostics, configs, environment dumps,
or command output without review. They may contain paths, sample identifiers,
hostnames, or secrets. The application intentionally does not persist raw
stdout/stderr from Nextflow or remote commands in machine-readable reports.

## Exit status

The controller uses `0` for completed success and `2` for invalid arguments,
validation/test/preflight blocking results, approval denial, operational
failure, or a failed queried run. Inspect the structured status/error code
rather than subdividing failures by process exit value. A Typer/Click usage
error occurs before the application JSON contract and prints human-readable
help; correct the invocation before parsing stderr as JSON.

Remote protocol return codes are transported inside sanitized responses and
mapped to controller errors:

| Code | Probe | Executor |
|---:|---|---|
| 0 | Success | Success |
| 10 | Protocol/config/schema | Protocol/config/schema |
| 11 | Unsupported operation | Unsupported operation |
| 20 | Outside allowlist | Outside allowlist |
| 21 | Missing/unreadable path | Unavailable path |
| 22 | Symlink/path/mount escape | Symlink/path escape |
| 30 | Budget exceeded | Budget exceeded |
| 31 | Time exceeded | Time exceeded |
| 40 | Unsupported format | Preflight failed |
| 41 | Invalid FASTQ | Deployment failed |
| 42 | — | Approval required |
| 43 | — | State conflict |
| 44 | — | Run failed |
| 50 | Sanitized internal failure | Sanitized internal failure |

## Installation and command discovery

### `biopipe: command not found`

Activate the environment used for installation, then verify:

```bash
python -m pip show easy-pipe
python -m biopipe version --json
```

If `python -m biopipe` works but `biopipe` does not, the environment's scripts
directory is not on `PATH`. Re-activate the environment; do not install into an
unrelated system Python.

### Schema or version mismatch

Run:

```bash
biopipe version --json
biopipe schema list --json
```

Controller, generated artifacts, probe/executor protocol, registry, and
compiler versions are separate. Rebuild both zipapps from the matching reviewed
checkout. Version-1 readers reject unknown fields and unsupported versions; the
MVP does not migrate artifacts automatically.

## SSH and Source Host

### `SSH_HOST_KEY_MISMATCH`

Stop. Verify the host and fingerprint through the site's trusted channel, then
repair `known_hosts` through normal OpenSSH administration. Never use
`StrictHostKeyChecking=no` or automatically accept the new key.

### `SSH_AUTH_FAILED` or `SSH_CONNECTION_FAILED`

Confirm the selected alias and identity independently:

```bash
ssh -G hpc01-probe
ssh hpc01-probe
```

With a ForceCommand account, the second command waits for JSON input or returns
a protocol error; it is not an interactive shell. Check account/key status,
network routing, and the fixed command with the administrator. Do not copy a
private key into the project.

### `SSH_TIMEOUT`

Check host reachability, the profile timeout, filesystem health, and whether a
network mount is stalled. The probe checks a cooperative monotonic deadline,
but Python cannot interrupt a kernel call already blocked on a filesystem. The
outer SSH timeout may therefore occur before probe return code 31.

### `SSH_OUTPUT_LIMIT_EXCEEDED`

Narrow the requested tree or reduce entry/path counts. Review the host-local
response ceiling only if the intended metadata set is legitimate. Do not raise
the limit to accommodate unreviewed directory growth.

### `PROBE_PROTOCOL_ERROR`, `PROBE_REQUEST_MISMATCH`, or `PROBE_REMOTE_FAILED`

Verify that the controller and `bioprobe.pyz` came from compatible releases and
both use protocol `1.0`. Send the documented health envelope directly through
the ForceCommand. A health-only response with no active allowlist means the
probe configuration was not found or loaded.

### `PATH_OUTSIDE_ALLOWLIST`, `PATH_UNAVAILABLE`, or `SYMLINK_FORBIDDEN`

Use the canonical existing path below both the SourceProfile root and the
host-local probe root. The probe intentionally rejects the root itself when an
operation requires a file, parent traversal, final/intermediate symlinks, and
unapproved mount crossing. Widen a root only after a data-owner review.

### `SCAN_BUDGET_EXCEEDED` or `INVALID_FASTQ`

For a budget failure, inspect a narrower delivery directory or reduce the
requested record sample. For invalid FASTQ, verify compression, four-line
records, sequence/quality length, and mate delivery on the Source Host without
printing record contents into tickets or logs. Use an attributable manifest
exclusion only after scientific review; the detector never silently repairs a
malformed file.

## Manifest, planning, and generation

### `MANIFEST_INTEGRITY_FAILED`

Do not edit a finalized manifest. Re-run inspection into a new empty artifact
location, or apply a separate version-1 override. The embedded manifest digest
must match its canonical content.

### `MANIFEST_OVERRIDE_CONFLICT`

Check that every override path was scanned, is unique, remains below the scan
root, and does not split a paired lane or reuse one read. Unaddressed pairing
errors remain blocking. See [the manifest workflow](manifest-workflow.md).

### `ARTIFACT_WRITE_FAILED`, `MANIFEST_STORAGE_FAILED`, or existing output

Inspection, overrides, planning, profiles, generation, deployment, work, and
results use create-only semantics where replacement would be unsafe. Choose a
new empty destination. Do not remove an existing target until its provenance,
retention status, and active-run state are understood.

### Planning or registry validation failure

Only `--goal fastq-qc` and the reviewed component graph are supported. A full,
integrity-valid resolved manifest without blocking errors is required. Resource
limits must cover every selected component, execution paths must not overlap
raw data, and `minimum_length` is valid only with trimming.

### Generated content/hash mismatch

Generated files are immutable compiler outputs. Restore the exact generated
directory or regenerate into a new path from the original reviewed planning
bundle. Local workflow customization is outside the M5 execution contract and
must not be approved as though it were registry-generated code.

## Validation and synthetic test

The authoritative details are in `reports/validation.json` and
`reports/test.json`.

### `NEXTFLOW_NOT_FOUND` or `TOOL_NOT_FOUND`

Activate the pinned `easy-pipe-m4` environment and confirm the selected
executables with `command -v`. Do not substitute an unreviewed version. Missing
FastQC, fastp, or MultiQC blocks E2E.

### `TOOL_VERSION_MISMATCH`

The executable version differs from `software.lock.yaml`. Recreate the pinned
environment or regenerate from an intentionally updated registry; never edit
the lock to match whatever happens to be installed.

### `NF_TEST_NOT_FOUND` or `NF_TEST_SUITE_NOT_FOUND`

Validation is `degraded`, not passed. Install/activate the pinned nf-test
environment and retry. Degraded evidence cannot satisfy real-data approval.

### `COMMAND_TIMEOUT` or `COMMAND_OUTPUT_LIMIT`

Inspect resource pressure and the isolated run locally. The CLI accepts bounded
timeout/output ceilings for legitimate slow hosts, but increasing them does not
fix a hung tool or noisy failure. Raw command output is intentionally discarded
after the bounded decision.

### `STUB_RUN_FAILED`, `E2E_RUN_FAILED`, or `OUTPUT_ASSERTION_FAILED`

Check the report's failed check and remediation. A zero workflow return code is
insufficient: expected FastQC, fastp, MultiQC, trace, timeline, report, and DAG
artifacts must have the exact cardinality and basic parseable structure.
Re-run with committed synthetic data before considering real inputs.

## Execution profile and preflight

### `EXECUTION_PROFILE_INVALID`

Common causes are an unsafe/missing owner-only approval key; an edited or
existing profile; overlapping role roots; a path that is not absolute; missing
SIF path/hash assignments; SIFs outside the cache root; or Docker profiles that
declare SIFs. Profiles are immutable and create-only—register a new reviewed
profile instead of editing one.

### Remote `CONFIG_INVALID`

The executor config requires an exact field set, mode `0600`, trusted ownership,
and a no-follow trusted parent chain. All configured roots, executables, and the
JAR must exist at startup. Writable roots may not be group/world-writable or
overlap by path or filesystem identity; private state must be `0700`. Both
runtime keys are required, with the unused one set to `null`.

### `PROFILE_BINDING_MISMATCH`

Hash the exact controller profile file and compare it with remote
`profile_hash`. A whitespace or key-path change changes the file hash. Replace
the remote config/profile as a reviewed pair; do not patch the reported hash.

### Failed fixed preflight checks

The report contains exactly the controller SSH check plus these nine remote
checks:

- `host_relationship` and `path_mapping`;
- `rawdata_readable`;
- `workdir_writable`, `output_dir_writable`, and `cache_writable`;
- `disk_space`;
- `runtime`; and
- `container`.

`PATH_MAPPING_INCOMPLETE` means the Execution Host has no reviewed mapping for
one or more Source Host paths. `INSUFFICIENT_SPACE` means at least one deploy,
work, output, or cache filesystem is below the configured threshold.
`NEXTFLOW_VERSION_MISMATCH`, `EXECUTABLE_CHANGED`, or
`NEXTFLOW_JAR_CHANGED` requires restoring/reviewing the exact runtime and a new
preflight. `IMAGE_UNAVAILABLE`, `IMAGE_DIGEST_MISMATCH`, or
`IMAGE_LOCAL_ARTIFACT_REQUIRED` requires preloading the locked Docker identity
or the hash-matched SIF; the agent will not pull it.

### `OUTPUT_ALREADY_EXISTS`

Initial work and result targets are create-only. Select a new run target through
a newly reviewed plan/profile; do not point a new submission at old results.
Resume uses the exact previously recorded private directories and is a separate
mode.

## Approval, submission, status, and resume

### `APPROVAL_REQUIRED`

An attributable safe `--actor`, explicit `--approve-real-data`, valid private
controller key, fresh passed preflight, and all prior gates are mandatory. A
dry-run or past approval is not authorization.

### `APPROVAL_ARTIFACT_MISMATCH` or `PREFLIGHT_STALE`

One or more core/report/profile/bundle hashes changed, or the preflight exceeded
its freshness window. Re-run validation/test if their inputs changed, then run
a fresh preflight and perform a new review/approval. Never alter a report hash.

### `RUN_SUBMISSION_FAILED` with an uncertain outcome

Keep the returned recoverable run ID and local private state. Query the exact ID
first; a response may have been lost after remote acceptance. Retrying status or
the recovery path is idempotent for the same bindings. Do not create another
submission merely because the first SSH response was lost.

If the run remains locally `pending` and the agent confirms it absent, wait the
documented grace interval before explicit signed `--abandon-pending`. This
creates a tombstone that prevents a late same-ID submission. It does not kill a
running job.

### `RUN_STATUS_FAILED`

Status accepts only the exact locally recorded run ID and profile/project
binding. Verify the project directory and profile. A failed status report exits
nonzero and includes the remote return code plus command/environment hashes,
not arbitrary log paths.

### `RESUME_INCOMPATIBLE`

Resume requires a recorded terminal run, the same deployment/profile/project/
bundle/software compatibility, exact prior work/output/cache identities, a
fresh `preflight --resume RUN_ID`, and a new approval. Any changed input or
execution identity blocks resume by design; start a newly planned run instead.

## When to escalate

Stop and follow [SECURITY.md](../SECURITY.md) if there is evidence of path
escape, raw-record disclosure, arbitrary command execution, host-key bypass,
signature forgery/replay, approval bypass, secret logging, unauthorized
overwrite, or audit/state corruption. Preserve evidence without copying real
reads or secrets into the report.
