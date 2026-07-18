# M2–M3 operations guide

M2 provides a local controller, a manually installed Remote Probe, fixed
OpenSSH transport, privacy-safe FASTQ detection, and auditable manifests. It
does not deploy software automatically and does not run analysis workflows.

M3 can deterministically plan and generate a fixed FASTQ-QC Nextflow project,
but still does not run it. See the
[planning and generation guide](generated-project.md) after completing the
manifest workflow.

## Build the zipapp

From the repository root with Python 3.11 or newer:

```bash
SOURCE_DATE_EPOCH=315532800 \
  python remote_probe/build_zipapp.py --output remote_probe/dist/bioprobe.pyz
sha256sum remote_probe/dist/bioprobe.pyz
```

The build uses only the Python standard library and normalizes archive order,
timestamps, permissions, and compression. Repeating it with the same sources
and `SOURCE_DATE_EPOCH` produces byte-identical archives. A health smoke test
can be sent over standard input after installing a reviewed configuration:

```bash
printf '%s\n' \
  '{"protocol_version":"1.0","request_id":"health-1","operation":"health"}' \
  | BIOPROBE_CONFIG=/absolute/path/to/config.json \
      python remote_probe/dist/bioprobe.pyz
```

## Manual Source Host installation

Review the zipapp and configuration before copying them. The following is an
example performed by the operator, not by `biopipe`:

```bash
ssh hpc01 'mkdir -p ~/.local/bin ~/.config/bioprobe'
scp remote_probe/dist/bioprobe.pyz hpc01:~/.local/bin/bioprobe.pyz
ssh hpc01 'chmod 0755 ~/.local/bin/bioprobe.pyz'
```

Create a local `config.json` containing only the approved roots, then install
it with restrictive permissions:

```bash
scp config.json hpc01:~/.config/bioprobe/config.json
ssh hpc01 'chmod 0600 ~/.config/bioprobe/config.json'
```

Do not place passwords, private keys, tokens, or patient identifiers in this
configuration. Keep its `allowed_roots` aligned with the roots registered in
the corresponding controller SourceProfile. The controller applies a lexical
pre-check, while the probe independently performs the authoritative canonical
filesystem check; neither check replaces the other.

## Register and verify a source

The host value is an existing alias from `~/.ssh/config`:

```bash
biopipe source add hpc01 --host hpc01 --allowed-root /data/raw
biopipe source show hpc01
biopipe source verify hpc01
```

Verification sends a `health` request over standard input. The SSH command
contains only fixed options, the SSH alias, and the validated probe path; raw
data paths are never command arguments. Verification succeeds only when the
probe reports that a host-local allowlist configuration is active.

The production OpenSSH adapter drains stdout and stderr concurrently into
bounded in-memory buffers. It terminates SSH if stdout exceeds the configured
response ceiling, continuously discards stderr beyond its retained diagnostic
prefix, and redacts paths, credentials, authorization headers, and private-key
material before surfacing an error.

Metadata-only inspection:

```bash
biopipe inspect hpc01:/data/raw/run42 --policy metadata-only --json
```

FASTQ format-summary inspection creates a full manifest, sanitized manifest,
and—only when no blocking errors remain—a candidate samplesheet. The bundle is
create-only: if any destination already exists, no new member is retained.

```bash
biopipe inspect hpc01:/data/raw/run42 \
  --policy format-summary \
  --sample-fastq-records 1000 \
  --output projects/run42/dataset.manifest.json

biopipe manifest show projects/run42/dataset.manifest.json
biopipe manifest apply-overrides \
  projects/run42/dataset.manifest.json \
  --overrides projects/run42/manifest.overrides.yaml \
  --output-dir projects/run42/resolved \
  --name dataset
```

See the [manifest workflow](manifest-workflow.md) for artifact names, integrity
checks, sanitization, and override rules.

Unknown host keys and changed host keys are blocking errors. Add host keys
through the operator's normal reviewed OpenSSH process; `biopipe` never accepts
them automatically.

The probe checks its elapsed-time budget between filesystem operations. A
filesystem call that is itself stuck (for example on an unavailable network
mount) cannot be interrupted safely by Python; the controller's independent
SSH timeout remains the hard upper bound and may therefore surface as
`SSH_TIMEOUT` instead of probe return code 31.

## Remove controller registration

This removes only the local SourceProfile and never contacts the Source Host:

```bash
biopipe source remove hpc01
```

## Manual uninstall from a Source Host

After confirming the exact host and paths, the operator may remove the two M2
files manually:

```bash
ssh hpc01 'rm ~/.local/bin/bioprobe.pyz ~/.config/bioprobe/config.json'
```

M2 never removes remote files automatically. Removing the configuration does
not affect raw data.

## Troubleshooting

- `SSH_HOST_KEY_MISMATCH`: inspect `known_hosts` and verify the host identity;
  do not bypass strict checking.
- `SSH_TIMEOUT`: verify network access and the SourceProfile timeout.
- `PROBE_PROTOCOL_ERROR`: ensure controller and probe both use protocol `1.0`.
- `PATH_OUTSIDE_ALLOWLIST`: update the host-local probe configuration only
  after reviewing the intended data boundary.
- `SYMLINK_FORBIDDEN`: use a real canonical path below an allowed root.
- `SCAN_BUDGET_EXCEEDED`: narrow the directory or have an operator review the
  host-local FASTQ content ceilings; requests cannot raise them.
- `INVALID_FASTQ`: repair the source file or record an explicit reviewed
  exclusion; a malformed candidate is never silently accepted.
