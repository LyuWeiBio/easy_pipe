# ADR 0012: Bind one fixed workload without activating it

- **Status:** Accepted for dormant implementation
- **Date:** 2026-07-23
- **Scope:** M7.0d-h pure workload construction and start-intent hash binding

## Context

ADR 0011 reserves one authenticated scheduler run, rechecks its execution
artifacts from the allocated node, and burns a create-only start intent before
yielding a live at-most-once permit. It deliberately left the future workload
undefined. Connecting that permit directly to caller-supplied script bytes,
argv, environment, Nextflow configuration, or scheduler flags would reopen a
command-execution surface and make the durable intent insufficient evidence of
what was authorized.

The workload must therefore be derived entirely from trusted config-v2, the
store-owned run reservation, and the exact consumed scheduler preflight. Its
bytes and values must be reproducible and hash-bound before the start intent is
committed. Defining that contract is still separate from materializing files,
submitting `sbatch`, or executing Nextflow.

## Decision

### 1. Derive one pure, closed workload plan

`prepare_scheduler_workload` is a pure source-level contract. It performs no
filesystem access, process execution, environment lookup, scheduler mutation,
or sleeping. It accepts only:

- one trusted scheduler config-v2 object;
- one store-owned scheduler-run snapshot; and
- the exact passed, consumed, unexpired scheduler-preflight snapshot bound to
  that run's token hash, actor, and domain-separated consumer digest.

It rejects mismatched config and contract hashes, request/preflight identities,
profile, policy, project, resume state, approval artifact hashes, deployment,
runtime executables, Nextflow launcher/JAR/version, containers, or manifest
hash. The sealed deployment must contain the fixed FASTQ-QC entry files:
`main.nf`, `nextflow.config`, `assets/samplesheet.csv`, `conf/base.config`, and
`conf/local.config`.

The returned immutable plan binds the workload contract version `1.0`, run and
preflight identities, manifest, resume mode, exact bootstrap and Nextflow argv,
batch and overlay hashes, environment, private paths, scheduler submission
marker, fixed `sbatch` argv, and minimal submit environment. Raw capability,
approval-signature, and HMAC-key bytes are not part of the plan.

### 2. Fix the batch bytes to the compute bootstrap only

The ASCII batch is bounded to 16 KiB and has this sole logical form:

```text
#!/bin/sh
set -eu
umask 077
exec '<absolute-python3>' '-I' '-S' '<bioexec-compute-bootstrap>' \
  '--contract-version=1.0' \
  '--config=<trusted-config-v2-path>' \
  '--run-id=<run-id>' \
  '--identity-sha256=<run-identity-hash>' \
  '--bootstrap-sha256=<configured-bootstrap-hash>'
```

Every argument is independently POSIX single-quoted with fixed escaping. The
renderer admits no extra argument, control text, non-ASCII shell text,
alternate interpreter or artifact leaf, `--wrap`, or workload command. In
particular, the batch contains no Nextflow command: it enters only the
hash-pinned bootstrap described by ADR 0011.

The plan also derives a held, single-node `sbatch` argv through the existing
closed Slurm contract. It fixes `--parsable`, `--hold`, `--export=NIL`,
`--no-requeue`, one node and task, policy CPU/memory/partition/account/QoS/time,
the hash-derived job name, runtime working directory, and stdout/stderr paths.
It contains neither a script path nor `--wrap`; a future adapter would have to
provide the exact batch bytes on stdin. The submit environment is exactly
`HOME=<run-directory>`, `LANG=C`, and `LC_ALL=C`.

Constructing these values does not call `sbatch` and does not create a Slurm
job.

### 3. Fix the dormant Nextflow continuation

Each run derives this private runtime layout:

```text
<state_root>/scheduler-runs-v1/<run_id>/runtime-v1/
  workload.config
  nextflow.log
  home/
  nxf-home/
  tmp/
  apptainer-config/
<preflight-work-dir>/.easy-pipe-nextflow-cache-v1/
```

The plan names these paths but does not create any directory or file. Its exact
Nextflow argv is:

```text
<absolute-nextflow>
-C <runtime-v1>/workload.config
-log <runtime-v1>/nextflow.log
run <sealed-deployment>
-profile local
-work-dir <preflight-work-dir>
--output_dir <preflight-output-dir>
--samplesheet <sealed-deployment>/assets/samplesheet.csv
-name ep-<sha256(run_id)>
[-resume ep-<sha256(resume_run_id)>]
```

Every attempt receives a deterministic, shell-inert Nextflow run name. An
exact resume selects the prior bound run name explicitly and uses
`NXF_CACHE_DIR=<preflight-work-dir>/.easy-pipe-nextflow-cache-v1`, so a new
private launch directory does not silently select an unrelated or absent
session. Run operation, `resume_run_id`, preflight, deployment, work, output,
and approval identities must already agree. Activation still requires durable
terminal evidence for the selected prior run and create-only validation of the
shared cache path.

The 64 KiB-bounded UTF-8 overlay includes the sealed deployment's
`nextflow.config`, sets the global executor and every admitted compiler label
to local with policy CPU and memory values and queue size one, disables Wave,
Tower, Fusion, Docker, Podman, Charliecloud, Conda, Spack, and Singularity, and
enables Apptainer with the preflight cache. Its run options are fixed to
`--containall --no-home --cleanenv --net --network none`. Process labels map
only to the passed local `fastqc`, optional `fastp`, and `multiqc` SIFs. This
closed-label claim relies on the exact sealed, approval-bound deployment being
the reviewed compiler output; arbitrary trusted Nextflow projects are not an
admitted input.

The immutable Nextflow environment contains exactly:

```text
LANG, LC_ALL, PATH, HOME, JAVA_CMD,
NXF_ANSI_LOG, NXF_CACHE_DIR, NXF_OFFLINE, NXF_DISABLE_CHECK_LATEST,
NXF_HOME, NXF_BIN, NXF_VER, NXF_TEMP, TMPDIR,
APPTAINER_CACHEDIR, APPTAINER_CONFIGDIR,
SINGULARITY_CACHEDIR, SINGULARITY_CONFIGDIR
```

`PATH` is constructed from the configured Apptainer, Java, and Nextflow parent
directories followed by `/bin` and `/usr/bin`; no caller or ambient environment
entry is inherited. Both Nextflow and Apptainer are forced to their reviewed
offline, private-home configuration.

### 4. Bind the exact plan into start-intent schema 1.1

The plan separately hashes its batch bytes, overlay bytes, canonical Nextflow
argv, and canonical environment. A domain-separated submission marker binds
the run identity, exact preflight request/revision/journal, manifest, batch,
overlay, command, and environment. The final domain-separated workload binding
then covers those values plus the bootstrap argv, resume flag, private paths,
working directory, submission marker, fixed `sbatch` argv, and submit
environment.

The private scheduler-run schema becomes `1.1`. Before creating
`start.intent.json`, the compute bootstrap supplies the authority-sealed plan
to the run store. Under the run lock, the store recomputes its canonical
binding, batch, overlay, command, and environment hashes and checks the plan's
run and exact preflight identities. The resulting
`workload_binding_sha256` and `workload_batch_sha256` are committed into the
create-only intent, copied into its live permit, and recomputed from the same
plan again when that permit is consumed. A caller cannot substitute two merely
well-formed digests. There is no automatic migration or reinterpretation of
older private scheduler-run state.

After consuming the permit, the bootstrap still returns. It does not
materialize the overlay, invoke the recorded Nextflow argv, or cross an
`execve`/`Popen` boundary.

### 5. Keep every execution adapter inactive

The installed version-1 service does not import the workload module or the
scheduler-run module. Protocol version 2 still has no active dispatcher. This
slice does not:

- create the runtime directory tree or write `workload.config`;
- create and verify initial or resume work/output directories;
- create a workload submit intent, send batch bytes to `sbatch`, bind a job ID,
  release a held job, or recover a lost submit response;
- execute the planned Nextflow argv or any analysis process;
- persist or reconcile workload status, enforce polling cadence, cancel a job,
  or dispatch protocol-version-2 status/resume operations; or
- claim acceptance on a real Slurm cluster or shared filesystem.

The fixed plan is review and test evidence only. It is not an installed
workflow path.

## Consequences

### Positive

- No caller-controlled shell, argv, environment, scheduler flag, container, or
  Nextflow config fragment is admitted at the future workload boundary.
- Batch, overlay, command, environment, scheduler marker, and complete workload
  binding are deterministic and secret-free.
- The create-only start intent now records exactly which dormant batch and
  continuation were authorized before the at-most-once permit is consumed.
- Resume selects one deterministic prior run name and the cache rooted under
  the already bound work directory; it cannot fall back to ambient launch
  history.
- Version 1 and its production execution behavior remain unchanged.

### Costs and remaining blockers

- The overlay records the scheduler policy CPU and memory values and uses queue
  size one, but this is not dependency-free evidence that every planned
  Nextflow process resource request fits the allocation. Activation requires a
  bounded, authenticated planned-resource summary and a fail-closed
  compatibility check against the scheduler policy.
- The plan only names private directories and carries overlay bytes. A later
  adapter must create them owner-only and create-only, verify ownership/mode and
  stable identity, write and `fsync` exact bytes plus their parent directory,
  and recheck them adjacent to process creation. Initial and resume work/output
  path materialization needs the same treatment.
- No durable workload submit/job/status state, protocol-version-2 dispatcher,
  status reconciliation, cancellation policy, or terminal prior-run evidence
  currently authorizes submission or resume.
- Local-executor and container closure assumes the deployment is the exact
  approval-bound output of the reviewed compiler. Activation must retain that
  provenance check and reject any unknown process name, label, or
  higher-priority executor/container override instead of treating a generic
  Nextflow project as trusted.
- Path hashing and later process execution are not atomic; administrator-owned
  immutable path chains or a separately reviewed descriptor-based execution
  design remain required.
- The sleep-inclusive pre-spawn deadline guard and durable poll-rate enforcement
  required by earlier ADRs remain activation blockers.
- `flock`, `O_EXCL`, stable directory-descriptor identity, directory `fsync`,
  held-job recovery, and scheduler/accounting behavior still require
  site-specific real-cluster validation.

## Next step

A later activation slice may materialize only the hash-bound private runtime
and connect the fixed batch to an explicit protocol-version-2 workload state
machine. It must first add resource-compatibility evidence, create-only private
path materialization, durable submit/job/status reconciliation, and
sleep-inclusive boundary checks, then pass real-cluster acceptance. It must not
reconstruct a burned start permit or accept replacements for any planned byte,
argv element, environment entry, or scheduler flag.

## References

- [Nextflow environment variables](https://docs.seqera.io/nextflow/reference/env-vars)
- [Nextflow caching and resuming](https://docs.seqera.io/nextflow/cache-and-resume)
