# ADR 0003: Version scheduler contracts without reinterpreting v1

- **Status:** Accepted for dormant implementation
- **Date:** 2026-07-19
- **Scope:** M7.0b scheduler-aware profile, configuration, and protocol contracts

## Context

M7.0a added pure Slurm argument, identifier, output, state-mapping, and
reconciliation primitives. Those primitives are deliberately unreachable from
the current Controller and Remote Executor entry points.

The next slice needs contracts that can eventually bind scheduler policy into
the same profile, project, preflight, approval, signature, durable-state, and
resume identities used by local execution. It cannot achieve that by adding
optional fields to an existing version-1 document:

- the installed JSON Schema v1 catalog is frozen;
- `ExecutionProfile` v1 means a direct Nextflow local executor;
- Remote Executor config and protocol v1 accept exact field and operation sets;
- current reports cannot represent an indeterminate scheduler observation; and
- a v1 client must never be silently upgraded or downgraded after a v2 failure.

The roadmap originally used `runtime.executor: slurm` as shorthand. That field
is ambiguous for the first supported topology. The outer launch uses Slurm,
while Nextflow runs inside one allocation with its local task executor. A
task-per-job Nextflow Slurm configuration remains unsupported.

The M7.0a `sbatch` contract also fixed one node and one task but relied on site
defaults for CPU and memory. Those defaults are execution-relevant scheduler
policy and therefore must be explicit and hash-bound before the contract is
connected to a cluster.

## Decision

### 1. Keep all v1 meanings and entry points unchanged

M7.0b adds parallel version-2 code contracts. It does not modify or reinterpret:

- `ExecutionProfile` v1 or the frozen schema-v1 bytes and catalog;
- the execution-profile CLI or immutable v1 registry;
- `bioexec.config.load_config()`, which continues to accept only config v1;
- `bioexec.protocol.parse_request()`, which continues to accept only protocol
  v1 and its seven current operations;
- the current Controller client, signer, preflight, approval gate, runner,
  reports, dispatcher, or service health response; or
- local execution, native Nextflow Slurm placeholders, or generated project
  bytes.

The new modules must remain absent from imports in all production entry points.
Sending a v2 profile, config, or request to a v1 path fails before mutation.
There is no automatic fallback from v2 to v1.

### 2. Name the first topology explicitly

`SlurmExecutionProfileV2` fixes this runtime mapping:

```json
{
  "launch_backend": "slurm",
  "workflow_engine": "nextflow",
  "workflow_executor": "local",
  "container_engine": "apptainer",
  "topology": "single_allocation_nextflow_local"
}
```

This means one Slurm allocation, a shared filesystem, Apptainer, and Nextflow
local orchestration inside the compute node. It does not mean that each
Nextflow process becomes a separate scheduler job. Existing PipelineSpec and
ExecutionPlan documents for this topology continue to describe their inner
workflow executor as `local`.

Every container in the v2 profile must have an exact SIF path and SHA-256 below
a configured shared cache root. Docker, modules, arbitrary environment overlays,
job arrays, federated clusters, and task-per-job execution are not admitted.

### 3. Bind the complete allocation policy

The exact scheduler policy contains only:

```text
partition
account
qos
time_limit
cpus_per_task
memory_mib
submit_timeout_seconds
status_poll_seconds
max_pending_seconds
```

All fields have strict type, character, format, and range validation. There is
no `extra_flags`, shell, script, module, environment, cluster, or cancel field.
CPU and memory are emitted as fixed `--cpus-per-task=<n>` and `--mem=<n>M`
arguments; neither may come from a site default.

The canonical policy is sorted, compact ASCII JSON. Its SHA-256 is calculated
identically by the Controller model and dependency-free Remote Executor. Any
policy change changes both the policy hash and the canonical profile hash.

This slice freezes the resource values and their identity. A later activation
slice must define and test the deterministic compatibility rule between the
reviewed allocation and PipelineSpec resource bounds before submission; it may
not infer or enlarge resources on the login node.

### 4. Define a complete but syntax-only Remote Executor config v2

The dormant config-v2 parser accepts the full v1 configuration field set plus:

- `schema_version: "2.0"`;
- `profile_version: "2.0"`;
- the exact runtime object above; and
- the exact scheduler policy.

The initial M7.0b executable set was exactly:

```text
java, nextflow, apptainer, sbatch, squeue, sacct, scontrol
```

ADR 0008 later adds the fixed `python3` interpreter and
`bioexec-compute-preflight` worker needed by allocated-node preflight. ADR 0011
adds the separate `bioexec-compute-bootstrap` artifact. The current dormant
config-v2 executable set is therefore exactly those ten roles; the later ADRs
do not make the syntax-only parser or protocol reachable.

Every executable is one canonical absolute path with its fixed leaf name.
`scontrol` is reserved for a later fixed held-job release operation. `docker`,
`scancel`, a shell, and arbitrary commands are absent.

The parser validates decoded mappings only. It performs no file reads, path
resolution, permission checks, process execution, environment lookup, or
network access. Activation must reintroduce the existing trusted parent walk,
non-symlink file identity, ownership, mode, and mutation-boundary rechecks for
all v2 executables and artifacts.

### 5. Define a separate protocol-v2 envelope

The dormant scheduler protocol uses `protocol_version: "2.0"` and the exact
top-level request fields already familiar from v1. Its only operations are:

```text
health, preflight, deploy, submit, status, resume
```

There is no `cancel`, generic `slurm`, shell, exec, or v1 pending-abandon
operation. A missing scheduler observation never authorizes resubmission or an
absence tombstone.

Every non-health payload binds `profile_version`, `profile_id`, `profile_hash`,
and `scheduler_policy_hash`. The caller never supplies raw scheduler policy,
flags, a job ID, submission marker, submit time, batch script, argv, state, or
exit evidence. Those values must eventually be generated, observed, and
persisted by the trusted Remote Executor.

Submit and resume use a canonical HMAC envelope with the literal protocol
version `2.0`, the operation, and the complete unsigned payload. Operation and
scheduler bindings are signed; request ID remains transport metadata, matching
the existing v1 boundary. Version-1 and version-2 signatures are not
interchangeable.

### 6. Preserve scheduler ambiguity as evidence

The v2 Slurm evidence contract binds:

- exact job ID, 64-hex marker, and scheduler submit time;
- batch-script and scheduler-policy hashes;
- raw and mapped scheduler state;
- a stable reason code, evidence source, exit status, and signal.

Mapped state includes `indeterminate`. Missing, contradictory, truncated,
requeued, restarted, or otherwise unsupported evidence cannot be compressed to
success, failure, or absence. Current v1 run/status reports are not reused for
this evidence and remain unchanged.

### 7. Treat this PR as code-contract evidence only

M7.0b validators, canonical hashes, schemas generated from the controller
model, and synthetic fixtures are implementation evidence. They do not prove:

- a supported Slurm installation or version;
- compute-node visibility, permissions, storage, or network isolation;
- executable, Nextflow JAR, or Apptainer/SIF identity on a cluster;
- submission, held-job release, status polling, or recovery; or
- a complete M7 real-cluster acceptance run.

`SlurmExecutionProfileV2` is not added to the frozen schema-v1 catalog or its
CLI. A separately installed schema-v2 catalog and scheduler-aware reports must
be published before any production entry point accepts v2 documents.

## Consequences

### Positive

- Local v1 protocol, schema, entry-point, and execution semantics remain
  unchanged; the remote zipapp inventory changes because it now packages the
  dormant v2 modules.
- Outer scheduler launch cannot be confused with the inner workflow executor.
- CPU, memory, and every other admitted scheduler value are reviewable and
  hash-bound.
- Controller profile, agent config, signed protocol, and future durable state
  have one common policy identity.
- Unknown scheduler states can remain explicitly indeterminate.

### Costs

- Profile, config, protocol, reports, and installed schemas require parallel v2
  implementations rather than optional v1 fields.
- Policy validation is intentionally duplicated between the dependency-bearing
  Controller and dependency-free agent, so parity tests are mandatory.
- A config-v2 document is not deployable until trusted filesystem identity and
  scheduler preflight are connected in later slices.

## Next step

The next reviewable slice is the dormant fixed compute-node preflight contract
and template described by [ADR 0004](0004-m7-compute-preflight-contract.md). It
must remain unable to mint a usable capability until a real scheduler job
returns complete, hash-bound evidence for paths, storage, Nextflow, Apptainer,
SIF files, resource policy, and network isolation.
