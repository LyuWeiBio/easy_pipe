# ADR 0011: Burn one compute bootstrap into a durable run intent

- **Status:** Accepted for dormant implementation
- **Date:** 2026-07-23
- **Scope:** M7.0d-g authenticated run reservation, compute-node rechecks, and at-most-once start permit

## Context

ADR 0010 makes capability issuance and consumption durable without retaining a
raw token. Consumption alone cannot authorize a workflow start. If a process
stops after consuming the capability or after deciding to start Nextflow, a
retry must distinguish an exact recoverable reservation from a start that may
already have crossed the process boundary.

Deployment also follows scheduler preflight. The preflight allocation proves
that the target is visible and reservable, but it cannot attest to bundle bytes
that did not yet exist. Login-node hashes are likewise not proof that the same
deployment, runtime, JAR, bootstrap, and containers are present on the
allocated compute node immediately before a future workflow start.

Connecting protocol version 2 or submitting a real workload in the same slice
would make these recovery and trust boundaries difficult to review. This slice
therefore adds a dormant, independently testable bridge and stops before any
Nextflow process is created.

## Decision

### 1. Authenticate and bind one exact scheduler run

The dormant run verifier accepts only an already parsed protocol-version-2
`submit` or `resume` request, a trusted scheduler config-v2 object, a durable
scheduler-preflight snapshot, and a sealed deployment binding. It reparses the
request through the strict protocol-v2 parser and verifies the canonical HMAC
envelope with the configured key ID and constant-time digest comparison.

The resulting run identity binds:

- operation, run ID, and optional resume run ID;
- preflight ID, canonical request hash, token hash, and trusted issue/expiry
  times;
- deployment ID, exact direct-child directory identity, sorted file inventory,
  and canonical bundle hash;
- profile, scheduler policy, project, and compatibility hashes;
- authorization ID, exact authenticated actor text, approval time and key ID;
- all eight approval artifact hashes and the canonical signed-request hash;
  and
- trusted configuration and contract hashes.

The consumer binding uses the domain
`easy-pipe.scheduler-run.consumer-binding.v1` over that complete identity. The
same actor and consumer digest must be written by capability consumption and
must match again when the compute bootstrap loads the preflight. No caller may
substitute free-form consumer text after approval verification.

After request verification, the raw capability token is retained only in the
repr-redacted, store-owned verified request long enough for the separate
capability transition. The approval signature, HMAC key, and raw token are
absent from durable run bytes and snapshots.

### 2. Reserve the run before consuming its capability

Each run uses the separate owner-only namespace:

```text
<state_root>/scheduler-runs-v1/<run_id>/identity.json
<state_root>/scheduler-runs-v1/<run_id>/lease.lock
<state_root>/scheduler-runs-v1/<run_id>/start.intent.json
```

The namespace and run directories are exact mode `0700`. Records are exact
owner-only mode-`0600` files, opened relative to verified directory descriptors
with no-follow, stable-identity, canonical-JSON, size, owner, mode, and
link-count checks. The lease uses one validated owner-only fixed-inode lock
file. Record creation uses exclusive names, complete writes, file `fsync`, and
parent-directory `fsync` before replay.

The immutable `identity.json` is created before capability consumption. An
exact retry may load the same reservation after response loss; the same run ID
with any changed approval, request, deployment, profile, capability, config, or
resume binding is a conflict. An incomplete, unsafe, or noncanonical identity
fails closed and is never repaired in place.

The scheduler-preflight private schema becomes `1.3`. Capability actors are
preserved as the exact authenticated bounded UTF-8 text admitted by protocol
version 2, with no case folding or Unicode normalization, so journal replay and
the run consumer binding use identical bytes. There is no automatic migration
or reinterpretation of older private state.

### 3. Build a fourth, fixed compute artifact

The closed zipapp builder adds one distinct role:

```text
compute-bootstrap -> bioexec.compute_bootstrap
```

It produces `bioexec-compute-bootstrap` with its own entry point and SHA-256;
it is not a renamed executor or compute-preflight artifact. The scheduler
configuration fixes its absolute path with that exact leaf, and the trusted
loader records its startup identity and full hash.

The bootstrap is silent and accepts exactly five ordered arguments:

```text
--contract-version=1.0
--config=<absolute config-v2 path>
--run-id=<run identifier>
--identity-sha256=<run identity SHA-256>
--bootstrap-sha256=<bootstrap SHA-256>
```

There are no abbreviations, extra arguments, arbitrary module names, commands,
argv, environment overlays, or shell surface. Any malformed input, trust
failure, or uncertain durable commit returns fixed exit code `70` without
writing stdout or stderr.

### 4. Re-open every execution artifact from the allocated node

After loading the exact run reservation and its consumed preflight, the
bootstrap rechecks the trusted config file and fully reopens and rehashes:

- the absolute Python interpreter;
- Java and the Nextflow launcher;
- Apptainer and `bioexec-compute-bootstrap` itself;
- the pinned Nextflow one/shadow JAR;
- the complete sealed deployment inventory and canonical bundle hash; and
- every SIF recorded by the passed compute-preflight manifest.

The deployment must remain the same mode-`0500` direct child of one trusted
deploy root with the recorded device, inode, owner, group, exact file set,
sizes, and hashes. Extra, missing, replaced, symlinked, oversized, or changed
files fail closed. Runtime, JAR, bootstrap, and SIF paths retain the trusted
ownership, no-symlink, and non-writable-parent requirements established by
ADRs 0005 and 0008.

The bootstrap verifies the artifact invoked as `sys.argv[0]` and the running
interpreter selected as `sys.executable` against config-v2; it does not rely on
`PATH` or an archive shebang. These source-level checks still do not make path
verification and later execution atomic. Administrator-owned immutable path
chains remain an activation requirement.

### 5. Burn the start decision before yielding one live permit

The run store holds a nonblocking run lease, verifies that no start intent
exists, runs all compute-artifact checks, and reloads the consumed preflight to
prove that its revision, journal hash, capability, actor, and consumer binding
did not change during verification. It then creates `start.intent.json` with
`O_EXCL` and binds the run identity plus the exact consumed preflight revision,
journal, token hash, grant binding, actor, consumer digest, and trusted
consumption time.

Only a fully written, file- and directory-fsynced intent that replays to its
expected canonical hash yields a `SchedulerStartPermit`. The permit is opaque,
non-reconstructible, and bound to the exact store, snapshot, process, Python
`Thread` object, live lease session, run identity, and intent hash. It can be
consumed once while that session remains live.

An existing intent is always burned. A complete retry, partial file, unsafe
file, uncertain commit, process exit, thread change, lease loss, or restart
cannot recreate a permit. The intended future fixed workload continuation may
therefore cross its process-start boundary at most once for one run ID. This
slice consumes the internal permit and exits; it does not execute that
continuation or start Nextflow.

### 6. Recover only before the start intent

| Failure point | Durable result | Retry behavior |
| --- | --- | --- |
| Before run identity commits | no safe reservation or commit unknown | retry only after exact state inspection |
| Complete identity, response lost | exact secret-free reservation | exact request may reload it |
| Capability consume response lost | exact consumed actor/consumer binding | the same reservation may continue |
| Compute artifact verification fails | no start intent | remediation and exact recheck may retry |
| Start intent write or replay is uncertain | intent is treated as burned | never issue another permit |
| Permit is lost or process restarts | start intent remains | never reconstruct or continue automatically |

This asymmetry permits response-loss recovery while every action is still
side-effect free, then becomes permanently non-retrying before a future
workflow process could start.

### 7. Keep protocol and workload execution inactive

No version-1 config loader, protocol parser, dispatcher, ForceCommand,
preflight, deployment, runner, status, or resume path imports the run store or
bootstrap. Protocol version 2 has no active endpoint. This slice does not:

- submit a workload `sbatch` job or render its final batch template;
- invoke Java, Nextflow, or an analysis process;
- persist a Slurm workload job ID or reconcile workload status;
- add cancellation, cleanup, or background recovery; or
- claim validation on a real Slurm cluster or shared filesystem.

Building, installing, or directly testing the fourth zipapp is contract
evidence only. It does not activate scheduler execution.

## Consequences

### Positive

- Approval, deployment, capability consumption, and workflow-start authority
  share one replayable, secret-free identity.
- Exact response-loss recovery is possible until the create-only start intent,
  while any uncertain start decision permanently blocks replay.
- The allocated node rechecks the deployment and every execution artifact that
  a future fixed Nextflow continuation would use.
- Version 1 and the installed production path remain unchanged.

### Costs and remaining blockers

- Full deployment, runtime, JAR, bootstrap, and SIF hashing adds bounded I/O at
  the future workload boundary.
- Losing a live permit intentionally strands that run; automatic repair or
  permit reconstruction would violate at-most-once startup.
- A path may still change between its final hash and process execution unless
  the service identity cannot mutate the complete path chain.
- ADR 0012 now defines a pure fixed batch, scheduler submission surface,
  Nextflow argv/environment/overlay, and start-intent workload hash binding.
  Materialization, active protocol-v2 dispatch, `sbatch`/Nextflow execution,
  scheduler status/reconciliation, durable poll-rate enforcement, the
  sleep-inclusive pre-spawn scheduler guard, and real-cluster acceptance remain
  unimplemented.
- Shared-filesystem `flock`, `O_EXCL`, stable descriptor identity, and
  directory-`fsync` behavior require site-specific compute-node validation.

## Next step

[ADR 0012](0012-m7-fixed-workload-contract.md) defines and hash-binds the pure
fixed `sbatch`/Nextflow workload contract while keeping execution dormant. A
later activation slice must add verified resource compatibility, create-only
private runtime materialization, an explicit protocol-version-2 dispatcher,
durable workload job/status reconciliation, positive-only lost-response
recovery, sleep-inclusive boundary checks, and real-cluster acceptance. It must
not weaken the create-only run identity or burned start-intent boundary
introduced here.
