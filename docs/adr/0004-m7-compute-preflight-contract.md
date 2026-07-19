# ADR 0004: Stage compute-node preflight before scheduler activation

- **Status:** Accepted for dormant implementation
- **Date:** 2026-07-19
- **Scope:** M7.0c compute-node preflight manifest, template, evidence, and state contract

## Context

M7.0a introduced unreachable Slurm argument and observation primitives. M7.0b
added parallel version-2 profile, configuration, and protocol contracts without
changing the version-1 service. The next scheduler boundary is compute-node
preflight: login-node readability is not evidence that an allocated compute
node can see the same inputs, runtimes, containers, and storage.

Connecting this boundary immediately would be unsafe. The version-2
configuration is still syntax-only; it does not load trusted filesystem
identities. The current command runner cannot provide exact batch-script bytes
on standard input. Durable state has no scheduler-preflight namespace or
compare-and-swap lease. The installed agent also has no hash-bound compute
worker or interpreter contract.

The request order is intentionally `preflight` then `deploy`. A preflight job
therefore cannot attest to bundle bytes that do not exist yet. It can prove
that the deployment target is visible and can be safely reserved, but the
deployed bundle must be rechecked from the compute node immediately before a
future workload starts.

## Decision

### 1. Add a dormant, pure preflight contract first

M7.0c defines a dependency-free module for:

- an exact compute-preflight manifest and canonical identity;
- deterministic fixed-template bytes and their SHA-256;
- a held-submit and one-poll-at-a-time transition contract;
- strict compute evidence parsing;
- terminal scheduler/evidence reconciliation; and
- the data required by a future one-use capability.

The module performs no filesystem access, process execution, sleeping, token
generation, or state mutation. The current version-1 configuration, protocol,
dispatcher, preflight, deployment, and runner do not import it. Passing its
synthetic tests is contract evidence only.

### 2. Preserve the held-job mutation sequence

A future active implementation must use this order:

```text
durable submit intent (marker + manifest + script hashes)
→ sbatch --hold, with the exact script bytes on stdin
→ parse one local numeric job ID
→ query the exact job and prove PENDING + JobHeldUser
→ bind job ID + marker + scheduler Submit time + user hold
→ durably persist the exact job reference
→ durably record a fresh release intent before the overall deadline
→ scontrol release <job-id>
→ bounded squeue/sacct polling
→ terminal accounting success + complete compute evidence
→ durable evidence
→ one-use capability issuance
```

The only release primitive is the literal `scontrol release` operation for an
exact job whose ID, marker, scheduler Submit time, `PENDING` state, and
`JobHeldUser` reason were validated together. A normal pending observation or
numeric job reference is insufficient. There is no `scancel`, generic
scheduler command, shell command, user-provided script, or free flag surface.
An expired held attempt may be retained for operator reconciliation, but it
cannot enter the release-ready phase.

If `sbatch` has an ambiguous or lost response, marker discovery is
positive-only. One exact user-held match may bind the existing attempt; zero
matches remain unknown, multiple matches are a conflict, and no outcome
authorizes another submission. If release has an ambiguous response, ordinary
pending or missing observations remain `release_unknown`; exact active or
terminal evidence may resume reconciliation, but release is not blindly
replayed. After an executor restart, a persisted `release_ready` intent is
always recovered as `release_unknown` before any query; it never authorizes a
second `scontrol release` call.

### 3. Poll idempotently without holding an SSH request open

The version-2 `preflight` operation will eventually be start-or-one-poll for an
exact `preflight_id` and canonical request hash. One call may advance at most
one durable transition and may return a bounded `retry_after` value. Repeating
the exact request must never create another `sbatch` attempt. A changed request
under the same identifier is a state conflict.

Queue disappearance alone moves an attempt only to accounting-pending. It is
not success, failure, absence, or permission to resubmit. Only one matching
allocation-level `sacct` observation in `COMPLETED` state with exit `0:0` can
be a scheduler-success candidate. Requeue, restart, duplicate accounting,
unknown state, missing exit evidence, marker/Submit mismatch, or conflicting
sources remain indeterminate.

Pending and overall deadlines are irreversible. The overall bound is derived
from the fixed submit timeout, maximum pending duration, Slurm runtime limit,
and two status-poll intervals of accounting grace. Scheduler success, compute
evidence, and capability issuance each recheck trusted monotonic elapsed time;
elapsed time is measured from the durable submit intent. A late result cannot
revive a timed-out attempt. M7.0 has no cancellation operation, so an exact
residual job reference must remain available for operator reconciliation.
The overall deadline uses that global elapsed time, while `max_pending_seconds`
measures only the duration since the durable release intent.

### 4. Require both scheduler success and complete compute evidence

The fixed compute result contains exactly these checks:

```text
allocation_policy
apptainer_runtime
cache_storage
deployment_target
free_space
input_paths
network_isolation
nextflow_runtime
output_storage
path_mapping
sif_artifacts
work_storage
```

Raw worker evidence binds only identities observable on the compute node. The
combined durable state and capability chain additionally binds the fixed script
hash and scheduler-derived Submit time; these are never trusted when
self-reported by the worker. The top-level status is not trusted: the parser
derives pass/fail from the complete duplicate-free check set. Scheduler success
without a complete result does not pass, and a nominally passing result cannot
override non-successful or indeterminate scheduler evidence.

The eventual worker must perform no-follow input checks, deterministic path
mapping, JAR and SIF hashing, runtime identity/version checks, private
work/output reservation probes, cache/deployment visibility and writability,
per-role free-space checks, and a fixed offline Apptainer network-policy probe.
The network probe proves that the reviewed command contract was used; only
operator cluster acceptance can establish the behavior of the site kernel,
runtime, and firewall.

### 5. Do not overstate deployment evidence

Because deployment follows preflight, the `deployment_target` check covers
only compute-node visibility, target absence or resume identity, safe
reservation behavior, writability, and free space. It does not attest to a
future bundle. The M7 workload bootstrap must re-open and re-hash the deployed
bundle, Nextflow JAR, Apptainer executable, and every SIF on the compute node
before starting Nextflow.

### 6. Keep capability issuance inactive until durable prerequisites exist

The pure contract may describe a capability candidate, but the installed
service must not mint one until a later connection slice provides:

- a trusted version-2 configuration loader with parent, owner, mode, symlink,
  and startup-identity checks plus mutation-boundary rechecks;
- a hash-bound compute worker or interpreter;
- a bounded stdin-capable scheduler runner;
- a distinct scheduler-preflight state namespace and record schema;
- an exclusive submit-intent claim before the first `sbatch` call;
- serialized transition/lease semantics; and
- atomic one-use consumption that stores only a token hash.

The capability grant identity binds the passed evidence chain, token hash,
issuance and expiry times, and the unconsumed or consumed actor/time state.
In-memory state and capability objects reject ordinary public reconstruction;
this is defense in depth, not a substitute for the future durable lease and
compare-and-swap boundary.

Version-1 preflight records and tokens are not reusable. A version-1 runner
must not consume a scheduler capability, and a future scheduler runner must
reject version-1 records.

## Consequences

### Positive

- The scheduler mutation and evidence grammar can be reviewed before it becomes
  reachable.
- Exact template bytes, marker identity, scheduler observations, and compute
  evidence share one fail-closed binding chain.
- Lost responses, accounting delay, and timeout have explicit non-resubmitting
  states.
- Existing local execution and version-1 release evidence remain semantically
  unchanged.

### Costs

- This PR cannot run a real Slurm preflight or issue a usable capability.
- Activation requires trusted filesystem loading, durable concurrency control,
  and a reviewed compute worker in a separate change.
- Bundle identity requires a second compute-node check after deployment.

## Official scheduler basis

Slurm documents that `sbatch` reads a batch script from standard input when no
script path is supplied, returns after the controller accepts a job and assigns
an ID, and does not imply that resources have been granted. A held job is
released with `scontrol release`. `squeue` and `sacct` expose different pieces
of lifecycle evidence, and duplicate accounting records require explicit
handling.

- <https://slurm.schedmd.com/sbatch.html>
- <https://slurm.schedmd.com/scontrol.html>
- <https://slurm.schedmd.com/squeue.html>
- <https://slurm.schedmd.com/sacct.html>

## Next step

The next connection slice must implement the trusted version-2 loader,
stdin-capable scheduler runner, scheduler-preflight state namespace, and fixed
compute worker. It must remain unable to start a workflow until the deployment
and every runtime artifact are revalidated from the allocated compute node.
