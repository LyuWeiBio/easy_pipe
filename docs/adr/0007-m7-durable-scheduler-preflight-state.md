# ADR 0007: Burn scheduler mutations into durable one-shot intent

- **Status:** Accepted for dormant implementation
- **Date:** 2026-07-22
- **Scope:** M7.0d-c scheduler-preflight state, serialization, and mutation intent

## Context

ADR 0004 defines the pure compute-preflight state machine. ADR 0005 binds the
version-2 scheduler configuration to trusted filesystem identities. ADR 0006
adds a bounded process transport for six fixed Slurm operations. Those pieces
still do not make a scheduler mutation safe to retry: Slurm cannot atomically
commit an `sbatch` or `scontrol release` side effect together with a local JSON
record.

A process may stop after the controller accepts a mutation but before the
response or local state is durable. An in-memory lock, a replaceable snapshot,
or a successful local return code cannot prove that replay is safe. The state
boundary must instead make every mutation attempt durable and irreversible
before the process starts, then recover only through read-only scheduler
evidence.

## Decision

### 1. Use a separate owner-only append-only namespace

M7.0d-c stores scheduler preflights below the trusted version-2 state root in
`scheduler-preflights-v1/<preflight_id>/`. It does not reuse the version-1
`StateStore` namespace or its generic replace operation.

The attempt identity is create-only and binds the canonical request hash,
manifest, generated template identity, submission marker, profile, scheduler
policy, trusted configuration, and contract hashes. Revisions are numbered,
create-only records joined by an exact SHA-256 predecessor chain. The current
state is obtained by replaying those records through the public pure
preflight transitions; durable code cannot reconstruct an arbitrary state
dataclass.

All namespace and attempt directories are exact owner-only `0700`
directories. Identity, lease, intent, and revision records are exact owner-only
`0600` regular files opened relative to verified directory descriptors with
no-follow semantics. Reads enforce fixed schemas, canonical duplicate-free
JSON, byte and revision ceilings, stable inode identity, ownership, mode, and
link count. A malformed or partial durable object fails closed.

### 2. Combine a lease, CAS, and irreversible intent

Three controls serve different failure boundaries:

- a fixed-inode nonblocking `flock` lease excludes concurrent transition
  executors;
- the expected revision and full journal hash reject stale writers; and
- an `O_EXCL`, hash-bound submit or release intent survives process failure and
  permanently burns that mutation attempt.

Every durable object follows the ordering `create`, complete write, file
`fsync`, then parent-directory `fsync`. Existing namespace, attempt, and
revision directories are resynchronized under their leases before adoption,
so a visible entry left by a stopped creator cannot back a permit while an
ancestor remains undurable. A mutation permit is not returned until its exact
intent and directory entry are durable. Intent records are never deleted,
replaced, expired, or recreated. Garbage collection must retain the attempt
identity and both mutation tombstones.

The lease descriptor is close-on-exec. A permit is opaque, bound to the exact
store, in-memory trusted-configuration identity, state object, intent, process,
`Thread` object, and live lease session, and can be consumed once before its
absolute deadline. Matching configuration content hashes alone are not enough.
The scheduler transport rejects submit or release without such a permit.
Holding a stale snapshot, recovering an old intent, or constructing a
look-alike Python object cannot authorize another mutation.

### 3. Treat a durable intent as unknown until positively resolved

A submit intent overlays `prepared` as `submit_unknown`. The live permit keeps
the exact prepared state needed for the one admitted `sbatch`; every later
load exposes only the unknown recovery state. A clean job-ID response is still
provisional. Only an exact marker-bound `PENDING + JobHeldUser` observation
may append the held-job revision. After a restart, discovery and exact held
query are allowed, but another submit is not.

A release intent binds the full job ID, marker, scheduler Submit time, held
state and reason, plus the current revision and journal hash. It overlays
`held` as `release_unknown`; the live permit alone carries the transient
`release_ready` state. A successful release receipt may append `polling` while
the permit is live. Otherwise restart and lost-response recovery use only
`squeue` and `sacct`. Missing or pending evidence remains unknown; exact active
or terminal evidence may resume reconciliation; release is never replayed.

An intent that exists but is empty, partial, noncanonical, or unreadable is
still burned. Corruption blocks automatic progress rather than turning an
uncertain mutation into an apparently unused claim.

### 4. Preserve strict time and evidence boundaries

The live permit deadline starts before intent persistence, so lock, write,
`fsync`, trust rechecks, process creation, input delivery, and output drain do
not each receive a fresh command timeout. Durable elapsed values remain
monotonic through the pure transition contract. Release authorization that is
already outside the overall deadline is durably terminal and does not create
a release intent.

Durable records may contain parsed job and scheduler observations, stable
reason codes, invocation hashes, and bounded transport flags. They never
contain scheduler raw stdout or stderr, the submit template duplicated in an
error, argv, environment, approval keys, HMAC keys, or a raw capability token.
Capability issuance and consumption remain outside this slice.

### 5. Keep the implementation dormant

The installed version-1 protocol, dispatcher, service entry point, preflight,
deployment, and run path do not import the scheduler state, runner, or permit.
M7.0d-c adds no version-2 operation and performs no background recovery. The
new components can start a scheduler process only when explicitly imported and
combined by future reviewed version-2 orchestration.

## Consequences

### Positive

- Concurrent or restarted callers cannot obtain a second submit or release
  permit for one preflight attempt.
- Lost scheduler responses have a durable positive-only recovery path.
- State history cannot be silently overwritten or rolled back by a stale
  in-process writer.
- Pure state transitions remain the single source of lifecycle semantics.

### Costs and remaining blockers

- Append-only revisions require a future reviewed retention and compaction
  policy that preserves mutation tombstones.
- Shared-filesystem activation requires real-cluster proof that the selected
  filesystem provides the required `flock`, exclusive-create, and directory
  `fsync` semantics.
- A hostile same-identity process can still race path-based scheduler
  execution as described by ADR 0006.
- Boot/monotonic-clock continuity, fixed compute-worker installation,
  capability lost-response semantics, and real Slurm acceptance remain
  activation blockers.

## Next step

M7.0d-d must add the separately installed, hash-bound fixed compute-preflight
worker and its descriptor-safe manifest/evidence files. No protocol-version-2
activation is allowed until the worker, durable driver, deployment rechecks,
and real-cluster acceptance are complete.
