# ADR 0009: Orchestrate durable compute preflight only to candidate

- **Status:** Accepted for dormant implementation
- **Date:** 2026-07-22
- **Scope:** M7.0d-e trusted clock, single-step driver, and evidence journal

## Context

ADRs 0005 through 0008 provide a trusted scheduler configuration, six fixed
Slurm operations, one-shot durable mutation permits, and a separately installed
compute worker. They deliberately do not connect those pieces. A caller could
exercise each primitive directly, but there was no reviewed component that
selected the only legal next action after restart, preserved timeout continuity,
or committed compute evidence into the append-only state history.

The pure contract also describes capability issuance. That boundary is more
sensitive than scheduler orchestration: durable storage may retain only a token
hash, while a lost issuance response must never cause a second raw token to be
minted. Combining that decision with the driver would make this slice too broad.
The safe intermediate boundary is the existing `candidate` phase. It proves
scheduler and compute evidence but grants no authority to start a workflow.

## Decision

### 1. Add one dormant start-or-one-poll driver

`SchedulerPreflightDriver` accepts only a `TrustedSchedulerConfig`, a validated
compute manifest, and the canonical request SHA-256. It creates or loads the
exact request-bound attempt, performs at most one phase-specific lifecycle
action, and returns a bounded sanitized result. It does not sleep, loop, start a
background thread, accept an operation name, or expose caller-selected Slurm
arguments, environment variables, job IDs, or raw scheduler output.

The fixed actions are:

| Durable phase | One permitted driver action |
| --- | --- |
| `prepared` | burn submit intent, submit held, then query exact hold evidence |
| `submit_unknown` | marker discovery followed by exact hold query; never resubmit |
| `held` | burn release intent and release that exact held job once |
| `release_unknown` / `polling` | one fixed `squeue` plus `sacct` reconciliation |
| `awaiting_evidence` | stable-read and journal the bound worker evidence |
| `candidate` | deadline check only; never issue a token |
| terminal | return the durable result without side effects |

A submit or release intent remains the irreversible pre-process tombstone.
Transport uncertainty, an invalid response, process interruption, or restart
cannot authorize replay. Query transport failure is distinct from a trustworthy
empty query result and does not create a revision.

### 2. Anchor elapsed time to the durable submit intent

The scheduler state schema becomes `1.1`. Before a submit permit is exposed,
`submit.intent.json` records a canonical boot epoch and boot-relative monotonic
nanoseconds. Sampling reads the epoch before and after the monotonic clock:

- Linux uses `/proc/sys/kernel/random/boot_id` and `CLOCK_BOOTTIME`.
- Darwin reads `kern.boottime` through libc and uses sleep-inclusive
  `mach_continuous_time`, converted with `mach_timebase_info`.
- Unsupported or incomplete clocks fail closed without falling back to wall
  time or a caller-provided elapsed value.

Elapsed seconds are the ceiling of the nanosecond delta. An epoch change,
monotonic rollback, overflow, or elapsed regression appends one
`clock_discontinuity` revision and makes the attempt `indeterminate`. Reached
pending or overall deadlines append one `driver_timeout` revision and are
irreversible. A late scheduler result or evidence file cannot revive the
attempt.

### 3. Commit complete parsed worker evidence into the journal

`ingest_worker_evidence` holds the attempt lease while it performs the existing
no-follow, owner-only, stable, canonical evidence read and exact attempt
binding. It then appends one `compute_evidence` revision containing the parsed
fixed evidence object, its complete SHA-256, and trusted elapsed time.

Keeping the bounded parsed object in the owner-only revision makes replay
self-contained. Deleting or changing the worker handoff file after a successful
journal commit cannot change the recorded result. Replay reparses the fixed
evidence schema, rebinds the manifest, profile, job, marker, and worker, and
requires the event digest before reconstructing `candidate` or `failed`.
Partial revisions, a broken hash chain, duplicate keys, oversized records, or
post-commit reload uncertainty fail closed.

### 4. Stop before capability issuance

The driver never imports or invokes `issue_capability` or
`consume_capability`, never generates randomness, and always returns
`preflight_token: null`. `candidate` is not `passed` and cannot authorize a
deployment or workflow. M7.0d-f will separately define token-hash-only
issuance, response-loss behavior, expiry, and atomic one-use consumption.

### 5. Keep protocol version 2 unreachable

No version-1 config loader, parser, command dispatcher, ForceCommand,
preflight, deployment, runner, or state path imports this driver. There is no
protocol-version-2 operation or installed driver entry point. Direct Python
import remains a testing and review surface, not an activated service path.

## Consequences

### Positive

- Restart recovery has one reviewed, non-resubmitting action for every durable
  pre-capability phase.
- Scheduler completion and compute evidence become one replayable append-only
  chain rather than a transient file read.
- Timeout continuity no longer depends on wall time or caller-supplied elapsed
  values on supported hosts.
- The slice ends at an explicit state with no execution authority.

### Costs and remaining blockers

- Every driver call is intentionally one step; a future protocol client must
  poll using the bounded retry hint.
- The retry hint is not an active rate limiter while the driver remains
  unreachable. Active dispatch must durably enforce poll cadence so an early or
  concurrent caller cannot overload Slurm queries; diagnostic-only active polls
  do not consume append-only revisions.
- Darwin and Linux boot-clock behavior, shared-filesystem locks, exclusive
  create, and directory `fsync` still require real deployment validation.
- Durable capability issuance/consumption, deployment-to-compute bundle and
  runtime rechecks, active version-2 dispatch, and real Slurm acceptance remain
  unimplemented.
- The same-identity path hash/process-start race and detached-descendant limits
  described by ADRs 0006 and 0008 remain activation blockers.
- A host suspend after the mutation permit's continuous-clock guard but before
  `Popen` can still start `sbatch` or `scontrol` after the overall deadline.
  The post-action guard makes that attempt terminal and prevents replay or
  authorization, but cannot undo a late scheduler mutation. Active dispatch
  therefore requires a sleep-inclusive recheck adjacent to process creation.

## Follow-up

M7.0d-f implements the separately reviewed durable capability lifecycle in
ADR 0010. Disk stores only the exact token hash and evidence binding, a lost
issuance response burns the grant without reissuance, and consumption is an
atomic actor/time/consumer-bound one-use transition. Protocol version 2 remains
inactive until deployment bootstrap, a create-only run permit, compute-node
rechecks, and real-cluster acceptance are complete.
