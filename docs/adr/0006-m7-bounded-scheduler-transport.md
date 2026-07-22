# ADR 0006: Bound Slurm transport behind fixed dormant operations

- **Status:** Accepted for dormant implementation
- **Date:** 2026-07-19
- **Scope:** M7.0d-b bounded scheduler process transport

## Context

The M7 Slurm primitives construct fixed argument vectors and strictly parse
bounded scheduler output. The trusted version-2 loader binds those primitives
to installed scheduler executables and can detect later filesystem changes.
Neither layer starts a process.

The version-1 command runner is not a suitable bridge between them. It has no
stdin payload contract, decodes output with replacement, uses independent
stream ceilings, and does not expose pipe failures or distinguish a failure
before process creation from an ambiguous result after a mutation starts.
Exposing that runner directly would also create an arbitrary argv, environment,
working-directory, timeout, and parser surface.

## Decision

### 1. Add a separate raw-byte scheduler transport

M7.0d-b adds a scheduler-only process transport. It always uses `shell=False`,
an absolute trusted executable, a minimal service-owned environment, closed
file descriptors, and a new process session on POSIX. Stdout and stderr remain
raw bytes. One aggregate byte ceiling covers both streams, and exceeding it
terminates the process group rather than returning truncated data to a parser.
Stdin, stdout, and stderr use one nonblocking selector loop; the transport does
not leave blocking reader or writer threads behind when a detached descendant
retains a pipe descriptor.

One monotonic operation deadline covers executable/config rechecks, process
creation, stdin delivery, output draining, and waiting. A small shared emergency
cleanup budget may follow the deadline so process-group termination and pipe
closure cannot reset the operation timeout once per stream or thread. Reader
and writer errors, descendants retaining a pipe, timeout, forced termination,
incomplete stdin, and output overflow are explicit transport failures. Cleanup
failure cannot overwrite a mutation-unknown result. The result records only
bounded output and non-secret evidence such as the stdin size and SHA-256; it
never records the stdin bytes or an inherited environment.

Failure before `Popen` is classified as not started. Once `Popen` succeeds, a
submit or release failure is an ambiguous mutation even if the child exits
nonzero or returns malformed output. The transport never retries a mutation.

### 2. Expose only six fixed Slurm operations

The adapter admits exactly:

- held `sbatch` submission;
- exact held-job `squeue` confirmation;
- marker-bound `squeue` discovery after a lost submit response;
- exact held-job `scontrol release`;
- exact-job `squeue` observation; and
- exact-job `sacct` reconciliation.

Callers cannot provide a binary, argv, environment, parser, output limit,
scheduler flag, shell text, or script bytes. Each operation derives its argv
from the existing Slurm builders and its executable from one
`TrustedSchedulerConfig`. Submit alone receives stdin, and those bytes must be
the freshly rendered template of an exact prepared `SchedulerPreflightState`.
All other operations close stdin.

Before an operation, the adapter revalidates the trusted configuration, state
root, selected executable, scheduler policy/profile bindings, and relevant
preflight or job evidence. It uses only the fixed private scheduler environment
and state-root working directory. Read-only output is parsed only after a clean
transport result: normal exit zero, complete pipes, no overflow or timeout, and
empty stderr. A failed query with empty stdout is never interpreted as a
missing job.

### 3. Preserve mutation ambiguity for later durable recovery

An `sbatch --parsable` job ID proves only that the Slurm controller accepted a
request. A release command binds only a job ID and is not atomic with the
preceding held-job observation. Post-start timeout, nonzero exit, signal,
stderr, output overflow, I/O failure, or invalid stdout therefore produces an
unknown submit/release result. A later durable state machine must reconcile
that state through the fixed discovery/query operations before any retry or
further transition.

This slice does not create that durable mutation intent. The new module remains
unreachable from the installed version-1 config loader, protocol, dispatcher,
and service entry point. It is transport infrastructure and synthetic test
coverage, not an activated scheduler API or cluster acceptance result.

### 4. Retain an explicit executable race boundary

The adapter places the full executable recheck immediately beside process
creation. Path-based `subprocess.Popen`, however, cannot atomically execute the
same descriptor that was hashed. A process with permission to replace the
executable or one of its parents can still race the final recheck.

Activation therefore requires either a deployment boundary in which the
service identity cannot modify the executable chain, or a separately reviewed
Linux-specific descriptor-based execution design. This ADR does not claim that
the current path recheck eliminates a same-identity replacement race.

## Consequences

### Positive

- Scheduler output remains lossless, bounded raw evidence until strict parsing.
- Fixed operations do not create a general remote command or scheduler-flag
  surface.
- Mutation ambiguity is explicit and cannot silently authorize a retry.
- Version 1 remains isolated and unchanged.

### Costs

- Pipe handling and process termination need substantially more tests than the
  pure Slurm contracts.
- Process-group termination cannot prove that a detached descendant or
  privileged external service stopped; such a result remains incomplete.
- Full trust rechecks count against every operation deadline.
- Durable version-2 orchestration, stronger deployment trust, immutable
  runtime installation, and real-cluster acceptance remain blocking work
  before activation.

## Next step

M7.0d-c adds the owner-only, append-only scheduler-preflight state and
exclusive submit/release intents described by ADR 0007. M7.0d-d adds the
separately installed, hash-bound compute worker and submission-bound runtime
rechecks described by ADR 0008. M7.0d-e adds the uninstalled, start-or-one-poll
driver described by ADR 0009; it preserves read-only recovery and stops at
`candidate`. The transport still has no installed version-2 caller.
