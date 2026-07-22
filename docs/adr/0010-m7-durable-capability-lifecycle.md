# ADR 0010: Persist scheduler capabilities without raw-token replay

- **Status:** Accepted for dormant implementation
- **Date:** 2026-07-22
- **Scope:** M7.0d-f capability issuance, response loss, expiry, and one-use consumption

## Context

ADR 0009 deliberately stopped the scheduler driver at `candidate`. The pure
preflight model still placed the raw capability token inside immutable state,
generic results could disclose it repeatedly, and consumption was only an
in-memory transition. That shape could not be replayed from token-hash-only
storage and two concurrent snapshots could both appear to consume the same
grant.

Capability issuance also has an asymmetric failure rule. If a process crashes
before committing a grant, a later attempt may safely generate a new token
because no token was returned. If the grant committed but its response was
lost, the token may have escaped; the grant must remain burned and no later
caller may reconstruct or replace it.

## Decision

### 1. Make durable capability state hash-only

`PreflightCapability` no longer contains a raw token. It records only the exact
SHA-256, an evidence-derived grant binding, trusted boot-relative issue and
expiry seconds, and mutually exclusive consumed or expired state. Consumption
also binds an authenticated actor identifier and a `consumer_binding_hash`
reserved for the exact future run, deployment, and approval identity.

`preflight_result`, driver results, state snapshots, revisions, exceptions, and
object representations never disclose a raw token. Generic passed results are
nonretryable and still contain `preflight_token: null`.

### 2. Commit before the sole raw response

`SchedulerPreflightStore.issue_capability` holds the attempt `flock`, verifies
snapshot CAS, resamples the sleep-inclusive clock, terminalizes clock or
deadline failures, requires manifest TTL and free-space thresholds to exactly
match the trusted config-v2 limits, and reserves one later revision for
consumption, expiry, or clock invalidation before invoking the internal CSPRNG.

It generates exactly 32 random bytes as lowercase hexadecimal, computes the
SHA-256, and appends a `capability_issued` revision containing only:

- the token hash;
- trusted issue and expiry seconds; and
- the complete grant binding hash.

The create-only revision must complete file `fsync`, directory `fsync`, full
journal replay, state equality checking, and a post-commit clock check before a
store-owned, repr-redacted issuance response is constructed. The second clock
sample rechecks the overall preflight deadline at the exact boundary; crossing
it appends `driver_timeout`, burns the just-committed grant, and returns no raw
token. Any exception or commit-unknown result likewise returns no token.

The issuance revision is the burn tombstone. There is no delivery
acknowledgement. A loaded `passed` grant always rejects another issuance and
never calls the CSPRNG, even when the first response was lost.

### 3. Consume under the same lock and trusted clock

Consumption holds the attempt lock and snapshot CAS while it:

1. checks the live hash-only grant;
2. resamples trusted boot-relative elapsed time;
3. treats `now >= expires_at` as expired;
4. compares the supplied token hash with `hmac.compare_digest`;
5. binds the actor, consumer hash, and trusted elapsed second; and
6. appends and replays one `capability_consumed` revision before returning.

Invalid tokens create no revision. A complete consumption revision makes every
stale or restarted caller fail as already consumed. A commit-unknown response
does not authorize workflow startup; restart may observe the consumed record,
but this slice has no run-start permit or process action.

Once the issuance response has completed before the overall preflight
deadline, later consumption is governed by the grant's trusted TTL. The overall
deadline bounds scheduler/evidence/issuance completion; it does not silently
shorten an already disclosed grant.

### 4. Make expiry and clock failure irreversible

Capability TTL uses the submit intent's boot epoch and sleep-inclusive elapsed
clock, never caller time or wall-clock UTC. Reaching the exact boundary appends
`capability_expired`, changes the attempt to terminal `timed_out`, and preserves
the hash-only grant as expired evidence. A boot epoch change, monotonic rollback,
or invalid sample appends `clock_discontinuity` and changes a passed grant to
`indeterminate`.

### 5. Extend exact replay and revision reservation

The private scheduler-state schema becomes `1.2`. Replay accepts exactly ordered
`capability_issued`, `capability_consumed`, and `capability_expired` events and
recomputes every token, evidence, timing, consumer, and grant binding. Unknown,
reordered, altered, partial, noncanonical, or oversized revisions fail closed.

Scheduler polling now reserves enough capacity for terminal observation,
compute evidence, issuance, and one terminal capability event. Evidence ingest
and issuance each recheck their remaining capacity before advancing; issuance
checks before randomness.

### 6. Keep the lifecycle dormant

The start-or-one-poll driver still stops at `candidate` and imports neither
capability transition by name. Version-1 configuration, protocol, commands,
ForceCommand, preflight, deployment, and runner paths do not import scheduler
modules. There is no version-2 operation, capability endpoint, background loop,
or workflow start in this slice.

## Failure matrix

| Failure point | Durable result | May return raw token? | Retry behavior |
| --- | --- | --- | --- |
| Before issuance revision exists | `candidate` | No | A fresh issuance may generate once |
| Partial or unsafe revision | invalid attempt | No | Fail closed |
| Complete issuance, response lost | `passed`, hash-only | No on retry | Never regenerate or redisclose |
| Invalid or expired token | unchanged or durably expired | No | Never consume |
| Complete consumption, response lost | consumed grant | No start permit | Never consume again |
| Clock epoch discontinuity | `indeterminate` | No | Terminal |

## Consequences

### Positive

- Raw-token loss cannot cause a second token to be minted.
- Durable bytes and replay no longer depend on possession of the raw token.
- Concurrent and restarted consumers have one append-only winner.
- Expiry and boot discontinuity cannot be bypassed with caller-selected time.

### Costs and remaining activation blockers

- Losing the sole successful issuance response intentionally strands that
  preflight; an operator must create a new preflight identity.
- Consumption by itself is not workflow authorization. ADR 0011 adds a dormant
  authenticated consumer derivation and separate create-only run intent/permit,
  but no installed workflow-start path.
- The ADR 0011 bootstrap re-opens and hashes the bundle, runtime, JAR, itself,
  and every SIF from the allocated compute node; its permit is deliberately
  unusable after response loss or restart.
- Durable poll rate limiting, a sleep-inclusive pre-spawn mutation recheck,
  administrator-owned immutable runtime paths, and real-cluster `flock`,
  exclusive-create, directory-`fsync`, suspend, and Slurm acceptance remain
  mandatory.
- Preventing raw response bytes from entering application logs, core dumps, or
  swap is an activation/deployment responsibility beyond this source-level
  state contract.

## Next step

M7.0d-g defines the dormant deployment-to-compute bootstrap and create-only run
intent/permit in [ADR 0011](0011-m7-durable-run-bootstrap.md). It consumes the
exact actor and consumer binding recorded here, revalidates execution artifacts
on the allocated node, and burns the at-most-once start decision without
activating protocol version 2 or starting a workflow.
