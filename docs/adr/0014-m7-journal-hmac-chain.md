# ADR 0014: Chain the scheduler journal with a keyed HMAC

- **Status:** Accepted for dormant implementation
- **Date:** 2026-10-05
- **Scope:** M7 scheduler journal integrity; approval-HMAC-key reuse as the journal chain key

## Context

The scheduler journal (`scheduler_state.py`) is an append-only sequence of
revisions guarded by a plain SHA-256 hash chain (`previous_sha256`) plus
per-revision semantic replay. SHA-256 is unkeyed: anyone who can write to the
state directory — including a same-uid compute job, which shares the service
account on typical Slurm deployments — can rewrite the whole tail of a
journal, keep every `previous_sha256` link intact, and recompute the
unkeyed `grant_binding_hash`. The existing chain then verifies cleanly while
describing a different history than the one the service node committed.

ADR 0013 established that the 32-byte `approval_hmac_key` is the one secret
the service node holds that compute nodes never see (the staged compute-node
projection strips it). That key is therefore the right anchor for a keyed
journal integrity chain: a same-uid attacker without the key cannot forge
chain entries even with full write access to the state directory.

## Decision

### 1. Chained HMAC over canonical revision bytes

Every journal revision carries `journal_mac`, computed as:

```text
mac_{-1} = HMAC(key, DOMAIN || identity_sha256)          # genesis
mac_n    = HMAC(key, mac_{n-1} || canonical(revision_n \ journal_mac))
```

- `key` is `config.contract.approval_hmac_key` (32 bytes, service node only).
- `DOMAIN` is `b"easy-pipe:scheduler-journal:v1\x00"` (domain separation).
- `canonical(...)` is the existing canonical-JSON byte encoding; the MAC is
  computed over the *unsealed* revision so verification strips `journal_mac`
  and recomputes identical bytes (no self-referential MAC).
- Comparison uses `hmac.compare_digest`.

### 2. Verification on every replay, fail-closed

`_load_attempt` replays the chain from genesis on every load: a broken link
(`SCHEDULER_REVISION_MAC_INVALID`), or any other structural problem refuses
the load. Keyed (service-node) configs additionally verify every revision's
chained MAC; a config without the key cannot authenticate the chain, so it
cannot *extend* a journal at all (`_append_revision` raises
`SCHEDULER_JOURNAL_KEY_UNAVAILABLE`).

Key-less configs (the compute-node projection, ADR 0013) *can* load: the MAC
chain cannot be verified without the key, so those loads check only the
unkeyed hash-chain links. This is not a downgrade — the compute node was
never a MAC verifier, it never appends journal revisions (it writes intent
files), and its security-critical checks are anchored in the service-node
invocation plus the service node's own MAC-verified loads, which still
detect a forged tail fail-closed.

The MAC check runs after the plain hash-chain link check, so the two layers
stay independent: hash-link breakage still reports
`SCHEDULER_REVISION_CHAIN_INVALID`, MAC forgery reports
`SCHEDULER_REVISION_MAC_INVALID`.

### 3. Key identity is bound into the journal

The attempt identity records the non-secret `journal_key_id`
(`config.contract.approval_key_id`). A journal presented under a different
key id is refused with `SCHEDULER_JOURNAL_KEY_MISMATCH` before any MAC is
checked. Key rotation therefore retires in-flight journals explicitly
instead of failing later with a confusing MAC error.

### 4. Legacy journals are rejected, not migrated

Schema version bumps `1.4` → `1.5`. Journals written without `journal_mac` /
`journal_key_id` fail the exact-field schema check
(`SchedulerStateContractError`) or the schema-version check
(`SCHEDULER_ATTEMPT_IDENTITY_INVALID`). There is no silent acceptance and no
automatic upgrade: an operator re-creates the attempt under the new schema.

### 5. Key rotation procedure

1. Drain: let in-flight runs finish, or abandon them (`abandon` stays
   available — it does not need the old journal chain to verify new MACs,
   only to *read* history; a rotated key cannot read old journals, so
   in-flight attempts must be closed out first).
2. Generate a new 32-byte `approval_hmac_key` and a new `approval_key_id`;
   write them into the service-node config-v2 file (mode `0o600`,
   root-owned).
3. Restart the scheduler service so `load_trusted_scheduler_config` picks up
   the new key. Old journals under `<state_root>` are now unloadable by
   design; archive or delete the retired state directory after confirming no
   run still needs it.
4. Never copy the new key to compute-node-accessible paths — the
   `require_approval_key=False` loader path hard-rejects key-bearing files
   (ADR 0013).

## Consequences

- A same-uid full-tail rewrite that keeps the hash chain intact is now
  rejected on replay (`SCHEDULER_REVISION_MAC_INVALID`); the attacker cannot
  forge the chain without the service-node key.
- Schema `1.5` journals are unreadable by older code (forward-only
  break, consistent with the project's versioned-contract policy).
- Key rotation is disruptive by design (retires in-flight journals); the
  procedure above is the supported path, and the explicit
  `SCHEDULER_JOURNAL_KEY_MISMATCH` code tells the operator exactly why a
  journal stopped loading.
- The MAC covers revision *content* as committed; it does not cover file
  metadata (modes, ownership) — those remain guarded by the existing
  owner-only permission checks on the state directory tree.

## Tests

`remote_executor/tests/test_journal_mac.py`: happy-path chain verification,
tampered terminal revision rejected, full-tail rewrite with intact hash
chain rejected, key-id mismatch rejected, legacy (1.4) format rejected,
key-less load succeeds hash-chain-only while key-less create/append stay
fail-closed. Existing tamper tests that target layers above
the MAC reseal the chain first (`_reseal_journal_macs`) so each test still
exercises its own layer.

Amendment (2026-10-05): §2 originally forbade key-less *loads* as well.
The compute-node bootstrap must load the preflight journal under its
key-less staged projection (ADR 0013), so key-less loads are allowed with
hash-chain-only verification. The MAC guarantee is unchanged where it
matters: only the key-holding service node verifies MACs, and key-less
appends remain refused, so a forged tail is still detected fail-closed.
