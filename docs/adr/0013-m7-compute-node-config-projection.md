# ADR 0013: Stage a key-less compute-node config projection per run

- **Status:** Accepted for dormant implementation
- **Date:** 2026-10-05
- **Scope:** M7 approval-HMAC-key confinement; compute-node config staging and binding

## Context

ADR 0012 fixed the workload batch to exec only the hash-pinned compute
bootstrap with `--config=<trusted-config-v2-path>`. The batch carried no key
bytes, but the referenced config file itself carried `approval_hmac_key` —
the single 32-byte secret that authenticates submit/resume approvals. Any job
code running on the compute node could read that file from shared storage and
forge arbitrary approvals, collapsing the whole approval trust root.

## Decision

### 1. The batch never names the key-bearing config file

`prepare_scheduler_workload` now derives a deterministic run-private path for
the bootstrap's `--config`:

```text
<state_root>/scheduler-runs-v1/<run_id>/compute-config-v1/scheduler.json
```

The path is a pure function of the trusted state root and the reserved run
identifier, so the service node (staging plus batch construction) and the
compute node (batch re-derivation inside the bootstrap) agree on it without
any extra channel. The workload binding digest covers it.

### 2. The service node stages a canonical key-less projection

`render_compute_node_config(contract)` renders the canonical config-v2 JSON
with every trusted binding preserved (roots, executables, Nextflow JAR,
limits, scheduler policy, `approval_key_id`) but with the control-plane
secret `approval_hmac_key` stripped. The projection is deterministic and
idempotent: rendering an already-stripped contract yields identical bytes.

`stage_compute_node_config(config, run_id)` writes those bytes to the
deterministic path with create-only (`O_CREAT|O_EXCL|O_NOFOLLOW`), owner-only
(`0o600`, `0o700` staging directory), fsync'd semantics. Re-staging is
idempotent only for byte-identical content; divergent content is a hard error.
Staging requires the full service-node config — staging from an already
stripped config is rejected as a programmer error.

### 3. The loader enforces the trust direction

`load_trusted_scheduler_config(path, *, require_approval_key=True)`:

- default: the file must be the full service-node config carrying the key;
- `require_approval_key=False` (compute-node path): the file must be the
  staged projection — a key-bearing file is hard-rejected before parsing.

The compute bootstrap loads with `require_approval_key=False`.

### 4. Run and preflight identities bind the projection

Both the run identity and the preflight attempt identity now record
`compute_config_sha256` (the projection digest of the reserved full
contract) alongside the existing full-config digests.
`SCHEDULER_RUN_SCHEMA_VERSION` moves 1.1 → 1.2 and
`SCHEDULER_STATE_SCHEMA_VERSION` moves 1.3 → 1.4.

`scheduler_config_binding_matches(identity, config)` accepts a loaded config
when it is the full config matching the recorded full digests, or the staged
projection matching the recorded projection digest. The compute node therefore
re-verifies that its staged file is the exact projection of the reserved
contract — a swapped or tampered staged file fails closed. Approval
verification (`verify_scheduler_run_request`) additionally refuses to run
without the control-plane key.

## Consequences

- The approval HMAC key never appears in any file, argv, environment, or
  digest visible to a compute node. The batch bytes, the staged config, and
  the start intent remain secret-free (the existing
  `test_workload_plan_is_byte_reproducible_and_secret_free` invariant now also
  covers the `--config` path).
- Dormant M7 stays dormant: no submit path is activated by this change; the
  activation adapter must call `stage_compute_node_config` once per reserved
  run before submitting the batch bytes.
- `SchedulerAgentConfig.approval_hmac_key` is now `bytes | None`; only the
  service-node parse path and approval verification require it to be present.
