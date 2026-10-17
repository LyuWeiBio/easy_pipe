# Deployment hardening guide

Operational constraints that keep the reviewed security properties true in
production.  These are deployment obligations, not code defaults: the software
fails closed where it can, but the properties below depend on how the hosts
are provisioned.

## 1. UID and ptrace isolation

The Remote Executor service account and the compute jobs it launches **must
not share a UID** on the same kernel unless `kernel.yama.ptrace_scope >= 1`.

- With the default `ptrace_scope = 0`, any process can ptrace a same-UID
  process.  A compute job running as the executor's UID could attach to the
  executor service and read the approval HMAC key from its memory, or rewrite
  the scheduler journal's tail (the journal HMAC chain in ADR 0014 assumes
  the attacker does not hold the key -- ptrace would hand it over).
- Compliant topologies, in decreasing order of preference:
  1. Run the executor service and compute jobs on **different machines**.
  2. Run them as **different UIDs** on the same machine (e.g. service account
     `bioexec`, jobs as per-project submit UIDs).
  3. Set `kernel.yama.ptrace_scope >= 1` (restricted ptrace) and document the
     setting in the site record.
- Verify after provisioning: as the job UID, `cat /proc/<executor-pid>/mem`
  and `gdb -p <executor-pid>` must both fail; `sysctl kernel.yama.ptrace_scope`
  must report the expected value.

## 2. Executor pinning assumption

The executor launches Nextflow with `-profile local` and a generated overlay
(`workload.config`) that pins `process.executor = 'local'` **after**
including the bundle's `nextflow.config`.  Because the selected Nextflow
profile is applied after the overlay's top-level statements, a bundle-side
`process.executor` assignment reachable through the profile would silently
win over the overlay.

- `deploy_bundle` rejects any bundle whose `nextflow.config`,
  `conf/base.config`, or `conf/local.config` assigns `process.executor` to
  anything but `'local'` (`CONFLICTING_EXECUTOR_PROFILE`, fail-closed).
- The deployment is then sealed read-only (`0o500`/`0o400`) and hash-verified
  before every run, so the pinning cannot drift after deploy.
- Do not hand-edit a deployed bundle's config files: the per-run inventory
  check will reject the deployment (`DEPLOYMENT_CONTENT_CHANGED`).

## 3. State-directory cleanup (wedge recovery)

The scheduler's crash-recovery points are fail-closed but **wedge**: a crash
mid-mutation can leave half-written attempt/run records that the service will
not touch again on its own.  They need operator cleanup:

1. Stop the executor service (no new mutations while cleaning).
2. Back up the whole state root (`state_root`) to operator-controlled
   storage; record the backup location and checksum.
3. Identify wedge records: attempt/run entries whose journal revisions never
   committed, or records the service logs as incomplete on startup.
   Cross-check against the journal -- anything not referenced by a committed
   journal revision is suspect.
4. Remove (or quarantine) only the identified half-written records.  Never
   edit committed journal revisions or finalized records.
5. Restart the service and confirm it reaches a clean steady state; keep the
   backup until the next successful maintenance window.

There is no automatic "claim and resume" path for wedged records yet; manual
cleanup following the steps above is the supported procedure.

## 4. Key rotation and in-flight runs

Rotating the approval HMAC key **orphans in-flight runs**:

- The scheduler journal HMAC chain (ADR 0014) is keyed; after rotation, old
  journal revisions no longer verify under the new key, and old signed
  payloads (submit/resume/abandon/deploy) are rejected.
- The key-rotation runbook (`docs/key-rotation-runbook.md`) requires draining
  runs first: no active, pending, or uncertain run may be bound to the old
  profile at rotation time.
- If rotation must happen with runs in flight (emergency), those runs become
  orphans: they cannot be resumed or abandoned under the new key.  Record
  each orphaned run ID, its last known status, and the owner sign-off
  accepting the orphaning; clean up their state directories per section 3
  after confirming nothing references them.

See also: [ADR 0014](adr/0014-m7-journal-hmac-chain.md) (journal keying),
[ADR 0015](adr/0015-release-evidence-signing.md) (evidence attestation),
[key-rotation runbook](key-rotation-runbook.md).
