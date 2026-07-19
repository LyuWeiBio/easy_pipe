# Key-rotation runbook

> Status: **PROCEDURE_ONLY — UNEXECUTED TEMPLATE**.
>
> This repository copy is not rotation evidence. Keep its checkboxes unchecked.
> Record identities, approvals, dates, and evidence checksums in the site's
> controlled system without storing any private key or HMAC value.

This runbook separates three controls that must never be treated as one key:

1. constrained SSH client keys for the Remote Probe and Remote Executor;
2. the symmetric approval HMAC key shared by one controller execution profile
   and one executor configuration; and
3. SSH server host keys recorded through the site's authenticated trust process.

Changing one control does not rotate the others. The application has no online
key-management API and never edits `authorized_keys`, `known_hosts`, or remote
configuration.

## Rotation record and authority

- Rotation ID: `________________`
- Exact controller commit/tag: `________________`
- Key class and old non-secret key ID/fingerprint: `________________`
- New non-secret key ID/fingerprint: `________________`
- Rotation reason: `scheduled / role change / suspected compromise / host rebuild`
- Change owner: `________________`
- Approver: `________________`
- Controller HMAC custodian: `________________`
- Executor configuration/HMAC custodian: `________________`
- Probe/executor SSH-key owner: `________________`
- Host-key trust owner: `________________`
- Remote administrator: `________________`
- Incident owner, if applicable: `________________`
- Start/end time in UTC: `________________`
- Evidence location/checksum: `________________`
- Rollback deadline and owner: `________________`

Never record a private-key path from a user's home directory, HMAC bytes,
complete executor configuration, shell history, agent socket, token, or
signature in a ticket or lower-trust evidence bundle.

## Preconditions

- [ ] The organization has stopped new approval issuance and controller access
      to the old HMAC through site controls; `easy_pipe` has no pause command.
- [ ] A scheduled HMAC rotation has no active, pending, or uncertain run bound
      to the old profile.
- [ ] Status, response-loss reconciliation, retention, and approved resume
      obligations for terminal old-profile runs are closed or explicitly
      waived under recorded owner approval.
- [ ] Previously issued preflight/approval state has expired or been consumed,
      and its exact maximum lifetime was reviewed.
- [ ] The new key material was created through an approved secret channel with
      owner-only storage and backup policy.
- [ ] The new profile/config/key IDs are unique and attributable.
- [ ] A maintenance window, rollback owner, and incident contact are present.
- [ ] Existing audit, project, and remote private state are preserved.

The application has one complete configuration per executor endpoint and no
status-only endpoint. A second SSH alias alone is not an independent service
boundary. Planned non-disruptive HMAC rotation across active or uncertain runs
is therefore unsupported: drain them before the change. In an emergency,
revoke/isolate first and record the resulting status/recovery impact through
incident response rather than retaining a submission-capable old endpoint.

## Approval HMAC key rotation

The controller key file contains exactly 32 random bytes encoded as 64 lowercase
hexadecimal characters, with an optional final newline. The remote executor
configuration contains the same secret under a distinct owner-only boundary.
The secret must never be printed.

### Prepare the new controller side

Create a new key file and key identifier at a site-approved absolute path that
is outside every Git worktree. The Python open uses `O_EXCL`, so an existing
destination fails instead of being truncated:

```bash
install -d -m 0700 /secure/biopipe/controller-keys
python - <<'PY'
import os
import secrets

path = "/secure/biopipe/controller-keys/controller-rotation-next.hex"
descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="ascii") as stream:
    stream.write(secrets.token_hex(32) + "\n")
    stream.flush()
    os.fsync(stream.fileno())
PY
```

Create a new immutable execution profile with a new `profile_id`, the new
`approval-key-id`, and the absolute new key-file path. Reuse roots, mappings,
runtime, and container identities only after reviewing that they are still
current. Preview first:

```bash
biopipe execution-profile create pilot-executor-next \
  --source-host pilot-source \
  --execution-host pilot-source \
  --ssh-alias pilot-exec \
  --software-lock pilot/case-001/generated/software.lock.yaml \
  --output-dir execution-profiles \
  --deploy-root /srv/biopipe/deployments \
  --work-root /srv/biopipe/work \
  --output-root /srv/biopipe/results \
  --cache-root /srv/biopipe/container-cache \
  --container-engine docker \
  --approval-key-id controller-rotation-next \
  --approval-key-file /secure/biopipe/controller-keys/controller-rotation-next.hex \
  --dry-run \
  --json
```

For Apptainer instead, supply every reviewed `--sif NAME=PATH` and matching
`--sif-sha256 NAME=SHA256` required by the software lock. Docker uses the
locally present digest-pinned identities from that lock. After reviewing the
preview, run the exact command without `--dry-run`:

```bash
biopipe execution-profile create pilot-executor-next \
  --source-host pilot-source \
  --execution-host pilot-source \
  --ssh-alias pilot-exec \
  --software-lock pilot/case-001/generated/software.lock.yaml \
  --output-dir execution-profiles \
  --deploy-root /srv/biopipe/deployments \
  --work-root /srv/biopipe/work \
  --output-root /srv/biopipe/results \
  --cache-root /srv/biopipe/container-cache \
  --container-engine docker \
  --approval-key-id controller-rotation-next \
  --approval-key-file /secure/biopipe/controller-keys/controller-rotation-next.hex \
  --json

biopipe execution-profile show pilot-executor-next \
  --profile-dir execution-profiles \
  --json

python -c 'import hashlib, pathlib; p=pathlib.Path("execution-profiles/pilot-executor-next.json"); print(hashlib.sha256(p.read_bytes()).hexdigest())'
```

Record the displayed non-secret profile and SHA-256 in the controlled change
record. Do not print or hash the HMAC file into ordinary evidence.

### Prepare and switch the executor side

Build a new complete executor configuration that binds:

- the new profile ID and exact profile file SHA-256;
- the new approval key ID and new HMAC value;
- unchanged or newly reviewed roots, executables, JAR, runtime, and limits; and
- mode `0600` under a trusted no-follow parent chain.

Transfer the HMAC through the approved secret channel, not argv, source control,
terminal output, or a ticket. Validate ownership and permissions before the
window. Once the drain/expiry gate above is met, switch the complete
configuration atomically through site administration; do not edit only the
reported profile hash or key ID in place. Keep any rollback copy offline and
inaccessible to normal controller submission until the change is accepted.

### Validate and cut over

1. Activate the complete new executor configuration during the maintenance
   window and block the old configuration from normal controller access.
2. Run the fixed executor health operation through the constrained alias:

   ```bash
   printf '%s\n' \
     '{"protocol_version":"1.0","request_id":"health-rotation-1","operation":"health","payload":{}}' \
     | ssh pilot-exec
   ```

3. Show the new local profile and verify its exact hash against remote config.
4. Use a new synthetic project/output target.
5. Run validation/test, a fresh preflight with the new profile, and an approved
   synthetic submission.
6. Query terminal status and inspect sanitized audit order/hashes.
7. Revoke the old HMAC material and securely dispose of extra copies only after
   independent acceptance or an authorized rollback decision.

Old preflight tokens, authorization signatures, and profile bindings must not
be migrated to the new profile. Every new submission needs a fresh preflight
and attributable approval.

## Constrained SSH client-key rotation

Probe and executor keys should be distinct. Rotate one account at a time:

1. Create a new client key through site policy without copying it into a
   project directory.
2. Add its public key with the exact reviewed `restrict,command="..."`
   ForceCommand and no interactive/shared-shell privilege.
3. Add a temporary controller SSH alias that selects only the new identity and
   keeps strict host-key checking enabled.
4. For the probe, preview and run `biopipe source verify SOURCE --dry-run
   --json` and then the same command without `--dry-run`. For the executor, use
   the fixed health JSON/SSH envelope shown above; there is no generic executor
   health CLI command.
5. If a stable SSH alias can select the new `IdentityFile`, update that SSH
   configuration through review without changing the SourceProfile/execution
   profile. If the probe alias, username, or port changes, add a new reviewed
   SourceProfile ID. If execution-profile bytes change, create a new immutable
   profile and require fresh preflight/approval. `source remove` only removes
   local registration; it never revokes a remote public key.
6. Confirm no active automation uses the old public key before revoking it.
7. Preserve the old fingerprint, revocation time, and approval—not the private
   key—in the change record.

Do not reuse one unrestricted key for both accounts and do not grant a PTY,
port forwarding, agent forwarding, X11 forwarding, arbitrary command, or file
transfer capability.

## SSH host-key change

`SSH_HOST_KEY_MISMATCH` is not a normal client-key rotation result. Stop and
verify the new server fingerprint through an authenticated independent channel.
Determine whether the change is an approved host rebuild or a possible
interception event. Only the site SSH administrator may update `known_hosts`
under policy. Never disable strict checking or automatically trust the observed
key.

After an approved host-key update, rerun fixed health, `source verify`, and a
fresh executor preflight before any approval.

## Emergency compromise sequence

For suspected HMAC or SSH private-key exposure:

1. Stop new approvals and isolate the affected constrained endpoint.
2. Preserve controller project/audit/private state and remote state without
   editing or deleting it.
3. Revoke the affected SSH public key or disable the executor approval endpoint
   through the authorized administrator.
4. Identify local pending/accepted records and their latest remote statuses; do
   not assume a lost response means no submission occurred. Immediate
   revocation may intentionally remove the normal status path.
5. Follow the [incident-response runbook](incident-response-runbook.md).
6. Build a new profile/config/key set and validate it with synthetic data.
7. Independently review possible forged approvals, replay, audit integrity, and
   downstream result trust before restoring access.

## Verification and closeout

- [ ] New and old non-secret IDs/fingerprints, exact commit, owners, and UTC
      times are recorded.
- [ ] No private/HMAC material appeared in source, logs, tickets, evidence, or
      command history.
- [ ] New profile and executor config hashes match exactly.
- [ ] Fixed health, fresh preflight, approval, submission, status, and audit
      checks passed with synthetic data.
- [ ] A scheduled HMAC rotation drained active/uncertain old runs; an emergency
      rotation recorded any intentionally lost normal recovery path.
- [ ] All terminal old-profile status, reconciliation, retention, and resume
      obligations were closed or explicitly waived under recorded owner
      approval.
- [ ] Old public/HMAC credentials were revoked by an authorized administrator.
- [ ] Secret backups and obsolete copies follow the approved retention and
      secure-disposal policy.
- [ ] An independent reviewer verified the evidence checksum and rollback
      decision.

Rotation never authorizes real data by itself. A successful key test also does
not prove host integrity, container safety, or scientific correctness.
