# Incident-response runbook

> Status: **PROCEDURE_ONLY — UNEXECUTED TEMPLATE**.
>
> This document is engineering guidance, not a substitute for the site's
> incident policy or proof that an incident exercise occurred. Keep repository
> checkboxes unchecked and retain sensitive evidence only in the approved
> incident system.

Use this runbook for suspected confidentiality, integrity, authorization, or
execution-boundary failures involving `easy_pipe`. Routine operational failures
remain in the [troubleshooting guide](troubleshooting.md), but any evidence of
path escape, raw-record disclosure, arbitrary command execution, host-key
bypass, forged/replayed approval, secret logging, unauthorized overwrite, or
audit/state corruption is a security incident until triaged.

The project is not a containment or forensic platform. Trusted host
administrators, identity owners, network/security teams, and data owners retain
their normal authority.

## Incident record

- Incident ID: `________________`
- Declared time in UTC: `________________`
- Incident commander: `________________`
- Technical lead: `________________`
- Data owner/privacy contact: `________________`
- Controller/Source/Execution Host owners: `________________`
- Key owner: `________________`
- Communications/legal contact: `________________`
- Exact commit/tag and profile IDs: `________________`
- Affected project/run IDs: `________________`
- Evidence location/checksum/access class: `________________`
- Recovery approver: `________________`

Use anonymous case/run references in ordinary communications. Hostnames, paths,
sample names, full reports, SSH diagnostics, private state, keys, tokens, and
signatures belong only in restricted evidence when necessary.

## Severity guide

| Class | Examples | Initial posture |
|---|---|---|
| Critical integrity/confidentiality | Raw sequence/read-name disclosure, arbitrary remote command, forged approval, confirmed key theft, malicious administrator/runtime | Stop approvals, isolate affected constrained endpoints, preserve evidence, invoke site incident response immediately |
| High integrity | Path escape, host-key bypass, container/JAR/executable replacement, audit/private-state tampering, unauthorized overwrite | Stop affected workflow and approvals; preserve and independently verify exact identities |
| Operational uncertainty | Lost submit response, stale preflight, source outage, disk exhaustion | Preserve state and follow fixed recovery; escalate if evidence suggests tampering or disclosure |
| Quality/process | Wrong non-sensitive pilot case, incomplete runbook, unreviewed version | Pause pilot/release claims; correct through a new reviewed artifact/process |

Severity is set by the organization. A sanitized error alone cannot prove the
absence of a more serious event.

## First response

1. Stop new approvals for the affected execution profile. Do not add
   `--approve-real-data` merely to reproduce a failure.
2. Preserve controller project trees, `audit/events.jsonl`, reports, hidden
   state, exact commit/profile hashes, and affected remote state in place.
3. Prevent further access through the affected constrained SSH key or executor
   endpoint when authorized. Avoid destroying old status/recovery access until
   active and uncertain run IDs are understood.
4. Do not delete work/output/state, edit hashes, rewrite audit, regenerate into
   the same path, or rotate evidence away before collection.
5. Engage host, key, data, security, and runtime owners appropriate to the
   suspected boundary.
6. Record UTC times and exact actions through the site's evidence process.

If containment requires changing a host or key, follow the
[key-rotation runbook](key-rotation-runbook.md) and preserve the old non-secret
identity/fingerprint and revocation time.

## Safe triage

Start with bounded, structured, non-mutating facts:

```bash
git rev-parse HEAD
git status --short --branch
biopipe version --json
biopipe schema list --json
biopipe source show pilot-source --json
biopipe execution-profile show pilot-executor \
  --profile-dir execution-profiles \
  --json
```

Do not run `source verify`, preflight, status, resume, or reconciliation until
the incident commander approves contact with the affected host. `source
verify` contacts the probe. Preflight creates remote isolation state and writes
local report/private state when appropriate; status writes the latest status,
private run state, and audit event; resume and abandonment can mutate additional
remote and local state.

Within the restricted evidence boundary, establish:

- exact source commit/tag, installed versions, schema/CLI/protocol versions;
- affected SourceProfile/execution-profile hashes and non-secret key IDs;
- run IDs, local submission state (`pending`, `accepted`, or `abandoned`), and
  the separate latest remote status (`submitted`, `running`, `succeeded`, or
  `failed`); hidden state remains read-only and is not a public API;
- the last known passed validation/test/preflight timestamps and hashes;
- host-key and executable/JAR/container identities from approved records;
- audit ordering and whether bytes/modes/ownership changed; and
- the minimum data classes potentially exposed.

Never attach full manifests, samplesheets, QC outputs, audit logs, remote config,
environment dumps, raw stdout/stderr, or key material to a lower-trust ticket.

## Scenario playbooks

### SSH host-key mismatch

Treat `SSH_HOST_KEY_MISMATCH` as possible interception or an unapproved rebuild.
Do not disable strict checking or accept the observed key. Obtain the expected
fingerprint through an authenticated independent channel, involve the SSH host
owner, and determine whether any credentials or traffic could have been
exposed. After an approved update, rerun only fixed health and fresh preflight
before restoring approvals.

### SSH or approval-key exposure

Pause new approvals, revoke the affected constrained public key or isolate the
approval endpoint, and enumerate accepted/pending runs. For HMAC exposure,
assume approval forgery is possible for that profile until audit, remote state,
and run reservations are reviewed. Create a new profile/config/key set; never
overwrite the old profile or reuse old preflights/authorizations.

### Path escape or raw-data disclosure

Stop probe/executor access to the affected root through the administrator.
Preserve the exact request/response evidence without copying raw records.
Determine whether the issue is a display-path disclosure, metadata exposure,
full read identifier, or sequence/quality disclosure. Inspect allowlists,
canonical/mount/symlink identities, versions, and configuration ownership.
Do not widen or relocate a root as the incident fix without a new review.

### Generated artifact, audit, or private-state corruption

Make a restricted immutable snapshot before any recovery. Compare the exact
source identity, generated bytes, controlled report hashes, profile, bundle,
run state, and audit ordering against retained evidence. Regenerate only into a
new path from reviewed inputs. Do not edit a finalized artifact or hidden state
to satisfy validation/status/resume.

### Runtime, container, JAR, or executable compromise

Isolate the executor endpoint and runtime/container daemon, stop new approvals,
and involve host/runtime owners. Record approved and observed identities. Treat
affected results as untrusted until the exact dependency, host exposure, run
set, and scientific impact are independently assessed. Restore only reviewed
absolute executables/JARs and hash/digest-pinned local containers, then create a
fresh profile/preflight and synthetic validation run.

### Lost submit response

The original failure can retain its transport code, commonly `SSH_TIMEOUT`,
while adding a recoverable `run_id`, `recovery_action=query_status`, and
`status_query_required=true`. It is not proof of compromise and not proof that
no job started. Preserve the exact run ID/private state and query that ID
through the fixed status path after remote contact is approved. A new submit
while the local record is pending is blocked as `RUN_SUBMISSION_FAILED`.

Only if exact status confirms the run absent may signed `--abandon-pending`
reconciliation be considered after the fixed five-minute grace period. An
attempt made too early returns `abandon_available_at`; wait until that time and
repeat the same explicit abandonment. It creates a tombstone; it does not
cancel a running job. Escalate if local/remote bindings disagree.

### Capacity exhaustion

Stop new submissions to the affected roots and preserve active-run state. Do
not delete unknown deployment/work/output/state directories or reduce the
preflight threshold. The capacity owner follows the
[capacity and quota runbook](capacity-and-quota-runbook.md), identifies exact
owners/holds, and authorizes allocation or disposal separately.

## Evidence integrity and communications

- Record original evidence hashes before producing a working copy.
- Restrict evidence access to the incident/data/key owners who need it.
- Keep UTC timestamps, collector identity, source location/classification, and
  every transformation/redaction decision.
- Use only sanitized counts, fixed statuses/error codes, versions, timestamps,
  run IDs, and hashes in broad status reports.
- State uncertainty explicitly. A passed local test, checksum, or sanitized
  bundle does not prove host integrity or absence of disclosure.
- Coordinate external notification, regulatory assessment, and legal hold
  through the organization's authorized process.

Vulnerability reporting follows [SECURITY.md](../SECURITY.md). Do not open a
public GitHub issue containing a suspected secret, private host/path, sample
identifier, exploit detail, or restricted evidence.

## Recovery gate

- [ ] The incident commander defined the affected identities, data classes,
      profiles, runs, and trust boundaries.
- [ ] Required evidence was preserved and checksummed before remediation.
- [ ] Compromised credentials/endpoints were revoked or isolated by their
      authorized owners.
- [ ] Host keys, configs, executables, JARs, containers, profiles, artifacts,
      audit, and state were independently reviewed as applicable.
- [ ] Recovery uses new immutable profiles/projects/targets where identity
      changed; no finalized artifact/state was hand-edited.
- [ ] Synthetic validation/test/preflight and constrained remote lifecycle
      checks passed after remediation.
- [ ] Data/scientific owners assessed whether existing results can be trusted.
- [ ] Backup/retention/legal-hold decisions were updated.
- [ ] Recovery approval, residual risk, monitoring window, and rollback owner
      are recorded.

## Post-incident review

Record root cause, control effectiveness, detection gap, operator friction,
affected versions/runs, key and retention actions, scientific impact, and an
owner/deadline for each corrective action. Add a regression test or runbook
change where safe and reproducible, but never commit real incident evidence.

Closing an incident does not complete M6.1/M6.2 acceptance or authorize
production use. Those claims require their own exact, independently reviewed
evidence.
