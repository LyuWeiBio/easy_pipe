# Backup, retention, restore, and disposal runbook

> Status: **PROCEDURE_ONLY — UNEXECUTED TEMPLATE**.
>
> This file does not establish a retention policy or prove a backup/restore.
> Keep repository checkboxes unchecked. The data owner and site administrators
> must approve actual periods, storage systems, encryption, legal holds, and
> disposal evidence.

`easy_pipe` does not back up, replicate, archive, encrypt, delete, or expire
project or remote data. Planning/generated bundles and deployment/output
targets are create-only, but most controller reports and hidden state are
atomically replaced as the latest view; `audit/events.jsonl` is append-only.
The executor leaves deployment, preflight/run state, work, output, and logs in
place. This runbook defines the decisions around those boundaries.

## Policy record

- Policy/change ID: `________________`
- Exact commit/tag: `________________`
- Data classification: `________________`
- Data owner: `________________`
- Backup owner: `________________`
- Secret-backup custodian: `________________`
- Retention owner: `________________`
- Restore approver: `________________`
- Restore-test operator: `________________`
- Secure-disposal owner: `________________`
- RPO/RTO authority: `________________`
- Incident/legal-hold contact: `________________`
- Capacity owner: `________________`
- Approved storage/encryption boundary: `________________`
- Evidence location/checksum: `________________`

Record storage-system identifiers only at the minimum sensitivity needed. Do
not put real hosts, raw paths, sample identifiers, keys, tokens, or complete
manifests in a repository copy of this record.

## Asset classes

Assign a site-approved retention class and owner to every row before a pilot.

| Asset | Sensitivity and purpose | Backup/restore rule |
|---|---|---|
| Reviewed source commit/tag and release evidence | Integrity identity; sanitized evidence may still expose operational metadata | Retain immutable checksums and independent review; do not present draft evidence as sign-off |
| Full controller project tree | May contain names, paths, samplesheet, full manifests, latest reports, hidden recovery state | Encrypted restricted cold backup as one bound tree; preserve modes and never edit hidden state |
| `audit/events.jsonl` | Sensitive append-only lifecycle metadata; not a cryptographic chain or WORM store | Retain and externally anchor according to policy; restore only with the matching project identity |
| Controller approval HMAC key | Secret authorization material | Use approved secret backup/escrow separate from project backup; never place in evidence archive |
| SSH private keys/agent configuration | Secret transport identity | Managed by site SSH/KMS policy, not the project backup |
| Execution profile and SourceProfile | Contains hosts/roots/key references, not key bytes | Restricted configuration backup tied to exact hash and version |
| Remote deployment snapshot | Reproducible bounded code/config used by a run | Retain through run/review window; verify bundle hash before relying on a restore |
| Remote work directory | Nextflow state needed for diagnosis/resume | Retain while run/recovery/resume obligations exist; treat as potentially sensitive |
| Remote result directory | QC outputs and operational logs may identify samples | Data-owner retention and access controls apply; never assume reports are de-identified |
| Remote private executor state | Tokens, reservations, leases, preflight/run files, profile/run bindings | Cold owner-only backup if policy requires; copied state does not guarantee status/resume and must never overwrite live state |
| Raw FASTQ delivery | Primary high-sensitivity source data outside `easy_pipe` ownership | Follow source-system policy; this project never copies or deletes it |
| Sanitized pilot/acceptance summary | Counts, fixed statuses, versions, timestamps, hashes | Verify redaction and checksum; sanitized is lower risk, not guaranteed anonymous |

## Backup procedure

1. Identify the exact commit/tag, project ID, profile hash, run IDs, and current
   terminal/pending state without exporting full reports.
2. For active, pending, or uncertain runs, preserve the original state and
   endpoint. A live storage snapshot may be incident evidence, but must not be
   advertised as a resumable operational backup. Coordinate a quiesced/cold
   snapshot after terminal closure with the run and execution owners.
3. Use the site's approved snapshot/backup mechanism with encryption, access
   logging, integrity checks, and a destination suitable for the data class.
4. Preserve regular-file bytes, directory/file modes, ownership metadata where
   required, and the relationship between project, audit, latest reports, and
   hidden state. Record that live file locks are not captured.
5. Compute/record checksums inside the controlled boundary. Publish only the
   minimum sanitized aggregate needed for evidence.
6. Verify the backup can be enumerated and read by the restore role without
   exposing its contents to the pilot/release record.
7. Record completion time, backup-system object/version, checksum reference,
   owner, and next restore-test date.

Do not use an ordinary source archive as a backup of live projects: Git excludes
private state and should never contain real manifests or outputs. Do not copy
approval or SSH keys into the project tree to make backup simpler.

## Restore drill

Restore tests must use an isolated non-live destination and synthetic or
approved non-sensitive data. A restore is not a supported way to overwrite an
active project or executor state.

1. Use site controls to stop approvals/access and isolate any executor endpoint
   that could consume restored private state; there is no CLI pause command.
2. Restore into a new empty owner-only root. Never restore over live controller
   or remote state.
3. Verify expected inventory, modes, ownership, exact commit/profile/bundle
   hashes, report parseability, and audit parse/order before enabling any CLI
   operation.
4. Do not invoke submit, resume, or pending-abandon against restored state as a
   mere backup test. Those operations can mutate real remote state.
5. For a synthetic functional drill, register a new isolated profile/root set,
   run fresh validation/test/preflight, and use a new project/output identity.
6. Compare the controlled checksum result with the backup record and document
   every missing, normalized, or unsupported metadata field.
7. Remove test access according to site policy only after the evidence and any
   incident/legal hold are settled.

Deployment/work/output records bind filesystem device/inode identities, and a
copied `supervisor.lock` does not preserve its live process lock. Controller
reports and hidden state are latest views, not a complete history. Consequently
this procedure does not promise that a restored copy can perform status,
response-loss recovery, or resume.

Preserve and use the original project/state/endpoint for those operations. If
they are unavailable, involve the execution and incident owners and treat
recovery as unsupported/uncertain; never hand-edit copied state to make it
appear compatible.

## Retention decisions

The repository intentionally supplies no universal day counts. Define each
period from institutional policy, data-owner agreement, active-run needs,
incident/legal holds, reproducibility needs, and storage capacity.

At minimum, record separate decisions for:

- source delivery and raw reads;
- full controller artifacts and hidden recovery state;
- audit records and any external integrity anchor;
- remote preflight isolation and private protocol records;
- remote deployments and work directories;
- results and QC reports;
- approval/SSH secrets and revoked-key records;
- sanitized release/pilot evidence; and
- backup logs and restore-test evidence.

Retention expiry never grants automatic deletion authority. Before disposal,
confirm the exact target, owner approval, terminal run state, absence of
pending/reconciliation/resume need, backup success, legal/incident holds, and
the relationship to retained evidence.

## Capacity-aware retention

Use the [capacity and quota runbook](capacity-and-quota-runbook.md) to monitor
deploy, work, output, cache, and private-state filesystems. Low space is handled
by capacity allocation or an approved retention decision—not by deleting the
newest unknown directory or weakening the preflight threshold.

Recommended lifecycle states for site records are:

```text
active run
→ terminal but recoverable/reviewable
→ retention hold
→ disposal eligible
→ independently authorized disposal
→ disposal evidence retained
```

The executor has no cancel/delete endpoint. Any runtime termination or
filesystem disposal is an external site-admin action and must not be described
as a `biopipe` operation.

## Security and incident holds

Immediately suspend scheduled disposal when evidence may be needed for:

- suspected raw-data or identifier disclosure;
- HMAC/SSH key exposure or forged approval;
- host-key mismatch or possible interception;
- arbitrary command/container/runtime compromise;
- audit/private-state corruption;
- lost submission response or uncertain remote execution; or
- legal, regulatory, or data-owner hold.

Follow the [incident-response runbook](incident-response-runbook.md). Preserve
evidence without copying raw reads, secrets, or full diagnostics into an
ordinary ticket.

## Closeout checklist

- [ ] Every asset class has a data owner, backup owner, retention period,
      storage boundary, and restore authority.
- [ ] Project, audit, hidden state, secret, work, and result handling are
      separated by sensitivity.
- [ ] At least one isolated restore drill verified bytes, modes, hashes, and
      parseability without touching live state.
- [ ] The restore record makes no unsupported claim that copied state preserves
      live locks, inode bindings, status, response-loss recovery, or resume.
- [ ] Recovery time/objective and maximum acceptable data loss are recorded by
      the organization, not inferred from this tool.
- [ ] Active, uncertain, resumable, incident-held, and disposal-eligible states
      are distinguishable.
- [ ] Disposal requires exact target resolution and independent authorization;
      no broad recursive deletion command is embedded in automation.
- [ ] Sanitized backup/pilot evidence contains no real host, path, sample, raw
      record, private state, secret, token, or signature.
- [ ] An independent reviewer checked the evidence checksum and next test date.
