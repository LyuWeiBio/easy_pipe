# Capacity, quota, and local observability runbook

> Status: **PROCEDURE_ONLY — UNEXECUTED TEMPLATE**.
>
> This repository copy is not capacity evidence and defines no site quota.
> Keep checkboxes unchecked. Owners must record approved thresholds, alerts,
> allocations, and measurements in the controlled operations system.

`easy_pipe` performs a fixed preflight free-space check but does not provide a
quota service, scheduler, monitoring agent, automatic cleanup, cancellation, or
capacity reservation. The site is responsible for deploy, work, output, cache,
private-state, raw-data, backup, and controller filesystems.

Every instruction below to pause or stop new submissions means an authorized
site/organizational control on operator access or the constrained endpoint.
There is no `biopipe pause` command.

## Capacity record

- Environment/pilot ID: `________________`
- Exact commit/tag: `________________`
- Capacity owner: `________________`
- Per-device filesystem/quota owner and alternate: `________________`
- Execution/runtime owner: `________________`
- Data/results owner: `________________`
- Backup/retention owner: `________________`
- Incident contact: `________________`
- Monitoring system and access class: `________________`
- Alert escalation owner: `________________`
- Review period: `________________`
- Evidence location/checksum: `________________`

Do not place complete filesystem paths, mount names, hostnames, sample names,
command output, or private configuration in a broadly visible dashboard.

## Filesystem roles

The remote executor configuration keeps its read, deploy, work, output, cache,
and private-state roots non-overlapping by canonical path and filesystem
identity. Controller project/backup storage is outside that configuration and
needs separate site controls:

| Role | Growth driver | Availability/retention concern |
|---|---|---|
| Preflight isolation | Per-request client-home, runtime-config, NXF-home, and temporary directories, including for failed checks | Remote state accumulates; no automatic cleanup |
| Deploy | One bounded immutable run snapshot created on the first approved deployment/submit, not on preflight | Create-only; preserve through run/review window |
| Work | Nextflow task state, intermediate files, logs | Usually largest transient class; needed for diagnosis/resume |
| Output | FastQC/fastp/MultiQC results and workflow evidence | Potentially sensitive durable result; data-owner retention |
| Cache | Reviewed local images/SIFs and runtime cache | Must retain exact locked artifacts; never solve low space by pulling an unreviewed replacement |
| Private state | Tokens, reservations, leases, run bindings | Small but critical; mode `0700`, executor-only, never prune casually |
| Controller project | Manifests, generated sources, reports, hidden recovery state, audit | Back up as a bound sensitive tree |
| Raw/read root | Primary data managed outside `easy_pipe` | Read-only from this workflow; never cleanup target |

Role roots may share a physical filesystem, so sum planned demand across every
role on that device. Preflight checks each requested role path independently;
it does not aggregate same-device demand. A passing check on one path does not
create a reservation or guarantee space remains available through the run.

## Preflight thresholds

The controller execution profile defaults to `10 GiB` minimum free space and
allows a reviewed `--minimum-free-bytes` value from `1 GiB` through `1 PiB`.
The executor configuration also defines `limits.minimum_free_bytes` (default
`1 GiB`) as a host-local lower bound. A request cannot lower that executor
floor.

Preflight checks available bytes for deploy, work, output, and cache and returns
the fixed failed check/code `disk_space` / `INSUFFICIENT_SPACE` when any is below
the requested minimum. It does not estimate workflow-specific peak demand.

Set the immutable profile threshold from a documented estimate:

```text
minimum free before approval
  >= expected peak new work
   + expected new output
   + deployment/cache increment
   + concurrent-run allowance
   + filesystem/site safety reserve
```

Changing the threshold changes the profile hash and requires a new immutable
profile, matching executor configuration, fresh preflight, and new approval.
Never edit a profile or reported hash merely to clear `INSUFFICIENT_SPACE`.

## Quota planning

Before each pilot wave, record per role/device:

- approved hard/soft quota and current usage;
- available bytes and inodes;
- expected case count and maximum concurrency;
- expected input size and reviewed work/output multiplier;
- cache/deployment increment;
- active-run, resume, incident, legal, and retention holds;
- warning/critical thresholds and notification owner; and
- allocation or disposal lead time.

The first internal pilot should run serially unless the capacity owner has
reviewed concurrency. Local executor support is not scheduler isolation; host
cgroups, daemon limits, account quotas, process monitoring, and fairness remain
site responsibilities.

Planning `--max-cpus` is a per-component ceiling rendered as local executor
queue size, not a hard cap on total run/host CPU. `--max-memory-gb` is also a
component ceiling, not a total memory limit. Those fields and executor
`limits.*` validation bounds do not provide cgroups, concurrency enforcement,
fairness, quotas, or capacity reservations.

## Allowed local observability

Collect only structured, non-sensitive fields needed to operate the pilot:

- scan file count and duration;
- manifest sample and lane counts;
- validation/test/preflight fixed status and code;
- run state transitions and return code;
- deploy/work/output/cache free or used byte buckets;
- external-command timeout/error code counts; and
- audit parse/order/integrity status.

Bind each observation to an anonymous environment/case ID, exact version/commit,
UTC timestamp, and collection policy version. Prefer coarse buckets where exact
values could reveal dataset scale. Full paths, read names, sample names, raw
records, keys, tokens, complete stdout/stderr, audit lines, and complete reports
are forbidden in the shared metric stream.

There is no built-in metrics exporter. Use site-local filesystem/runtime
monitoring outside the controller protocol, with an explicit allowlist and
redaction review. Do not add a generic remote command or environment interface
to collect metrics.

The repository-local [internal pilot evidence compiler](internal-pilot-evidence.md)
is not a metrics exporter. It accepts only an operator-prepared strict
sanitized snapshot and packages coarse buckets, bounded counts, fixed states,
and SHA-256 pointers into an unreviewed `BLOCKED` draft. It never crawls the
project, runtime, reports, audit log, filesystem, or remote host.

## Alert and response matrix

| Condition | Required action | Forbidden shortcut |
|---|---|---|
| Preflight `INSUFFICIENT_SPACE` | Stop approval; capacity owner allocates space or applies an approved retention decision, then rerun fresh preflight | Lowering threshold without a new reviewed profile |
| Work/output growth above warning | Stop new submissions to affected root; identify exact active/held projects | Deleting the newest or largest unknown directory |
| Inode exhaustion | Treat as capacity failure even when bytes remain; involve filesystem owner | Broad recursive cleanup |
| Cache pressure | Retain exact locked images/SIFs needed by active profiles; review removal of unused identities separately | Pulling a floating/new image or modifying software lock |
| Private-state pressure/corruption | Stop submissions and preserve state; escalate through incident response | Editing/removing reservations, leases, or tombstones |
| Controller/backup pressure | Preserve project/audit/recovery state and follow approved retention | Moving private state into source control or a public share |
| Runtime runaway | Use site process/cgroup/runtime authority and preserve run state/evidence | Treating `--abandon-pending` as cancellation |

## Response to low space

1. Use authorized site/organizational controls to stop new approvals and access
   to submission on affected roots; do not look for a CLI pause operation.
2. Identify active, pending, terminal, resumable, incident-held, and
   retention-held projects through controlled records.
3. Confirm whether multiple logical roles share one filesystem/device.
4. Preserve controller and remote private state before any external action.
5. Allocate capacity or select disposal-eligible targets under the
   [backup/retention runbook](backup-retention-runbook.md).
6. Have the data/run owner and capacity/retention owner authorize exact targets.
7. Apply the site-admin action outside `biopipe`; the application has no delete
   endpoint.
8. Recheck capacity and runtime health, then run a fresh preflight. A previous
   preflight is not reusable after a material environment change.

If space loss caused partial writes, state disagreement, or uncertain execution,
follow the [incident-response runbook](incident-response-runbook.md) and do not
assume freeing space repairs integrity.

## Pilot review worksheet

For each anonymous case, record controlled values or approved buckets:

| Field | Before | Peak | Terminal/retained | Owner decision |
|---|---:|---:|---:|---|
| Preflight isolation bytes/inodes | `____` | `____` | `____` | `____` |
| Deploy bytes/inodes | `____` | `____` | `____` | `____` |
| Work bytes/inodes | `____` | `____` | `____` | `____` |
| Output bytes/inodes | `____` | `____` | `____` | `____` |
| Cache bytes/inodes | `____` | `____` | `____` | `____` |
| Private-state bytes/inodes | `____` | `____` | `____` | `____` |
| Controller project/backup | `____` | `____` | `____` | `____` |

Do not commit a completed worksheet when its values could identify internal
storage or dataset scale.

## Closeout checklist

- [ ] Every filesystem role has a capacity, runtime, data, and retention owner.
- [ ] Thresholds and concurrency assumptions are bound to the exact profile and
      executor configuration.
- [ ] Planning and executor limit fields were not treated as host quotas,
      reservations, cgroup controls, or scheduler isolation.
- [ ] Bytes and inodes are monitored with warning/critical escalation.
- [ ] Shared metrics contain only approved structured fields and no sensitive
      identity/path/output content.
- [ ] A low-space drill produced `INSUFFICIENT_SPACE`, blocked approval, and
      recovered through allocation/retention plus fresh preflight.
- [ ] Runtime runaway and response-loss procedures were not confused with a
      nonexistent cancel command.
- [ ] Disposal decisions followed backup, hold, exact-target, and independent
      authorization requirements.
- [ ] Peak/retained observations informed the next pilot quota and review date.
