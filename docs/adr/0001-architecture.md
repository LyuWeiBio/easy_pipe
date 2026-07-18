# ADR 0001: Local-first, artifact-oriented architecture

- **Status:** Accepted
- **Date:** 2026-07-18
- **Decision owners:** easy_pipe maintainers
- **Scope:** M0 foundation and constraints for the MVP

## Context

The MVP is intended to help a bioinformatics analyst discover remote FASTQ
inputs and produce a reproducible quality-control workflow. Raw data may live
on a laboratory server, shared filesystem, or HPC system and must remain in
that environment. At the same time, generated plans, software choices, and
execution decisions must be reviewable and auditable.

The system therefore has to satisfy two concerns that are easy to conflate:

1. reason about data structure without transferring reads to the controller;
2. generate and eventually execute useful workflows without becoming a
   general-purpose remote command runner.

M0 establishes contracts and repository structure only. It deliberately does
not implement SSH, remote probing, FASTQ inspection, pipeline generation, or
real-data execution.

## Decision

### 1. Separate host roles

The architecture models three roles independently:

- **Controller host:** runs the `biopipe` CLI, validates structured artifacts,
  plans workflows, and coordinates tests.
- **Source host:** stores raw data and will run the constrained read-only probe.
- **Execution host:** will run Nextflow close to the data after preflight and
  explicit approval.

A deployment may assign multiple roles to one machine, but the domain model
must not rely on that arrangement. In particular, access by the source host
does not imply access by the execution host.

### 2. Exchange typed, versioned artifacts

Subsystems communicate through strict, versioned Pydantic models rather than
loosely structured dictionaries or hidden database state. The primary planned
artifacts are `DatasetManifest`, `ManifestOverrides`, `PipelineSpec`,
`SoftwareLock`, `ExecutionPlan`, and `AuditEvent`.

JSON is the canonical machine-facing representation; YAML may be used for
human-reviewed inputs where supported. Unknown fields are rejected by default.
File-based artifacts make changes diffable, portable, and suitable for Git
review. A database may be added later for multi-project indexing, but is not a
dependency of the MVP.

### 3. Keep the CLI thin

Typer provides the user-facing command hierarchy, while domain models,
serialization, validation, hashing, and audit behavior remain independent of
terminal rendering. CLI commands translate validated user input into calls to
the appropriate subsystem and translate known failures into stable structured
errors.

M0 commands are placeholders. Their presence documents the intended product
surface and does not authorize networking, subprocess execution, or data
access.

### 4. Constrain the future remote boundary

Remote inspection will use the system OpenSSH client with the user's existing
configuration, SSH agent, and host-key policy. The controller will invoke a
versioned probe that accepts a bounded JSON Lines request protocol on standard
input and returns structured JSON Lines responses on standard output.

The probe will:

- implement an allowlist of fixed, read-only operations;
- canonicalize requested paths and enforce configured allowed roots;
- enforce budgets for files, bytes, records, depth, and elapsed time;
- return file metadata and aggregate format evidence only;
- never return sequences, quality strings, complete read identifiers,
  credentials, or arbitrary file contents.

There will be no general command, shell, `eval`, dynamic plugin, or arbitrary
Python operation. These constraints are architectural requirements for future
milestones, not features already implemented in M0.

### 5. Compile from reviewed components

Pipeline planning and Nextflow generation will be deterministic. A reviewed
component registry will define allowed tools, parameters, templates, and
immutable container references. User or model supplied free-form command text
will not be compiled into a workflow.

The first workflow target is FASTQ quality control: FastQC, optional fastp,
post-trim FastQC, and MultiQC. Broader assay support and model-assisted planning
are later extensions and must preserve the same typed boundary.

### 6. Make execution an explicit gated capability

Validation and execution remain separate operations. Any future real-data run
must require, in order:

1. schema and cross-field validation;
2. static and test-data checks appropriate to the generated workflow;
3. execution-host preflight for runtime, paths, storage, and containers;
4. an explicit real-data approval flag.

Subprocesses must receive argument arrays rather than shell command strings,
use timeouts, and check return codes. M0 implements no execution path.

### 7. Prefer auditable, fail-closed behavior

Failures use stable error codes and serializable details. Security-related
defaults deny access or execution when configuration is missing or ambiguous.
Important actions append structured events to JSONL audit logs; audit writes do
not overwrite earlier events. Logs and fixtures must not contain secrets or raw
biological data.

## Component boundaries

The intended dependency direction is:

```text
CLI adapters
    |
    v
application services (future sources / manifests / planner / validator / runner)
    |
    v
domain contracts + errors + serialization + hashing + audit
    |
    v
explicit infrastructure adapters (future OpenSSH / filesystem / Nextflow)
```

Infrastructure behavior must be reached through explicit adapters so that core
validation remains testable without a network, scheduler, container runtime,
or access to real data.

## Consequences

### Positive

- Raw data can remain on the source or execution infrastructure.
- Artifacts and changes are inspectable with ordinary files and Git.
- Stable models reduce ambiguity between discovery, planning, generation, and
  execution.
- A narrow probe and approval gate limit the impact of malformed input or an
  unsafe generated plan.
- Core behavior can be tested offline with synthetic fixtures.

### Costs and trade-offs

- File-based projects require explicit indexing if cross-project search is
  introduced later.
- Strict schema evolution requires versioning and migrations.
- A fixed probe and reviewed component registry support fewer ad-hoc workflows
  than a general remote shell.
- Keeping source and execution roles separate adds configuration and preflight
  work, even when many deployments use the same host for both.

These costs are accepted because traceability and least privilege are primary
requirements for the MVP.

## Rejected alternatives

### General-purpose SSH command execution

Rejected because it would make path policies, returned data, and side effects
difficult to bound or audit.

### Copying FASTQ data to the controller for inspection

Rejected because it violates the local-first privacy boundary and creates
unnecessary transfer and storage risk.

### Database-first project state

Rejected for M0 because it obscures diffs and adds deployment complexity before
multi-user search or indexing is required.

### Free-form workflow generation

Rejected for the MVP because arbitrary shell or Nextflow output cannot provide
the deterministic, reviewed software boundary required for safe execution.

## Follow-up decisions

Later ADRs should record material choices that are not settled here, including:

- the exact probe packaging and deployment mechanism;
- schema compatibility and migration policy;
- the initial component registry format and container pinning rules;
- execution profile semantics for local, shared-filesystem, and Slurm hosts;
- retention and integrity policy for audit records.
