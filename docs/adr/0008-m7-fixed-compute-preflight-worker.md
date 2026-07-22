# ADR 0008: Bind a fixed compute-preflight worker without activating Slurm

- **Status:** Accepted for dormant implementation
- **Date:** 2026-07-22
- **Scope:** M7.0d-d compute worker, runtime bindings, private files, and packaging

## Context

ADRs 0004 through 0007 define the pure compute-preflight state machine, load
trusted scheduler configuration, run six fixed Slurm operations, and burn each
scheduler mutation into append-only durable intent. The remaining compute-node
gap was executable evidence: the login node could submit a reviewed template,
but no separately installed artifact could validate the actual allocation,
runtime, inputs, containers, and shared storage or commit evidence for the
durable state machine.

Treating a worker path or its self-reported hash as trusted would be unsafe.
The worker also cannot rely on a zipapp `env` shebang because `PATH` would then
select the interpreter. Resume needs the original deployment, work, and output
directory identities, and an environmental check failure must remain readable
after Slurm reports a clean worker exit.

## Decision

### 1. Build a third, separately installed artifact

The closed zipapp builder accepts only two roles:

```text
executor           -> bioexec.main
compute-preflight  -> bioexec.compute_worker
```

The compute artifact is installed as the exact leaf
`bioexec-compute-preflight`. It has a distinct entry point and SHA-256; it is
not a renamed `bioexec.pyz` and cannot accept an arbitrary module or entry
point. Reproducibility checks build it twice under the normalized timestamp,
member-order, mode, and compression contract. The offline supply-chain
inventory records three artifacts while the M6.1 release-evidence contract
continues to cover only the two version-1 agents.

### 2. Bind the interpreter and complete compute runtime in manifest 1.1

Scheduler config-v2 now fixes absolute executables with the exact leaves
`python3`, `java`, `nextflow`, `apptainer`, and
`bioexec-compute-preflight`. The trusted loader records and hashes all five,
plus the exact Nextflow one/shadow JAR. The compute manifest is explicitly
version `1.1` and adds:

- absolute Python, Java, Nextflow launcher, Nextflow JAR, and Apptainer paths;
- full SHA-256 for each runtime object;
- the exact Nextflow version;
- command timeout and combined output budgets; and
- exact device, inode, owner, group, and mode for deployment, work, and output
  directories when resuming.

Resume identity records must appear exactly when `resume_run_id` appears, and
all three directories must remain exact mode `0700`. The service derives the
worker files only as:

```text
<state_root>/scheduler-preflights-v1/<preflight_id>/manifest.json
<state_root>/scheduler-preflights-v1/<preflight_id>/evidence.json
```

The public path derivation rejects non-identifiers, separators, traversal,
empty values, and values longer than 128 characters.

### 3. Invoke only a trusted absolute Python in isolated mode

The fixed batch template uses:

```text
<absolute-python3> -I -S <absolute-bioexec-compute-preflight> <five fixed args>
```

It never relies on `PATH`, the archive shebang, site packages, a user home, or
caller-selected Python flags. Immediately before `sbatch`, the scheduler
adapter reopens and rehashes Python, Java, the Nextflow launcher and JAR,
Apptainer, and the worker. The compute node repeats the relevant identity and
hash checks.

### 4. Accept exactly five ordered worker arguments

The worker accepts no positional values, abbreviations, repeated options, or
extension fields. Its ordered interface is:

```text
--contract-version=1.0
--manifest=<fixed manifest.json>
--manifest-sha256=<64 lowercase hex>
--worker-sha256=<64 lowercase hex>
--evidence=<fixed evidence.json>
```

Manifest and evidence must have one private parent, and the worker's current
directory must be that same directory identity. It opens every path component
without following links, stable-reads an owner-only `0600` manifest, requires
canonical bytes and the requested hash, and binds the CLI, interpreter, worker,
Slurm job ID, and submission marker before running checks.

### 5. Run twelve fixed checks in one frozen order

The worker executes only:

```text
allocation_policy
apptainer_runtime
cache_storage
deployment_target
free_space
input_paths
network_isolation
nextflow_runtime
output_storage
path_mapping
sif_artifacts
work_storage
```

The allocation check binds one node, one task, CPUs, memory, partition,
optional account/QOS, and the effective projected Slurm time limit. A null
account or QOS admits the site-selected default; a configured value must match
exactly. Runtime checks use full-file identities and hashes. Nextflow is
queried by the trusted Java/JAR pair in an offline private environment.
Apptainer receives a fixed clean, contained, no-home, network-none probe.

Read-only input traversal permits a data-administrator-owned tree only when
every traversed directory and file is non-symlink and not group/world-writable,
apart from the existing root/service-owned sticky-anchor exception; writable
roots, runtimes, JARs, SIFs, and worker state retain trusted ownership rules.
Storage checks use descriptor-based exclusive reservation probes and
`fstatvfs`. New deployment/work/output targets must be absent; resume targets
must match their exact original private identities. Every SIF is completely
hashed, and path mapping plus the ordered input-set hash are recomputed.

All subprocesses use one reviewed absolute argv, `shell=False`, an explicit
minimal environment, closed descriptors, a new process group, a combined
stdout/stderr ceiling, and one deadline. A process leader that exits while a
descendant retains a pipe receives only a short bounded drain window before
the original process group is terminated.

### 6. Separate environmental failure from worker failure

Every check yields a domain-separated evidence digest over its fixed name,
status, code, attempt identities, job binding, and bounded normalized
observations. If one or more environmental checks fail but all twelve records
are complete and the evidence file is durable, the evidence status is
`failed` and the worker exits `0`. This lets Slurm terminal success authorize
the controller to read the negative evidence.

Malformed trust input, an unexpected internal failure, or an uncertain
evidence commit exits fixed code `70` and does not claim a complete result. The
worker is silent on stdout and stderr in both cases.

### 7. Commit and read worker files through private descriptors

The durable store creates the canonical manifest with `O_EXCL`, exact mode
`0600`, complete writes, file `fsync`, and attempt-directory `fsync`. The
worker publishes evidence with the same create-only ordering and never
overwrites, removes, or repairs a prior destination. An uncertain write,
`fsync`, close, or directory commit remains burned and returns nonzero.

After scheduler-confirmed `COMPLETED 0:0`, the store reads evidence only in
`awaiting_evidence`. It requires a regular owner-only `0600` file with one
link, a 256 KiB ceiling, no-follow and stable descriptor/path identity,
canonical duplicate-free JSON, and exact binding to the current manifest,
worker, profile, job ID, and marker. Missing evidence is pending; malformed,
replaced, or cross-attempt evidence fails closed.

### 8. Keep all scheduler behavior dormant

No version-1 configuration, protocol, dispatcher, preflight, deployment,
runner, command, or service entry point imports the worker, scheduler store, or
scheduler adapter. This slice adds no version-2 operation, background driver,
capability persistence, workflow bootstrap, or cancellation surface.
Building or installing the artifact is not cluster acceptance and does not
activate Slurm.

### 9. Retain the path-execution race as an activation blocker

Hashing a pathname and later asking the operating system to execute that path
are not one atomic operation. Python and worker self-checks also occur after
the interpreter has already loaded them. A same-identity process able to
replace runtime paths can still race Java, Apptainer, JAR, SIF, interpreter,
or worker execution.

Before activation, the complete interpreter, worker, runtime, JAR, and SIF
path chains must be administrator-owned and immutable to the service identity,
or a separate Linux descriptor-based execution design must be reviewed. A
descendant that deliberately leaves the original process group also cannot be
proven terminated; site cgroup/runtime controls remain required.

## Consequences

### Positive

- Compute evidence is produced by one reproducible, hash-bound, fixed entry
  point rather than a general script or command surface.
- Interpreter, runtime, container, input, storage, resume, scheduler, and
  durable-file identities form one reviewable evidence chain.
- Negative preflight results remain available without turning an incomplete
  worker run into trusted evidence.
- Version 1 and M6.1 release semantics remain unchanged.

### Costs and remaining blockers

- Full executable, JAR, SIF, and worker hashing adds bounded compute-node I/O.
- Strict read and writable-root permissions may require site-managed read-only
  projections and root-managed runtime installation.
- Shared-filesystem `O_EXCL`, `flock`, stable identity, and directory `fsync`
  behavior still require a real Slurm-cluster acceptance run.
- Durable capability issue/consume semantics, post-deployment compute rechecks,
  active dispatch, and real workflow execution remain unimplemented.

## Next step

M7.0d-e adds the durable driver-to-candidate connection and trusted boot clock
described by ADR 0009. M7.0d-f must add the separate token-hash-only capability
lifecycle. A later deployment/bootstrap slice must re-open and re-hash the
deployed bundle and all runtime artifacts on the allocated compute node
immediately before Nextflow. No version-2 operation may be activated until
those pieces and real cluster acceptance are complete.

## Official scheduler basis

- <https://slurm.schedmd.com/sbatch.html>
- <https://slurm.schedmd.com/srun.html>
