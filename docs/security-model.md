# Security and threat model

This document describes the MVP security boundary. It is an engineering model,
not a claim of regulatory compliance, clinical suitability, or protection from
a malicious administrator of a trusted host.

## Security objectives

The design aims to:

1. keep FASTQ sequence and quality data on the Source or Execution Host;
2. prevent the controller from becoming a general remote-command channel;
3. allow access only below explicit filesystem roots;
4. generate only the reviewed FASTQ-QC component graph with immutable software
   identities;
5. prevent real-data submission until validation, synthetic tests, fresh
   preflight, and attributable approval all bind to the same artifact hashes;
6. produce bounded, structured output without credentials or raw read content;
   and
7. preserve enough local and remote evidence to investigate a run.

Availability, biological correctness, host administration, backup, retention,
encryption at rest, enterprise identity management, and regulatory validation
remain operator responsibilities.

## Assets and data classes

| Asset | Sensitivity | Default handling |
|---|---|---|
| FASTQ sequence and quality | High | Read in place; never returned by the probe |
| Complete read identifiers | Sensitive | Parsed only for bounded aggregation; never returned |
| Sample names and filenames | Potentially sensitive | Present in full local artifacts; replaced in sanitized manifests |
| Remote paths and mount layout | Potentially sensitive | Present on controller and in bound local state; not sent to internet services |
| MultiQC/FastQC/fastp reports | Potentially sensitive | Remain under the reviewed result root |
| SSH private keys and passwords | Secret | Managed by OpenSSH/agent; never stored by `biopipe` |
| Approval HMAC key | Secret | Owner-only controller file and mode-0600 agent config only |
| Container/JAR/artifact hashes | Non-secret integrity data | Recorded in profiles, locks, reports, and audit events |
| Audit trail | Sensitive operational metadata | Append-only local JSONL with restricted filesystem access |

A sanitized manifest is intended for lower-risk review, but it is not a formal
de-identification guarantee. Dataset shape, counts, timestamps, and other
context can still be identifying when combined with external information.

## Trust assumptions

The MVP trusts:

- the Controller Host administrator, controller process, selected checkout,
  Python environment, local filesystem, and operator identity;
- the Source and Execution Host kernels and administrators;
- the OpenSSH client/server, verified host keys, constrained account keys, and
  local SSH agent;
- the exact Python interpreter used to start each remote zipapp;
- root- or service-owned executable/configuration parent chains on the
  Execution Host;
- the reviewed component registry, compiler templates, locked software, pinned
  Nextflow JAR, and locally installed container artifacts; and
- the operator's review of path mappings, outputs, licenses, and biological use.

If any trusted host administrator is malicious, that administrator can read
data available to the account, replace system components, observe process
memory, or change the kernel. The zipapps do not attempt to defend against that
privilege level.

## Threat actors and considered threats

The controls address accidental misuse and untrusted request/artifact/path
content, including:

- a crafted path that escapes an allowlisted root;
- a symlink or rename race during traversal or artifact access;
- a malformed, duplicate-key, deeply nested, non-finite, or oversized JSON
  request;
- a directory containing too many files or FASTQ content exceeding budgets;
- command/argument/environment injection through identifiers or paths;
- an SSH host-key mismatch, authentication error, timeout, or unbounded output;
- a modified manifest, generated file, software lock, validation report, test
  report, profile, container, JAR, executable, deployment, or resume target;
- real-data submission without explicit approval or with stale preflight;
- replay or forgery of a submit, resume, or pending-abandon mutation;
- an output collision or implicit overwrite; and
- a lost remote response leaving an ambiguous local submission state.

The MVP does not claim to address a compromised controller, root compromise,
malicious container daemon, kernel escape, side-channel exfiltration, denial of
service by a blocking network filesystem call, or all risks in the scientific
software supply chain.

## Boundary and control map

### Controller to Source Host

- The SourceProfile stores an SSH alias and limits, not a password or private
  key.
- OpenSSH is invoked with a fixed argument array, strict host-key checking,
  bounded stdout/stderr, timeout, and sanitized diagnostics.
- Requested data paths travel in JSON on standard input, not in SSH argv.
- The Remote Probe accepts only `health`, `list_tree`, `stat_files`,
  `detect_formats`, and `summarize_fastq`.
- Host-local configuration supplies the authoritative allowlist. Requests
  cannot add roots, enable symlink following, or raise budgets.
- Filesystem traversal uses directory descriptors, no-follow opens, identity
  checks, and optional mount-boundary enforcement.
- FASTQ inspection returns classification and aggregate length/encoding/header
  evidence, never the record lines.

### Manifest to generated project

- Strict schema version `1.0`, duplicate-key rejection, cross-field checks, and
  embedded SHA-256 prevent silent artifact reinterpretation.
- Overrides are separate attributable inputs. They cannot invent an unscanned
  path, silently fix a missing mate, or modify the original manifest.
- Only a full, valid, resolved manifest can be planned. A sanitized manifest is
  not executable input.
- The planner accepts only the fixed `fastq-qc` goal and controlled parameters.
  No free-form shell, Nextflow, URL, image, or tool definition is compiled.
- Registry components and OCI digests are reviewed and versioned. Generated
  projects are create-only and reproducible from the same inputs and versions.

### Validation and synthetic testing

- Static checks rederive the expected project and verify hashes, graph,
  containers, paths, samplesheet, and generated file bytes.
- Runtime checks use freshly copied generated sources and tiny committed
  synthetic FASTQs in isolated temporary roots.
- External commands use argument arrays, timeouts, output ceilings, and an
  allowlisted environment. Captured stdout/stderr is not written into reports.
- Nextflow operates offline with every container runtime disabled during local
  synthetic validation. Success proves wiring and compatibility, not biological
  quality or approval for real reads.

### Controller to Execution Host

- The Remote Executor accepts only `health`, `preflight`, `deploy`, `submit`,
  `status`, `resume`, and signed `abandon`; there is no general upload, command,
  environment, URL, or deletion operation.
- Configuration is strict, mode-restricted, no-follow opened, and bound to the
  exact controller profile hash. Read, deploy, work, output, cache, and private
  state roles cannot overlap or alias one another.
- Java, the Nextflow launcher, the pinned offline JAR, and the selected runtime
  are absolute trusted files whose identities are checked at startup, preflight,
  and immediately before launch.
- Deploy accepts only a bounded production file allowlist and verifies every
  file and the canonical bundle hash. Raw-data and test/report trees cannot be
  uploaded.
- Preflight binds the profile, project, mapped input set, storage, runtime,
  container evidence, and a short-lived one-use token.
- Submit, resume, and pending-abandon carry HMAC-SHA256 over the complete
  versioned operation payload. Verification happens before reading or mutating
  run state or consuming the token.
- Work and output directories are new, private, and create-only. Resume
  requires the prior compatible terminal state and exact filesystem identities.
- A durable reservation, job lease, deterministic audit events, idempotent
  acceptance recovery, and signed tombstone make response-loss outcomes
  recoverable without guessing that a job did not start.

### Runtime containment

The executor creates a private final Nextflow configuration with `-C`, forces
the local executor, disables Wave/Tower/Fusion, and rebuilds the environment
from an allowlist with `NXF_OFFLINE=true`. Each preflight/run receives private
`HOME`, `NXF_HOME`, temporary, Docker, and Apptainer configuration directories.
Proxy, credential, context, loader, and inherited Nextflow variables are not
passed.

Docker uses the local Unix socket with `--network none --pull=never`.
Apptainer uses hash-verified local SIFs with `--containall`, `--no-home`,
`--cleanenv`, and an isolated network namespace. Host firewalling remains the
recommended outer boundary: the agent cannot prove that an administrator's
daemon, container runtime, kernel namespace, or firewall behaves correctly.

## Approval and audit semantics

Real-data approval is not a reusable boolean. It is bound to:

- the full manifest, PipelineSpec, execution plan, software lock, and execution
  profile hashes;
- successful validation, successful synthetic test, and fresh passed preflight
  report hashes;
- the deployment bundle and compatibility hashes;
- an attributable actor and approval timestamp; and
- the explicit `--approve-real-data` invocation plus the configured HMAC key.

Any bound change requires new validation/preflight/approval as applicable.

Audit events are append-only JSONL written with locking, strict event parsing,
and durable filesystem synchronization. Deterministic events are idempotent
across recovery. This is not a cryptographic transparency log, remote
attestation service, WORM store, or protection from an administrator who can
rewrite the audit filesystem. Export/anchor audit evidence under local policy
when stronger non-repudiation is required.

## Residual risks

- The controller necessarily learns filenames, sample grouping, paths, file
  sizes, and bounded format summaries for full project operation.
- Full manifests and QC reports can reveal sample identity even though reads do
  not leave the remote host.
- Input files must remain immutable during a run. The executor rechecks them
  immediately before launch, but Nextflow later reopens them; a privileged or
  authorized writer can still change content during execution.
- Filesystem calls may block in the kernel despite cooperative deadlines. The
  outer SSH timeout bounds the controller wait but cannot repair a failed mount.
- A process-group termination cannot prove that a privileged container daemon
  removed every descendant or resource. Use host cgroups/runtime monitoring.
- Symmetric HMAC key compromise allows approval forgery for that profile. Rotate
  both copies, replace the profile/config, and invalidate pending work after any
  suspected exposure.
- Container digests and file hashes prove identity, not absence of
  vulnerabilities or scientific correctness.
- No automatic backup, encryption at rest, SIEM export, key management service,
  multi-user authorization, scheduler isolation, or retention policy is
  provided.

## Deployment hardening checklist

- Use separate service accounts and constrained SSH keys for probe and executor.
- Record and verify host keys; never disable strict checking.
- Keep SSH, HMAC, and runtime credentials separate and owner-only.
- Use the smallest read allowlist and non-overlapping private write roots.
- Make config, executable, JAR, SIF, and parent-chain ownership/permissions pass
  the documented checks.
- Preload only reviewed digest/hash-pinned images and block runtime egress with
  host firewall policy.
- Run the anonymous release acceptance scenario before introducing real paths.
- Review dry-run output, every artifact hash, mapped input, result target, and
  actor before approval.
- Monitor the execution account, filesystem capacity, daemon/cgroup state, and
  audit trail outside the application.
- Establish backup, retention, incident response, key rotation, and secure
  disposal procedures before production use.

For reporting a vulnerability, see [SECURITY.md](../SECURITY.md). Operational
errors are covered by the [troubleshooting guide](troubleshooting.md).
