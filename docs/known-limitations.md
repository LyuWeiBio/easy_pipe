# Known MVP limitations

These constraints are intentional release boundaries, not hidden future
behavior. Do not design a production process that depends on an unsupported
capability.

## Workflow and data

- The only supported analysis goal is `fastq-qc`: raw FastQC, optional
  controlled fastp trimming, post-trim FastQC, and MultiQC.
- Input is FASTQ/FQ, plain or gzip, single-end or paired-end, with the reviewed
  generic/Illumina naming rules and multi-lane grouping. BCL demultiplexing,
  BAM/CRAM, VCF, expression quantification, variant calling, single-cell,
  metagenomics, and other assays are outside the MVP.
- Ambiguous naming and pairing require an explicit attributable override. The
  system does not infer experimental design from a delivery sheet or repair a
  missing/corrupt read.
- FastQC/fastp/MultiQC reports are produced but not biologically interpreted.
  Tiny synthetic fixtures validate wiring only.
- This is not a clinical pipeline, diagnostic device, clinical interpretation
  service, or regulatory-compliance package.

## Planning and generation

- Planning is deterministic and registry-driven; there is no natural-language
  planner, LLM integration, arbitrary component composition, custom shell, or
  custom Nextflow injection.
- Only controlled parameters represented by the v1 schema are accepted.
- Registry and schema v1 are frozen for the MVP, but there is no automatic
  migration tool for a future version.
- Generated projects are immutable/create-only. Hand-edited generated code does
  not satisfy the validation or approval contract.
- `plan --executor slurm` can render the reviewed site placeholder, but M5
  preflight and real-data execution support only the Nextflow `local` executor.
  There is no Slurm/PBS/SGE/Kubernetes/cloud submission implementation.

## Hosts and filesystems

- Controller support targets macOS and Linux with Python 3.11+. Remote probe and
  executor support Linux/POSIX only. Windows is not supported.
- The Remote Probe requires Python 3.11+; the Remote Executor requires Python
  3.9+ plus a separately installed Java, pinned Nextflow JAR, and container
  runtime. The zipapps do not bundle these runtimes.
- Deployment and uninstallation are manual. `biopipe` does not create remote
  users, manage `authorized_keys`, install Python/Java/Nextflow/runtimes, load
  images, configure a firewall, or rotate keys.
- Different Source and Execution Hosts are supported only when they already
  share the data through an explicit path mapping. There is no SFTP, rsync,
  object-storage staging, or automatic raw-data copy.
- Execution inputs and configured roots must meet strict ownership, mode,
  non-symlink, and immutability assumptions. Some group-writable HPC delivery
  trees therefore require an administrator-managed read-only projection.
- A blocked kernel/network-filesystem operation cannot be interrupted by the
  probe's cooperative deadline. The controller SSH timeout bounds its wait but
  cannot restore the mount.

## Containers and network

- Real-data execution requires exactly Docker or Apptainer. Podman,
  Singularity-as-a-separate-profile, Conda process environments, and native
  uncontainerized real-data processes are not supported.
- Docker is bound to the local Unix socket and requires every locked image to
  be present by digest. Rootless/custom Docker contexts are not an MVP profile.
- Apptainer requires a local SIF path and full file SHA-256 for every selected
  tool.
- The executor sets offline/network-disabled runtime options and a private
  environment, but it cannot attest to the host kernel, privileged daemon,
  namespace implementation, or firewall. Host-level egress controls are still
  required.
- The project does not scan containers, JARs, Python packages, or system
  libraries for vulnerabilities. A digest proves identity, not safety.

## Execution lifecycle

- Real-data execution uses only Nextflow's local executor. Site schedulers,
  quotas, queues, and fair-share policies are not integrated.
- There is no remote cancel, kill, pause, delete, cleanup, log-download, or
  arbitrary troubleshooting operation. Operators use host process/container
  controls under local policy.
- `--abandon-pending` resolves a submission whose response was lost after a
  safety delay. It creates an authenticated tombstone and is not cancellation.
- Resume is allowed only for an exact recorded compatible terminal run with its
  original work/output/cache identities and a fresh preflight/approval.
- Deployments, work directories, results, agent state, and logs are never
  deleted automatically. Backup, retention, quota, and secure disposal are
  external responsibilities.
- A process-group termination cannot prove cleanup of all descendants created
  by a privileged container daemon; external cgroup/runtime monitoring is
  required.

## Privacy, identity, and audit

- The controller receives filenames, paths, sizes, timestamps, grouping, and
  bounded FASTQ aggregate evidence. “Reads stay remote” does not mean the
  controller sees no sensitive metadata.
- Full manifests, samplesheets, QC reports, execution reports, and audit events
  may identify samples. Sanitized manifests reduce direct identifiers but are
  not a formal anonymization guarantee.
- There is no built-in encryption at rest, secrets manager, hardware-backed key
  storage, KMS integration, SIEM export, role-based access control, or multi-user
  approval workflow.
- Approval uses one symmetric HMAC key per configured profile. Rotation and
  revocation are manual.
- Audit JSONL is append-only and fsync-backed but is not a cryptographically
  chained transparency log, remote attestation, WORM store, or defense against
  a privileged filesystem administrator.
- Audit events cover generation and the safety-critical execution lifecycle.
  Earlier source/inspection/override/planning and M4 validation/test/preflight
  evidence is preserved in create-only artifacts and machine-readable reports,
  not duplicated as one audit event per CLI command.
- The tool does not contact an external documentation/model service, and it has
  no web UI or server API. Local filesystem access controls are the controller's
  user boundary.

## Packaging and support

- The project is installed from a reviewed Git checkout; no PyPI release or
  binary installer is promised by the MVP.
- The pinned mamba environment is the reproducible validation/demo reference.
  A minimal controller installation does not include the workflow toolchain.
- The project is pre-1.0 application software even though its public artifact
  schemas and remote protocols are version `1.0`.
- Security fixes target only the latest `0.1.x` tag and current default branch;
  see [SECURITY.md](../SECURITY.md).

Future expansion must preserve the same typed, least-privilege, create-only,
hash-bound, and explicit-approval boundaries rather than silently relaxing
them.
