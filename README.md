# easy_pipe

`easy_pipe` is a local-first, remote-data-aware tool for building and running
one constrained bioinformatics workflow: FASTQ discovery followed by FastQC,
optional fastp trimming, post-trim FastQC, and MultiQC. It keeps reads on the
source or execution host, turns every reviewed input into versioned artifacts,
generates a deterministic Nextflow DSL2 project, validates it with synthetic
data, and requires an attributable approval before a real-data submission.

The current MVP is intentionally narrow. It is not a general remote shell, a
free-form workflow generator, a clinical reporting system, or a data-transfer
service.

## What the MVP provides

- a Python 3.11+ `biopipe` controller with strict version-1 schemas;
- a standard-library-only, read-only Remote Probe for Linux Source Hosts;
- bounded FASTQ/FQ and gzip inspection without exporting sequences, quality
  strings, or complete read names;
- deterministic single/paired-end and multi-lane grouping, sanitized manifests,
  and attributable overrides;
- a reviewed component registry and digest-pinned Nextflow DSL2 generator;
- static validation, Nextflow checks, stub tests, and tiny synthetic E2E tests;
- a standard-library-only Remote Executor with fixed operations, offline
  Docker/Apptainer policy, preflight, HMAC-authenticated approval, status, and
  compatible resume; and
- append-only, structured audit events and machine-readable reports.

## Quick start: run the anonymous release demo

The quickest safe evaluation uses only committed synthetic reads. It does not
need a real SSH server, does not contact a container registry, and must not be
interpreted as biological QC evidence.

Clone the repository, create the test environment from the reviewed,
human-readable specification, and install the controller from the reviewed
checkout:

```bash
git clone https://github.com/LyuWeiBio/easy_pipe.git
cd easy_pipe
micromamba create --strict-channel-priority -f environments/m4-test.yml
micromamba activate easy-pipe-m4
python -m pip install --no-deps --no-build-isolation -e .
```

The YAML pins the intended direct package versions but still asks the solver to
select platform artifacts. The committed
[platform locks and supply-chain inventories](environments/locks/README.md)
bind the corresponding cross-platform solves to exact package URLs, builds,
channels, and hashes. Verify that bundle fully offline before using it as
release evidence:

```bash
python scripts/generate_supply_chain_inventory.py verify
```

These locks record cross-platform metadata solves. Their native-runtime
validation remains `pending`; neither the locks nor a successful offline
integrity check claim that the environments ran on native hosts.

The separate `Release acceptance` workflow creates fresh native environments
from the exact Linux x86_64 and macOS arm64 explicit locks. Linux runs the
forced real local-tool demo plus isolated wheel/sdist and reproducible zipapp
checks; macOS runs the controller-only compatibility set. A successful Linux
job uploads only a create-only, path-free summary and artifact hashes. It does
not upload the retained demo directory and does not claim real SSH, a real
remote host, a container runtime, independent review, or release sign-off.

Verify the installed controller and inspect its frozen public schemas:

```bash
biopipe version --json
biopipe schema list --json
```

The installed catalog contains 21 frozen top-level contracts, including
override diffs, execution run/status/reconciliation reports, and the exact
outer `validation.json` and `test.json` report envelopes consumed by the
approval gate. `schema show` and `schema export` serve committed package bytes;
release tests compare those bytes with current Pydantic generation.

Run the release acceptance demo from the repository root:

```bash
bash scripts/demo_release_acceptance.sh
```

The script exercises the anonymous paired-end, multi-lane path end to end:
source registration and probe verification, inspection, manifest creation, one
sample rename override, planning, generation, validation, synthetic testing,
execution preflight, denial without approval, approved non-sensitive execution,
MultiQC output, and an audit trail. It uses isolated temporary directories and
prints the retained demo artifact directory at completion. See
[`examples/demo/README.md`](examples/demo/README.md) for the exact fixture and
expected outputs. The real local-tool MultiQC run, deterministic approved
execution boundary, and real `bioexec` JSONL contract are complementary offline
checks rather than one remote container execution.

If `micromamba` is unavailable, use `mamba env create` and `mamba activate` with
the same environment file. Creating the environment downloads public packages;
the demo itself is designed to run offline and never pulls a container.

## Production workflow

A production setup has three explicit roles, even when two roles share a host:

```text
Controller Host  ->  Source Host / read-only Remote Probe
       |
       +--------->  Execution Host / fixed Remote Executor + Nextflow
```

Operators first install and constrain the two remote zipapps. `biopipe` does not
install them, create accounts, change `authorized_keys`, or copy raw reads.
Follow the [installation guide](docs/installation.md) and the
[remote deployment guide](docs/remote-deployment.md) before using real data.

The normal artifact flow is:

```bash
biopipe source add hpc01 --host hpc01 --allowed-root /data/raw
biopipe source verify hpc01

biopipe inspect hpc01:/data/raw/run42 \
  --policy format-summary \
  --sample-fastq-records 1000 \
  --output projects/run42/dataset.manifest.json

biopipe manifest show projects/run42/dataset.manifest.json
biopipe manifest apply-overrides \
  projects/run42/dataset.manifest.json \
  --overrides projects/run42/manifest.overrides.yaml \
  --output-dir projects/run42/resolved \
  --name dataset

biopipe plan \
  --manifest projects/run42/resolved/dataset.manifest.resolved.json \
  --goal fastq-qc \
  --project-name run42-fastq-qc \
  --output projects/run42/planned/pipeline.spec.yaml

biopipe generate \
  --spec projects/run42/planned/pipeline.spec.yaml \
  --output projects/run42/generated

biopipe validate projects/run42/generated --json
biopipe test projects/run42/generated --profile test --json
biopipe preflight projects/run42/generated \
  --execution-profile execution-profiles/hpc01-local.json \
  --json
```

Review the generated project, `reports/validation.json`, `reports/test.json`,
`reports/preflight.json`, exact execution profile, software lock, mapped paths,
and output target. A real-data submission is deliberately a separate command:

```bash
biopipe run projects/run42/generated \
  --execution-profile execution-profiles/hpc01-local.json \
  --actor operator_id \
  --approve-real-data \
  --json
```

Use `--dry-run` first on commands that can write, invoke SSH, run an external
tool, sign an authorization, or mutate remote state. Dry-run output describes
the proposed operation and performs none of those effects. Use `--json` for
compact, stable machine-readable output. See the [CLI reference](docs/cli-reference.md)
for every command and its exact modes.

## Safety boundary

- Raw FASTQ reads are referenced in place; the controller receives bounded
  metadata and aggregate format evidence, not raw record content.
- OpenSSH uses the operator's existing configuration, agent, and strict host-key
  checking. The project never stores SSH passwords or private keys.
- The probe and executor expose fixed JSON operations only. Neither accepts a
  shell command, arbitrary argv, environment, plugin, URL, or delete request.
- Full manifests, paths, sample names, MultiQC output, and execution reports may
  still be sensitive and must remain inside the appropriate local boundary.
- Validation and synthetic tests are necessary but do not approve real data.
  Submission binds approval to exact artifact hashes, a fresh preflight, the
  controller key, the actor, and the explicit CLI flag.
- The executor never automatically removes deployments, work directories,
  results, or logs. `--abandon-pending` resolves an uncertain submission; it is
  not a job-cancellation command.

Read [SECURITY.md](SECURITY.md) before deployment and the full
[security and threat model](docs/security-model.md) before granting either
remote account access to data.

## Documentation

- [Installation and uninstall](docs/installation.md)
- [Remote Probe and Remote Executor deployment](docs/remote-deployment.md)
- [Operator-only real-host release acceptance](docs/real-host-acceptance.md)
- [Operations guide](docs/operations.md)
- [Non-sensitive internal pilot runbook](docs/internal-pilot-runbook.md)
- [Privacy-safe internal pilot evidence compiler](docs/internal-pilot-evidence.md)
- [Key-rotation runbook](docs/key-rotation-runbook.md)
- [Backup and retention runbook](docs/backup-retention-runbook.md)
- [Incident-response runbook](docs/incident-response-runbook.md)
- [Capacity and quota runbook](docs/capacity-and-quota-runbook.md)
- [CLI command reference](docs/cli-reference.md)
- [Frozen MVP schema v1](docs/schema-v1.md)
- [DatasetManifest review and overrides](docs/manifest-workflow.md)
- [Planning and generated projects](docs/generated-project.md)
- [Validation and synthetic testing](docs/m4-validation-testing.md)
- [Security and threat model](docs/security-model.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Known limitations](docs/known-limitations.md)
- [Release evidence workflow and trust boundary](docs/release-evidence.md)
- [Release checklist](docs/release-checklist.md)
- [Platform locks and supply-chain inventories](environments/locks/README.md)
- [Probe protocol](docs/probe-protocol.md)
- [Architecture decision record](docs/adr/0001-architecture.md)

## Development checks

From the repository root in the pinned environment:

```bash
ruff format --check .
ruff check .
mypy src remote_probe/src remote_probe/build_zipapp.py \
  remote_executor/src remote_executor/build_zipapp.py
python scripts/generate_supply_chain_inventory.py verify
python -m pytest
```

The complete release gate, reproducible zipapp check, and anonymous acceptance
scenario are listed in the [release checklist](docs/release-checklist.md).

## License and third-party software

The controller, probe, executor, templates, and project documentation are
licensed under the [MIT License](LICENSE). Workflow tools, Python dependencies,
and container contents retain their own licenses; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
