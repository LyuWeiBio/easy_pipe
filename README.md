# easy_pipe

`easy_pipe` is a local-first foundation for building auditable bioinformatics
pipelines. The long-term MVP will inspect the structure of remote FASTQ data
without moving reads to the controller, produce reviewed file-based artifacts,
and deterministically generate a constrained Nextflow DSL2 quality-control
workflow.

> **Project status: M2 FASTQ detection and DatasetManifest.** The repository
> provides a manually deployed, read-only Remote Probe, constrained OpenSSH
> controller, privacy-safe FASTQ summaries, deterministic pairing, and
> auditable full/sanitized/resolved manifests. Nextflow generation and
> real-data execution remain future milestones.

## Current scope

The completed M0-M2 foundation and inspection boundary provide:

- a Python 3.11+ package and Typer CLI skeleton;
- versioned, strict Pydantic data contracts;
- stable structured errors and JSON/YAML serialization helpers;
- SHA-256 artifact hashing and append-only JSONL audit records;
- a local, atomic SourceProfile registry that stores no SSH credentials;
- fixed `health`, `list_tree`, `stat_files`, `detect_formats`, and
  `summarize_fastq` JSONL operations;
- canonical allowlists, descriptor-based symlink rejection, and
  request/response/mount/depth/entry/runtime budgets;
- a fixed OpenSSH invocation using argument arrays, strict host-key checking,
  JSONL standard input, timeouts, bounded diagnostics, and redaction;
- a byte-reproducible, standard-library-only `bioprobe.pyz` build;
- bounded gzip/plain FASTQ validation and aggregate read-length, quality
  encoding, header-family, and mate-marker summaries;
- explainable generic/Illumina detection, four naming conventions,
  single/paired-end classification, and multi-lane grouping;
- SHA-256 finalized full and sanitized manifests, create-only artifacts,
  explicit traceable overrides, and deterministic candidate samplesheets;
- security, integration, lint, formatting, and type-checking checks.

The following capabilities are intentionally deferred:

- automatic remote probe deployment;
- pipeline planning, component resolution, and Nextflow generation;
- preflight checks, schedulers, containers, or real-data execution;
- arbitrary shell or Python execution of any kind.

## Install for development

Clone the repository and create an isolated environment:

```bash
git clone https://github.com/LyuWeiBio/easy_pipe.git
cd easy_pipe
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
```

The package requires Python 3.11 or newer.

## CLI

Show the top-level help:

```bash
biopipe --help
biopipe --version
# Equivalent when running from a checkout:
python -m biopipe --help
```

M2 implements source management, metadata/FASTQ inspection, and manifest
review. M3 adds deterministic planning and Nextflow project generation; later
validation and execution commands remain explicit placeholders:

```bash
biopipe source --help
biopipe inspect --help
biopipe manifest --help
biopipe plan --help
biopipe generate --help
biopipe validate --help
biopipe test --help
biopipe preflight --help
biopipe run --help
```

Create the fixed FASTQ-QC planning bundle and a new generated project:

```bash
biopipe plan \
  --manifest projects/run42/dataset.manifest.resolved.json \
  --goal fastq-qc \
  --output projects/run42/pipeline.spec.yaml

biopipe generate \
  --spec projects/run42/pipeline.spec.yaml \
  --output projects/run42/generated
```

These commands never run Nextflow or replace existing artifacts. See the
[M3 planning and generation guide](docs/generated-project.md) for trimming,
execution paths, immutable containers, and the real-data approval boundary.

The command hierarchy is:

```text
source add | list | show | remove | verify
inspect
manifest show | apply-overrides
plan
generate
validate
test
preflight
run
```

`source add/list/show/remove/verify`, `inspect`, `manifest show`, and
`manifest apply-overrides` are implemented. The remaining workflow surfaces
reserve later milestones and must not be interpreted as execution support.

Register an existing SSH alias and inspect one approved directory:

```bash
biopipe source add hpc01 --host hpc01 --allowed-root /data/raw
biopipe source verify hpc01
biopipe inspect hpc01:/data/raw/run42 --policy metadata-only --json
biopipe inspect hpc01:/data/raw/run42 --policy format-summary \
  --sample-fastq-records 1000 --output dataset.manifest.json
biopipe manifest show dataset.manifest.json
biopipe manifest apply-overrides dataset.manifest.json --overrides overrides.yaml \
  --output-dir resolved --name run42
```

The Remote Probe must first be built, reviewed, configured, and installed by
the operator. `biopipe` never writes to the Source Host. See the
[operations guide](docs/operations.md),
[manifest workflow](docs/manifest-workflow.md), and
[protocol reference](docs/probe-protocol.md).

## Development checks

Run the checks from the repository root:

```bash
python -m pytest
ruff check .
ruff format --check .
mypy src remote_probe/src remote_probe/build_zipapp.py
```

Apply the configured formatter with `ruff format .`.

## Security and privacy boundary

The design treats the controller, source host, and execution host as distinct
roles, even if a deployment later places more than one role on the same
machine.

- Raw reads, sequence, quality strings, complete read identifiers, and
  credentials do not enter controller artifacts or logs. M2 returns only
  bounded aggregate FASTQ facts.
- SSH will use an existing OpenSSH configuration, agent, and strict host-key
  verification. The project must not store passwords or private keys.
- The Remote Probe exposes only fixed read-only operations over a bounded JSONL
  protocol. There is no general-purpose shell, `eval`, plugin loader, or
  arbitrary Python interface.
- OpenSSH uses an argument array, timeout, and checked return code. User data
  paths travel only in JSON standard input and never enter the SSH arguments.
- Real-data execution will require validation, preflight checks, and an
  explicit approval gate. M2 contains no workflow execution path.
- Audit records are append-only and exclude secrets and raw biological data.

See [ADR 0001](docs/adr/0001-architecture.md) for the architectural rationale
and the boundaries reserved for later milestones.

## Planned MVP flow

```text
remote data directory
  -> constrained read-only probe
  -> DatasetManifest
  -> reviewed PipelineSpec
  -> approved component registry
  -> deterministic Nextflow project
  -> validation and tests
  -> explicit approval
  -> execution near the data
```

M2 ends at a reviewed DatasetManifest and candidate samplesheet; pipeline
generation and execution remain scheduled for M3-M6.

## License

This project is licensed under the [MIT License](LICENSE).
