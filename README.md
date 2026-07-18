# easy_pipe

`easy_pipe` is a local-first foundation for building auditable bioinformatics
pipelines. The long-term MVP will inspect the structure of remote FASTQ data
without moving reads to the controller, produce reviewed file-based artifacts,
and deterministically generate a constrained Nextflow DSL2 quality-control
workflow.

> **Project status: M0 engineering skeleton.** The repository currently
> provides foundational contracts and CLI placeholders. It does **not** connect
> to remote hosts, inspect FASTQ data, generate Nextflow projects, or run real
> data.

## Current scope

M0 establishes the interfaces that later milestones will build on:

- a Python 3.11+ package and Typer CLI skeleton;
- versioned, strict Pydantic data contracts;
- stable structured errors and JSON/YAML serialization helpers;
- SHA-256 artifact hashing and append-only JSONL audit records;
- test, lint, formatting, and type-checking configuration;
- an architecture decision record describing security and trust boundaries.

The following capabilities are intentionally deferred:

- SSH connections and remote probe deployment;
- directory scanning, FASTQ parsing, sample/lane inference, and pairing;
- manifest review and override workflows;
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

M0 exposes placeholders for the planned workflow surface. Use `--help` to
inspect a command without performing work:

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

The placeholder hierarchy is:

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

These names reserve the intended stages: source configuration, metadata-only
inspection, manifest review, planning, deterministic generation, validation,
testing, execution-host checks, and gated execution.

A placeholder confirms the intended interface only; it must not be interpreted
as support for remote access or real-data execution.

## Development checks

Run the checks from the repository root:

```bash
python -m pytest
ruff check .
ruff format --check .
mypy src
```

Apply the configured formatter with `ruff format .`.

## Security and privacy boundary

The design treats the controller, source host, and execution host as distinct
roles, even if a deployment later places more than one role on the same
machine.

- Raw reads, sequence, quality strings, complete read identifiers, and
  credentials must not enter controller artifacts or logs.
- SSH will use an existing OpenSSH configuration, agent, and strict host-key
  verification. The project must not store passwords or private keys.
- A future remote probe will expose fixed read-only operations over a bounded
  JSONL protocol. There is no general-purpose shell, `eval`, plugin loader, or
  arbitrary Python interface.
- Future subprocesses must use argument arrays, timeouts, and checked return
  codes; user input must never be interpolated into shell command strings.
- Real-data execution will require validation, preflight checks, and an
  explicit approval gate. M0 contains no execution path.
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

Only the foundational contracts around this flow are in scope for M0.

## License

This project is licensed under the [MIT License](LICENSE).
