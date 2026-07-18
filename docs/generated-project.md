# FASTQ-QC planning and generation

M3 turns one integrity-verified full `DatasetManifest` into a deterministic,
reviewable Nextflow DSL2 project. It does not execute Nextflow, pull containers,
contact a source host, or approve real-data use.

## Create planning artifacts

Only the fixed `fastq-qc` goal is accepted:

```bash
biopipe plan \
  --manifest projects/run42/dataset.manifest.resolved.json \
  --goal fastq-qc \
  --project-name run42-fastq-qc \
  --output projects/run42/pipeline.spec.yaml
```

The manifest must have a valid embedded digest, contain at least one resolved
single-end or paired-end sample, have no blocking errors, and declare
`privacy.artifact_scope: full`. A sanitized manifest is a review artifact and
cannot be used to build an executable project.

Planning creates one all-or-nothing, create-only bundle beside `--output`:

- the requested PipelineSpec YAML;
- `execution.plan.yaml`;
- `software.lock.yaml`;
- `dataset.manifest.resolved.json`, unless that exact file was the input.

No existing member is replaced. Optional trimming uses one controlled integer,
not a free-form command fragment:

```bash
biopipe plan \
  --manifest projects/run42/dataset.manifest.resolved.json \
  --output projects/run42/pipeline.spec.yaml \
  --trimming \
  --minimum-length 30
```

Use `--work-dir`, `--results-dir`, and `--container-cache` to set reviewed
absolute POSIX execution paths. If omitted, `biopipe` derives three separate
sibling paths outside the raw-data root. Review those paths before generation;
raw-data, work, results, and cache trees are not allowed to overlap.

## Generate the Nextflow project

```bash
biopipe generate \
  --spec projects/run42/pipeline.spec.yaml \
  --output projects/run42/generated
```

By default, `generate` loads the fixed sibling manifest, execution plan, and
software lock. Explicit alternatives can be supplied with `--manifest`,
`--execution-plan`, and `--software-lock`; all are revalidated together. The
output path must not exist.

The generated project contains:

- `main.nf`, `nextflow.config`, and local/Slurm configuration;
- fixed FastQC, optional fastp, post-trim FastQC, and MultiQC modules;
- `assets/samplesheet.csv` with execution-host paths;
- the resolved manifest, spec, execution plan, and software lock;
- a generated-project README and deterministic audit event.

Container tags and versions remain in `software.lock.yaml` for provenance, but
Nextflow process configuration uses immutable `repository@sha256:...`
references. The Slurm profile is deliberately a site-specific placeholder.

The generated samplesheet references FASTQ files in place. Original filenames
are never inserted into task scripts: processes stage reads under fixed aliases.
Sample, lane, chunk, paths, parameters, graph nodes, template identities,
resources, registry contents, and locks are all schema-checked. The full
manifest can contain identifying filenames and must remain in the appropriate
local review boundary.

## Execution boundary

M3 generation is not permission to run real data. The spec and execution plan
remain default-deny, and the README records that task network policy still has
to be enforced by validation/preflight before a real-data run. M4 adds static,
stub, and synthetic-data validation; M5 adds execution-host preflight and the
explicit approval gate.
