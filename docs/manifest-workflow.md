# DatasetManifest workflow

M2 turns bounded Remote Probe facts into local, versioned artifacts. Raw FASTQ
records never cross the probe boundary, and none of these commands starts an
analysis workflow.

## Inspect and review

```bash
biopipe inspect hpc01:/data/raw/run42 \
  --policy format-summary \
  --sample-fastq-records 1000 \
  --output projects/run42/dataset.manifest.json

biopipe manifest show projects/run42/dataset.manifest.json
```

When `--output` is provided, inspection creates one create-only bundle:

- `dataset.manifest.json`: full local manifest, including original names and
  remote paths;
- `dataset.manifest.sanitized.json`: stable anonymous sample/path projection;
- `dataset.manifest.samplesheet.csv`: candidate samplesheet, omitted whenever
  the manifest has a blocking error.

Every manifest carries `manifest_version: "1.0"` and a SHA-256 over its
canonical content. A digest mismatch blocks show, sanitization, samplesheet
generation, and override application. Re-running against existing artifact
names fails without replacing or partially extending the bundle.

The full manifest may contain sensitive filenames and stays local. The
sanitized manifest replaces source identity, paths, sample names, lane/chunk
labels, free text, and unknown codes/rules. It retains only reviewed aggregate
classification fields and declares `raw_content_exported: false`.

## Resolve an explicit ambiguity

Overrides are separate, attributable approval inputs. JSON and YAML readers
reject duplicate keys. Paths must be normalized absolute paths below the scan
root and must already occur in the original manifest or its unresolved scan
facts; an override cannot invent an uninspected FASTQ.

```yaml
override_version: "1.0"
rename_samples:
  old_delivery_name: control_01
exclude_files:
  - /data/raw/run42/bad_R1.fastq.gz
  - /data/raw/run42/bad_R2.fastq.gz
manual_pairs:
  - sample_id: reviewed_pair
    lane: L001
    read1: /data/raw/run42/reviewed_R1.fastq.gz
    read2: /data/raw/run42/reviewed_R2.fastq.gz
reason: Delivery sheet and filenames were reviewed together.
approved_by: operator_id
```

Paired-lane exclusions must remove both mates. Manual pairing can reassign a
scanned orphan or a complete existing pair, but cannot reuse one path twice,
mix excluded paths, or take only one mate from an existing pair. Unaddressed
pairing errors remain blocking.

```bash
biopipe manifest apply-overrides \
  projects/run42/dataset.manifest.json \
  --overrides projects/run42/manifest.overrides.yaml \
  --output-dir projects/run42/resolved \
  --name dataset
```

The command never modifies the original manifest or override file. It creates
one all-or-nothing, create-only bundle:

- `dataset.manifest.resolved.json`;
- `dataset.manifest.resolved.sanitized.json`;
- `dataset.override.applied.json`;
- `dataset.override.diff.json` linking the original, override, and resolved
  SHA-256 values;
- `dataset.samplesheet.csv`, only if the resolved manifest has no blocking
  errors.

M3 may consume only a valid, resolved manifest without blocking errors.
