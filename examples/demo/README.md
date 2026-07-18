# Anonymous release-acceptance demo

This directory contains only tiny, deterministic synthetic FASTQ records. The
read names, sequences, qualities, sample name, and lane identifiers were made
for this repository; they do not represent a person, specimen, experiment, or
public biological dataset.

`input/` is a paired-end, two-lane Illumina-style delivery. The reviewed
`overrides.json` renames its synthetic delivery label to
`anonymous_control_001` while preserving the immutable scan manifest.

From the repository root, run the complete offline acceptance check with:

```bash
bash scripts/demo_release_acceptance.sh
```

The script uses an already activated environment when all locked tools are
available. Otherwise it runs the environment named by `BIOPIPE_DEMO_ENV`
(default: `easy-pipe-m4`) through `MAMBA_EXE` or `micromamba`. It never installs
software, accesses the network, or pulls a container image. It prints the
absolute path of a newly created, retained acceptance directory on completion.
Before accepting evidence it verifies the pinned Java, Nextflow, and nf-test
versions; the workflow E2E also checks FastQC, fastp, and MultiQC against the
generated software lock.

The M6 scenario replaces external SSH and the remote container runtime with a
local deterministic harness. The same command also runs the M5 controller-to-
executor contract test, which sends production JSONL requests through the real
`bioexec` service entry point. Together they cover the remote preflight,
signed approval, deployment, submission, status, and audit contracts offline.
