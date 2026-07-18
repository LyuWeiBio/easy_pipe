# M4 validation and synthetic workflow testing

M4 proves that an M3-generated FASTQ-QC project is internally consistent and
can execute on tiny, committed synthetic reads. It never treats a successful
test as approval to run real data. The separate M5 remote preflight and
real-data approval path is documented in the
[remote deployment guide](remote-deployment.md).

## Safety boundary

The validation and test commands:

- accept only the fixed generated-project contract;
- use a single-end or paired-end fixture explicitly marked `synthetic: true`;
- validate every fixture record before starting Nextflow;
- execute a freshly compiled snapshot of the verified project and copy the
  already-validated FASTQ bytes into the isolated runtime before any command;
- create isolated, create-only temporary work and result directories outside
  the generated project and fixture roots;
- set `NXF_OFFLINE=true` and disable Docker, Apptainer, Singularity, Podman,
  Charliecloud, Conda, and Wave for preview, stub, and synthetic E2E commands;
- invoke subprocesses as argument arrays, with a timeout and bounded captured
  output;
- never include command stdout, stderr, sequence, quality, or read identifiers
  in the machine-readable reports; and
- do not overwrite input FASTQs. The E2E tools write only below the temporary
  runtime directory.

The E2E branch deliberately uses the pinned local FastQC, fastp, and MultiQC
executables from the M4 environment. It neither pulls containers nor contacts a
source host; MultiQC is invoked with its remote version check disabled.

## Reproducible mamba environment

The reviewed, human-readable environment input is
[`environments/m4-test.yml`](../environments/m4-test.yml). It pins the intended
direct versions, but creating from it performs a new platform solve. From the
repository root:

```bash
micromamba create --strict-channel-priority -f environments/m4-test.yml
micromamba activate easy-pipe-m4
python -m pip install --no-deps --no-build-isolation -e .
```

With `mamba`, the equivalent creation command is:

```bash
mamba env create --strict-channel-priority -f environments/m4-test.yml
mamba activate easy-pipe-m4
python -m pip install --no-deps --no-build-isolation -e .
```

Do not install these packages into the system Python. Creating the environment
downloads public packages; the validation and synthetic runs themselves are
offline.

The committed
[platform locks and supply-chain inventories](../environments/locks/README.md)
bind the reviewed cross-platform solver transactions to exact package URLs,
builds, channels, MD5 values, SHA-256 values, dependencies, and channel license
metadata. Their integrity and internal agreement can be checked without a
solver or network access:

```bash
python scripts/generate_supply_chain_inventory.py verify
```

The lock metadata deliberately records `resolution_scope` as
`cross_platform_metadata_only` and native-runtime validation as `pending` for
both platforms. A solved and integrity-valid lock is supply-chain evidence, not
proof that the environment executed successfully on a native host.

`.github/workflows/release-acceptance.yml` supplies candidate-specific native
execution evidence without rewriting that historical lock metadata. It creates
Linux x86_64 and macOS arm64 environments directly from the explicit files and
compares each native `micromamba env export --explicit` package set with its
reviewed lock. Linux then runs the real local workflow-tool acceptance; macOS
runs only controller installation, schema, source-profile, manifest,
planner/compiler, and dry-run tests. A passing macOS job is not remote-agent or
container-runtime evidence.

Confirm the selected executables before accepting E2E evidence:

```bash
python --version
java -version
nextflow -version
nf-test version
fastqc --version
fastp --version
multiqc --version
command -v ps
```

The environment pins the following public workflow tools:

| Tool | Version | Channel | Purpose |
|---|---:|---|---|
| OpenJDK | 23.0.2 | conda-forge | Nextflow and nf-test runtime |
| Nextflow | 26.04.6 | bioconda | config, lint, preview, stub, and E2E |
| nf-test | 0.9.5 | bioconda | generated test-suite layer |
| FastQC | 0.12.1 | bioconda | raw and post-trim read QC |
| fastp | 1.3.6 | bioconda | controlled optional trimming |
| MultiQC | 1.35 | bioconda | aggregate QC report |

The complete YAML also pins Python and every direct runtime/test dependency.
On 2026-07-18, strict-priority `micromamba create --dry-run` solved the same
YAML for both `osx-arm64` and `linux-64`. The principal selected builds were:

| Package | `osx-arm64` build | `linux-64` build |
|---|---|---|
| Python 3.12.11 | `hc22306f_0_cpython` | `h9e4cc4f_0_cpython` |
| OpenJDK 23.0.2 | `hfb9339a_2` | `h53dfc1b_2` |
| fastp 1.3.6 | `ha1d0559_0` | `h43da1c4_0` |
| FastQC 0.12.1 | `hdfd78af_0` | `hdfd78af_0` |
| Nextflow 26.04.6 | `h2a3209d_0` | `h2a3209d_0` |
| nf-test 0.9.5 | `h2a3209d_0` | `h2a3209d_0` |
| MultiQC 1.35 | `pyhdfd78af_1` | `pyhdfd78af_1` |

The Linux solve requires glibc 2.17 or newer. nf-test tracing also requires a
working `ps` command (normally supplied by the host's procps installation;
macOS supplies `/bin/ps`). Builds are intentionally not embedded in the
cross-platform YAML; exact versions are pinned and the solver selects the
reviewed platform build. The explicit lock and matching inventory are the
authoritative records of that selected artifact set; the table above remains a
human-readable summary rather than a substitute for their hashes.

## Repository checks

Run the Python and static checks before using workflow-level evidence:

```bash
python -m pytest
ruff check .
mypy
```

These checks do not substitute for `biopipe validate` or the synthetic E2E
profile; they cover the controller, strict schemas, fixture loader, output
assertions, and failure mapping.

## Validate a generated project

The normal command is repeatable:

```bash
biopipe validate projects/run42/generated
```

For stable machine consumption:

```bash
biopipe validate projects/run42/generated --json
```

Static validation checks, among other things:

- manifest integrity and full, executable artifact scope;
- strict parsing and cross-artifact consistency of the manifest, spec,
  execution plan, and software lock;
- the reviewed registry graph and exact software lock;
- non-overlapping raw-data, work, output, and container-cache paths;
- the default-deny policy and approval/preflight contract;
- the expected generated file set and byte-for-byte template regeneration;
- samplesheet mapping, immutable digest-only process containers, and absence of
  floating `latest` versions; and
- the deterministic generation audit event and artifact hashes.

Only after static validation passes does the runtime validation layer invoke
Nextflow. It resolves config as JSON, runs Nextflow lint, previews the fixed
graph with containers disabled, and then runs the generated nf-test suite when
it is available.

The command atomically writes `PROJECT/reports/validation.json`. Re-running the
command may replace only that allowlisted report; it does not replace generated
source artifacts.

## Single-end and paired-end synthetic tests

Generated projects carry a layout-matched fixture below
`PROJECT/tests/fixtures/<layout>`. The normal profile chooses it automatically:

```bash
biopipe test projects/single-end/generated --profile test
biopipe test projects/paired-end/generated --profile test
```

The repository fixtures can be supplied explicitly when validating a generated
project during development:

```bash
biopipe validate projects/single-end/generated \
  --fixture-root tests/fixtures/m4/single_end \
  --json

biopipe test projects/single-end/generated \
  --profile test \
  --fixture-root tests/fixtures/m4/single_end \
  --json

biopipe validate projects/paired-end/generated \
  --fixture-root tests/fixtures/m4/paired_end \
  --json

biopipe test projects/paired-end/generated \
  --profile test \
  --fixture-root tests/fixtures/m4/paired_end \
  --json
```

An override fixture must match the generated project's layout. Fixture loading
fails before Nextflow if any of these invariants is violated:

- the fixture document is not strict version `1.0` with `synthetic: true`;
- paths are absolute, traverse upward, escape the fixture root, or are symlinks;
- identifiers do not use the reserved `synthetic_se_...`, `synthetic_pe_...`,
  and `@SYNTHETIC_...` forms;
- a FASTQ is not a small regular ASCII file with four-line records, `ACGTN`
  sequence text, printable qualities, and matching sequence/quality lengths;
- paired reads do not have matching normalized headers and `/1`/`/2` markers;
  or
- a file exceeds 64 KiB, the fixture exceeds 256 KiB, or a file contains more
  than 16 records.

The `test` profile first repeats the project/config/syntax gates, then performs:

1. a Nextflow `-stub-run` of the selected single-end or paired-end graph; and
2. a local E2E run with the pinned FastQC, optional fastp, post-trim FastQC, and
   MultiQC tools.

Both runs use fresh temporary directories. No test work directory is reused,
and no `-resume` path is accepted by this profile.

## Output assertions

A zero Nextflow return code is necessary but not sufficient. M4 also requires:

- exactly one raw FastQC ZIP and HTML per expected read and sample/lane/chunk;
- when trimming is enabled, exactly one fastp JSON and HTML plus the expected
  single or paired trimmed gzip FASTQs;
- exactly one post-trim FastQC ZIP and HTML per expected read;
- a MultiQC HTML report and a non-empty `multiqc_data` directory;
- non-empty timeline, execution report, trace, and DAG artifacts; and
- a parseable trace in which all required processes appear and every task is
  `COMPLETED` or `CACHED`.

For E2E, FastQC ZIP files must be valid archives, HTML outputs must have an HTML
signature, fastp JSON must parse to an object, trimmed FASTQs must be readable
non-empty gzip streams, and the trace must parse as tab-separated data. The stub
layer checks the same path cardinality and non-empty structure without claiming
that stub payloads are biological QC evidence.

## Degraded and failure semantics

Every report has one terminal status:

| Status | Meaning | CLI exit |
|---|---|---:|
| `passed` | Every required layer passed | `0` |
| `failed` | A project, command, nf-test, or output assertion failed | non-zero (`2`) |
| `blocked` | A prerequisite such as Nextflow or a safe runtime directory is unavailable | non-zero (`2`) |
| `degraded` | Nextflow checks ran, but nf-test or its generated suite was unavailable | non-zero (`2`) |

Degraded is explicit evidence, not success. `NF_TEST_NOT_FOUND` and
`NF_TEST_SUITE_NOT_FOUND` preserve the completed Nextflow checks and add a
remediation. During the full test profile, a degraded stub layer may still be
followed by E2E so the report retains the maximum safe evidence, but the
aggregate result remains degraded and non-zero. Missing FastQC, fastp, or
MultiQC blocks E2E rather than degrading it, while a present tool whose version
differs from the software lock fails validation.

Static failure prevents all external commands. Timeout and captured-output
limits produce stable `COMMAND_TIMEOUT` and `COMMAND_OUTPUT_LIMIT` failures;
stdout and stderr are retained only in bounded memory for the command decision
and are then discarded. Nextflow log files stay in the temporary runtime; none
of this raw diagnostic output is copied into reports.

## Machine-readable report overview

`reports/validation.json` contains:

- `report_version`, `command`, `status`, `code`, `project_directory`, and
  `report_path`;
- the literal `synthetic_data_only: true` safety claim;
- `static_validation`, including checked artifact names, SHA-256 hashes,
  output target, and structured findings;
- `runtime_validation`, including mode, layout, trimming state, checks, and
  asserted output paths; and
- deduplicated remediation messages.

`reports/test.json` contains the same identity and static-validation fields plus
`profile: "test"` and a `runs` mapping for the synthetic workflow layers. Each
run records:

- `mode`, terminal `status`, and stable `code`;
- `layout`, `trimming_enabled`, and `synthetic_data_only: true`;
- ordered checks with status, code, bounded return code, message, and
  remediation; and
- sorted unique relative paths for critical asserted outputs.

Reports contain no FASTQ content or raw subprocess output. Report JSON is
serialized with stable key ordering and written through a temporary file plus
atomic replace. If the project root or `reports/` path is unsafe, report writing
fails instead of following a symlink.

## Interpreting the result

FastQC, fastp, and MultiQC outputs from these tiny fixtures prove wiring,
cardinality, parsing, and tool compatibility only. They must not be used to set
real trimming policy or infer biological quality. Real-data QC interpretation
still requires reviewed FastQC/MultiQC results and the implemented, separate
M5 explicit approval gate.
