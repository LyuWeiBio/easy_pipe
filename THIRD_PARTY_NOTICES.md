# Third-party notices

Last reviewed: 2026-07-18.

`easy_pipe` source code is licensed under the repository's MIT License. It uses
and orchestrates third-party software that remains subject to its own copyright
and license terms. This file is an inventory aid, not legal advice and not a
replacement for the complete license text distributed by each dependency.

## Controller runtime dependencies

The direct Python dependencies declared in `pyproject.toml` are not vendored
into this repository or the remote zipapps.

| Package | Declared range | Upstream license | Purpose |
|---|---:|---|---|
| [Jinja2](https://github.com/pallets/jinja/) | `>=3.1,<4` | BSD-3-Clause | Deterministic project templates |
| [Pydantic](https://github.com/pydantic/pydantic) | `>=2.8,<3` | MIT | Strict data models and validation |
| [PyYAML](https://github.com/yaml/pyyaml) | `>=6,<7` | MIT | Versioned YAML artifacts |
| [Rich](https://github.com/Textualize/rich) | `>=13,<15` | MIT | CLI presentation dependency |
| [Typer](https://github.com/fastapi/typer) | `>=0.12,<1` | MIT | CLI command tree |

Each installer resolves additional transitive packages. The human-readable
`environments/m4-test.yml` pins the intended direct versions, while
`environments/locks/direct-dependencies.json`, the platform explicit locks,
and the platform inventories record the exact cross-platform solver results,
including package URLs, builds, channels, and hashes. The inventory license
fields are channel metadata, not an independent legal review or permission to
redistribute. Native-runtime validation of both platform locks remains
`pending`. Before redistributing an installed environment, compare its actual
inventory with the matching lock and retain the license metadata and notices
supplied by the package source.

The source build uses [Setuptools](https://github.com/pypa/setuptools)
`>=77` (MIT). The optional `dev` extra directly declares
[build](https://github.com/pypa/build) (MIT),
[pytest](https://github.com/pytest-dev/pytest) (MIT),
[pytest-cov](https://github.com/pytest-dev/pytest-cov) (MIT),
[mypy](https://github.com/python/mypy) (MIT),
[Ruff](https://github.com/astral-sh/ruff) (MIT), and
[types-PyYAML](https://github.com/python/typeshed) (Apache-2.0). These are
development/release tools and are not required by either remote zipapp.

## Workflow components

The reviewed registry records these tools and immutable container identities.
They are invoked as separate programs; their source is not incorporated into
the `easy_pipe` Python package.

| Tool | Locked version | SPDX license in the registry | Upstream license |
|---|---:|---|---|
| [FastQC](https://github.com/s-andrews/FastQC) | 0.12.1 | GPL-3.0-or-later | [License](https://github.com/s-andrews/FastQC/blob/master/LICENSE) |
| [fastp](https://github.com/OpenGene/fastp) | 1.3.6 | MIT | [License](https://github.com/OpenGene/fastp/blob/master/LICENSE) |
| [MultiQC](https://github.com/MultiQC/MultiQC) | 1.35 | GPL-3.0-or-later | [License](https://github.com/MultiQC/MultiQC/blob/main/LICENSE) |

The registry references BioContainers images for these tools by OCI digest.
Container images include their own operating-system and language dependencies;
the table above is not a complete bill of materials for an image. Operators who
mirror or redistribute an image must inspect that exact digest, preserve its
notices/source offers, and satisfy every included license.

`environments/locks/containers.json` inventories the registry identities and
their declared component licenses, but exact-image digest verification and
container-content license review remain `pending`; its release-readiness state
is deliberately `blocked`. It must not be cited as an approval record.

## Workflow validation toolchain

The pinned synthetic-test environment also installs these independent tools:

| Tool | Pinned version | Upstream license | Use |
|---|---:|---|---|
| [OpenJDK](https://openjdk.org/) | 23.0.2 | GPL-2.0-only with Classpath Exception | Java runtime |
| [Nextflow](https://github.com/nextflow-io/nextflow) | 26.04.6 | Apache-2.0 | Workflow engine |
| [nf-test](https://github.com/askimed/nf-test) | 0.9.5 | MIT | Generated workflow tests |

The mamba/conda packages may carry build-time patches and dependencies. Retain
the metadata and notices supplied by the selected channels when redistributing
that environment.

## Optional host software

Real-data execution requires an operator-provided Docker or Apptainer runtime,
OpenSSH, Python, Java, and a pinned Nextflow JAR. These system components are
not bundled or redistributed by this repository. Their versions, licenses,
daemon terms, and distribution obligations belong to the deployment and must
be reviewed separately.

## Remote zipapps and generated output

`bioprobe.pyz` and `bioexec.pyz` contain only `easy_pipe` project modules and
use the remote Python standard library; they do not bundle the controller's
third-party Python dependencies or a Python interpreter.

Generated Nextflow source and generated-project documentation come from this
repository's MIT-licensed templates. Executing that project requires the
separate tools above. Workflow reports and scientific data remain the
operator's content; a tool's output may include its own notices or attribution.

## Release verification

Before a release or internal redistribution:

1. compare `pyproject.toml`, `environments/m4-test.yml`,
   `environments/locks/direct-dependencies.json`, the packaged registry, and
   this inventory;
2. run `python scripts/generate_supply_chain_inventory.py verify` and review
   `environments/locks/SHA256SUMS`, both explicit locks, and both complete
   package inventories;
3. export the exact installed package list and license metadata and compare it
   with the matching platform inventory;
4. inspect every distributed container digest and remote artifact rather than
   treating a `pending` or `blocked` inventory record as approval;
5. retain upstream copyright/license texts and source offers where required;
   and
6. record reviewer, date, scope, and exceptions in the release checklist.
