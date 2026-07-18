# Installation and uninstall

This guide installs the controller from a reviewed repository checkout. The
project does not currently publish a PyPI package or an automatic remote
installer. Remote Probe and Remote Executor deployment is a separate,
operator-controlled step.

## Supported hosts

| Role | Supported MVP environment | Required runtime |
|---|---|---|
| Controller | macOS or Linux | Python 3.11+, OpenSSH client |
| Source Host | Linux/POSIX | Python 3.11+, OpenSSH server |
| Execution Host | Linux/POSIX | Python 3.9+, Java, pinned Nextflow JAR, Docker or Apptainer |

The complete validation and synthetic E2E environment is tested on macOS and
Linux through `environments/m4-test.yml`. The Linux solve requires glibc 2.17
or newer. Windows is not an MVP target.

## Controller-only installation

Use this when you need the CLI, schema tools, planning, and generation but do
not need local workflow validation immediately:

```bash
git clone https://github.com/LyuWeiBio/easy_pipe.git
cd easy_pipe
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
biopipe version --json
```

`python -m pip install .` creates a normal installation from the selected
checkout. Developers who intentionally want source edits to be reflected in
the environment can use `python -m pip install -e '.[dev]'` instead.

Installing the controller does not install Nextflow, FastQC, fastp, MultiQC,
the remote zipapps, a container runtime, or any container image.

## Complete validation and demo environment

The reviewed environment pins the Python package set and the local synthetic
workflow tools:

```bash
git clone https://github.com/LyuWeiBio/easy_pipe.git
cd easy_pipe
micromamba create --strict-channel-priority -f environments/m4-test.yml
micromamba activate easy-pipe-m4
python -m pip install --no-deps --no-build-isolation -e .
```

With `mamba`:

```bash
mamba env create --strict-channel-priority -f environments/m4-test.yml
mamba activate easy-pipe-m4
python -m pip install --no-deps --no-build-isolation -e .
```

Environment creation downloads public packages. Normal validation and the
anonymous release demo then use the pinned local tools with Nextflow offline
mode and do not pull containers.

Verify the selected toolchain:

```bash
python --version
java -version
nextflow -version
nf-test version
fastqc --version
fastp --version
multiqc --version
biopipe version --json
```

See [M4 validation and synthetic testing](m4-validation-testing.md) for the
exact reviewed versions and degraded-mode behavior.

## Build the remote zipapps

Build both artifacts from the exact checkout that matches the controller:

```bash
SOURCE_DATE_EPOCH=315532800 \
  python remote_probe/build_zipapp.py --output remote_probe/dist/bioprobe.pyz
SOURCE_DATE_EPOCH=315532800 \
  python remote_executor/build_zipapp.py --output remote_executor/dist/bioexec.pyz
```

Record the checksums before transferring the files:

```bash
shasum -a 256 remote_probe/dist/bioprobe.pyz
shasum -a 256 remote_executor/dist/bioexec.pyz
```

On Linux, `sha256sum` is equivalent. Repeat the builds with the same source and
`SOURCE_DATE_EPOCH` and require byte-identical output before a release. The
zipapps contain only project modules and rely on the remote Python standard
library, plus the repository MIT `LICENSE`; they do not bundle Python itself or
third-party Python packages.

Continue with [remote deployment](remote-deployment.md). Copying a zipapp to a
server without configuring allowlists, permissions, and a fixed SSH command is
not a complete installation.

## Upgrade

Treat an upgrade as a new reviewed deployment:

1. check `biopipe version --json` and export the public schemas;
2. read the release notes and compare schema, registry, compiler, probe, and
   executor versions;
3. build and checksum new zipapps;
4. install them to new temporary names and perform health checks;
5. atomically select the reviewed artifacts according to local operations
   policy; and
6. rerun source verification, validation, synthetic tests, and preflight.

Do not reuse an old execution preflight or approval after any core artifact,
profile, remote agent, container, executable, or pinned Nextflow JAR changes.
There is no automatic schema migration in the MVP.

## Uninstall the controller

From the environment where it was installed:

```bash
python -m pip uninstall easy-pipe
```

For the pinned mamba environment, inspect it before removal:

```bash
micromamba env list
micromamba remove -n easy-pipe-m4 --all
```

Removing the package or environment does not remove controller state. The
default SourceProfile directory is `~/.config/biopipe/sources`; generated
projects, execution profiles, reports, and audit trails are wherever the
operator created them. Review and archive those files according to the local
retention policy before any manual deletion. Full manifests and reports can
contain sensitive sample names and paths.

## Uninstall remote components

`biopipe` never uninstalls remote software. An operator must first confirm the
exact account, host, paths, retention requirements, and whether a run is still
active. Then:

1. disable or remove the corresponding constrained SSH key;
2. revoke the execution HMAC key and remove its controller copy;
3. archive required audit, result, and configuration evidence;
4. remove only the reviewed `bioprobe.pyz` or `bioexec.pyz` and configuration;
5. separately decide whether deployments, work, results, cache, and private
   state may be retained or removed.

The executor deliberately has no remote delete operation. Uninstalling it does
not remove raw data and must not be used as a shortcut for job cancellation or
data-retention decisions.
