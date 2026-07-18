# MVP release checklist

Use one copy of this checklist per candidate. Record the release identifier,
commit, reviewer, date, host platforms, and links to retained CI/demo evidence.
A checked box means the stated evidence was reviewed, not merely that a command
was started.

Use the create-only [release evidence workflow](release-evidence.md) to bind
generated candidate facts and artifact hashes to the exact source commit. Its
instantiated `release-checklist.completed.md` remains `DRAFT_UNREVIEWED` and
`BLOCKED` with every box unchecked until an operator supplies the required
external evidence and an independent reviewer actually reviews it. A successful
offline checksum verification proves byte integrity, not release sign-off.

## Candidate identity

- [ ] Release identifier: `________________`
- [ ] Exact Git commit: `________________`
- [ ] Reviewer and date: `________________`
- [ ] The worktree is clean and the candidate commit is signed/reviewed under
      the project's Git policy.
- [ ] `biopipe version --json` reports the intended controller, probe, remote
      executor, registry, compiler, schema, and CLI-contract versions.
- [ ] `pyproject.toml`, `src/biopipe/version.py`, the probe/executor versions,
      registry version, generated metadata, and release notes agree.

## Frozen public contracts

- [ ] `biopipe schema list --json` succeeds and every catalog digest is stable.
- [ ] A fresh export succeeds without replacing an existing export:

  ```bash
  biopipe schema export --output release-evidence/schema-v1 --dry-run --json
  biopipe schema export --output release-evidence/schema-v1 --json
  ```

- [ ] All 21 exported contracts and `catalog.json` match both the installed
      package resources and complete committed v1 fixtures byte-for-byte, and
      contain no absolute checkout paths or timestamps.
- [ ] All public artifacts and reports still use schema/report/protocol version
      `1.0`; any intentional incompatible change has a new version rather than
      silently broadening v1.
- [ ] CLI help, `--json`, dry-run envelopes, success exit `0`, and failure exit
      `2` match [the CLI reference](cli-reference.md).

## Source and dependency review

- [ ] The release diff contains only intended changes and no generated caches,
      local profiles, private state, real reports, real data, or secrets.
- [ ] `LICENSE` still covers repository-owned source and documentation.
- [ ] `THIRD_PARTY_NOTICES.md` matches `pyproject.toml`,
      `environments/m4-test.yml`, and both packaged copies of the component
      registry.
- [ ] The exact installed environment and its transitive license metadata were
      inventoried for any redistributed environment.
- [ ] Every shipped/mirrored container digest was inventoried separately and
      its notices/source obligations were reviewed.
- [ ] No dependency, container, action, or remote runtime change lacks a
      provenance and security review.

## Static quality and regression suite

Run from the repository root in the pinned `easy-pipe-m4` environment:

```bash
ruff format --check .
ruff check .
mypy src remote_probe/src remote_probe/build_zipapp.py \
  remote_executor/src remote_executor/build_zipapp.py
python -m pytest
```

- [ ] Ruff formatting passes without modifying the candidate.
- [ ] Ruff lint passes without modifying the candidate.
- [ ] Strict mypy passes for controller, probe, executor, and builders.
- [ ] The complete pytest suite passes, including unit, integration, golden,
      security, controller/executor contract, Python 3.9 executor, and M6
      release-acceptance coverage.
- [ ] Coverage results were reviewed for changed safety-critical paths.
- [ ] GitHub Actions passes on every configured Python/platform job from the
      exact candidate commit.

## Reproducible remote artifacts

Build each zipapp twice from the same candidate and compare bytes:

```bash
release_tmp="$(mktemp -d)"
SOURCE_DATE_EPOCH=315532800 \
  python remote_probe/build_zipapp.py --output "$release_tmp/bioprobe-a.pyz"
SOURCE_DATE_EPOCH=315532800 \
  python remote_probe/build_zipapp.py --output "$release_tmp/bioprobe-b.pyz"
SOURCE_DATE_EPOCH=315532800 \
  python remote_executor/build_zipapp.py --output "$release_tmp/bioexec-a.pyz"
SOURCE_DATE_EPOCH=315532800 \
  python remote_executor/build_zipapp.py --output "$release_tmp/bioexec-b.pyz"
cmp "$release_tmp/bioprobe-a.pyz" "$release_tmp/bioprobe-b.pyz"
cmp "$release_tmp/bioexec-a.pyz" "$release_tmp/bioexec-b.pyz"
shasum -a 256 "$release_tmp"/*.pyz
```

- [ ] Probe builds are byte-identical and the release SHA-256 is recorded.
- [ ] Executor builds are byte-identical and the release SHA-256 is recorded.
- [ ] Both zipapps contain a root `LICENSE` whose bytes match the repository.
- [ ] Zipapp health/protocol smoke tests pass from the built artifacts.
- [ ] Executor build and tests pass under Python 3.9, not only controller Python.
- [ ] The artifacts contain no controller configuration, home path, HMAC/SSH
      secret, test report, bytecode cache, or undeclared third-party package.
- [ ] Generated projects and production deployment bundles include the reviewed
      `LICENSE`, and its hash participates in project integrity checks.
- [ ] Temporary build evidence is removed only after required hashes/logs are
      retained.

## Security gates

- [ ] Probe path/mount/symlink/race/budget/FASTQ-redaction tests pass.
- [ ] SSH strict host-key, argument-array, timeout, bounded-output, and
      diagnostic-redaction tests pass.
- [ ] Manifest integrity, sanitization, override confinement, duplicate-key, and
      create-only tests pass.
- [ ] Generator reproducibility, registry graph, immutable container, unsafe
      path, and artifact-tamper tests pass.
- [ ] Synthetic fixture confinement, external-command timeout/output ceiling,
      offline environment, and output assertion tests pass.
- [ ] Executor config/ancestor/executable/JAR/SIF trust, fixed protocol,
      deployment allowlist, output collision, one-use token, HMAC, replay,
      tombstone race, job lease, status recovery, and resume tests pass.
- [ ] A repository scan found no private keys, tokens, real sample identifiers,
      raw FASTQ content, production hosts, or approval signatures.
- [ ] `SECURITY.md`, the threat model, supported versions, disclosure route,
      residual risks, and incident actions were reviewed.

## Anonymous release acceptance scenario

Activate the pinned environment and run exactly:

```bash
micromamba activate easy-pipe-m4
bash scripts/demo_release_acceptance.sh
```

- [ ] The demo requires no source modification, real SSH host, real secret,
      external network request, container pull, or biological/patient data.
- [ ] Java `23.0.2`, Nextflow `26.04.6`, nf-test `0.9.5`, and all three native
      workflow tools match the pinned release environment/software lock.
- [ ] Source registration and health verification pass through the production
      probe JSONL/controller contract with only SSH transport replaced by the
      deterministic local harness.
- [ ] Paired-end, multi-lane inspection produces full and sanitized manifests
      plus a candidate samplesheet without exporting read content.
- [ ] One attributable sample rename override produces a valid resolved
      manifest and diff without modifying the original.
- [ ] Planning and generation produce the fixed digest-pinned FASTQ-QC project.
- [ ] `validate` passes and writes `reports/validation.json`.
- [ ] `test --profile test` passes with real local FastQC/fastp/MultiQC and
      writes `reports/test.json`.
- [ ] Remote-executor preflight passes all ten controller/remote checks and
      writes `reports/preflight.json`.
- [ ] Submission without explicit approval is rejected and causes no run.
- [ ] Explicit attributable approval passes the production controller gate and
      deterministic execution-boundary harness; the separate M5 test sends the
      fixed JSONL lifecycle through the real `bioexec` service entry point.
- [ ] The real local synthetic test produces a non-empty MultiQC HTML/data
      directory, while the controlled execution lifecycle reaches success and
      records fixed command/environment hashes. These are complementary checks,
      not a claim of one real remote container run.
- [ ] Create-only artifacts and reports preserve source/manifest/plan/
      validation/test/preflight evidence; the append-only audit includes
      generation, approval, deployment, submission, status, and completion
      events without raw sequence, quality, full read identifiers, secrets, or
      signatures.
- [ ] Retained demo artifacts and checksums are linked to the release record.

## Documentation and operator handoff

- [ ] A new reviewer followed the README quick start from a clean checkout.
- [ ] Installation and uninstall instructions were tested without deleting data.
- [ ] Probe and executor deployment examples match current config schemas,
      permissions, ForceCommand behavior, fixed operations, and key handling.
- [ ] Every CLI leaf command has a current example in the CLI reference.
- [ ] Troubleshooting codes/remediation match current controller and remote
      errors.
- [ ] Known limitations explicitly cover local executor only, shared-filesystem
      mapping, no staging/cancel/delete, privacy limits, container/host trust,
      and non-clinical scope.
- [ ] Generated-project paths and output assertions match its generated README.

## Publication and rollback readiness

- [ ] The release commit is present on the intended protected branch and CI is
      green before tagging.
- [ ] Release notes summarize features, security-relevant changes, breaking
      changes, dependency changes, known limitations, and upgrade steps.
- [ ] Published source archive and zipapp SHA-256 values match local evidence.
- [ ] No package is described as a PyPI/binary distribution unless that exact
      artifact was actually built, reviewed, and published.
- [ ] Operators have a rollback plan that disables constrained keys, stops new
      approvals, restores the prior reviewed controller/agents/configs, and
      preserves active-run/audit evidence.
- [ ] Approval HMAC and SSH key rotation owners are identified.
- [ ] Backup, retention, monitoring, capacity, incident response, and secure
      disposal owners are identified before internal trial access is granted.

The release is blocked while any mandatory box is unchecked or supported only
by stale/different-commit evidence.
