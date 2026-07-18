# Real-host release acceptance

This runbook is an operator-only release gate for one isolated Linux Source and
Execution Host. It is not a CI job. The repository supplies a bounded runner
and a sanitized evidence collector; it does not claim that a real host has
been tested. Only a named operator may run this procedure and record the
result.

The procedure is deliberately split into `prepare` and `execute`. `prepare`
creates the exact execution profile and then stops. An administrator can bind
the Remote Executor configuration to that profile's SHA-256 before `execute`
contacts it. The split avoids an unsafe bootstrap assumption and gives the
operator a review point before any approved submission.

## Acceptance boundary

Use a dedicated acceptance host or isolated acceptance accounts with:

- anonymous paired-end synthetic FASTQ files only; no human, production,
  customer, or otherwise identifying data;
- separate `bioprobe` and `bioexec` service accounts and constrained keys;
- authenticated OpenSSH host keys and strict host-key checking on every
  connection;
- an `authorized_keys` `ForceCommand` for the exact reviewed `bioprobe.pyz`
  and `bioexec.pyz`; neither key may open an interactive shell, forward ports,
  agents, or X11, or allocate a PTY;
- the reviewed Nextflow one/shadow JAR and its exact SHA-256;
- exactly one reviewed Docker or Apptainer runtime;
- locally preloaded, digest/hash-pinned FastQC 0.12.1, fastp 1.3.6, and
  MultiQC 1.35 containers;
- no Execution Host public-network egress by default; and
- distinct, non-overlapping read, deploy, work, output, cache, and private
  state roots with the ownership and modes in
  [remote deployment](remote-deployment.md).

Use only anonymous placeholder names in paths, samples, the override reason,
the profile identifier, and the actor identifier. Do not weaken a host check,
use a general remote shell, put secrets in environment diagnostic output, or
enable shell tracing. The acceptance runner itself begins with tracing
disabled, fail-closed shell options, and an owner-only umask.

The controller must be a reviewed checkout with the locked M6.1 environment
active. `biopipe`, Python, Java, Nextflow, nf-test, FastQC, fastp, and MultiQC
must resolve to the reviewed versions. The checkout must be pristine, including
no ignored or untracked runtime material; the collector binds its complete Git
tree to the candidate commit. Keep `NXF_OFFLINE=true`; the script also disables
Python bytecode writes and does not download tools, images, JARs, or FASTQs.

## Provision the constrained endpoints

Follow the complete [remote deployment guide](remote-deployment.md). In
particular, populate `known_hosts` through an authenticated site process and
give each acceptance key one fixed server-side command. The runner performs
two checks for each endpoint:

1. send the fixed protocol `health` JSON through `ssh ALIAS`; and
2. send the same JSON while supplying the deliberately invalid literal remote
   command `biopipe-forcecommand-self-test`.

The two responses must be byte-identical. A valid second response demonstrates
that the server ignored the client-supplied command and invoked the configured
fixed command. The raw health responses remain only in the private record
directory. They are inputs to the sanitizer, never direct release evidence.
Before either executor check, `execute` also requires its `--executor-alias` to
equal the exact `ssh_alias` stored in the prepared profile, so the checked
ForceCommand endpoint is the endpoint used by preflight and submission.

The Source Host must already have the anonymous dataset under its narrow read
allowlist before `prepare`. The Execution Host account, roots, runtime, JAR,
containers, private state, and constrained key must exist before `execute`.
Install the final executor config between the two stages, after the execution
profile hash is known.

## Prepare anonymous controller inputs

Create the controller approval key outside the repository and acceptance
record. Do not print its contents:

```bash
install -d -m 0700 /ABSOLUTE/PRIVATE/KEY-DIRECTORY
(umask 077; python -c 'import secrets; print(secrets.token_hex(32))' \
  > /ABSOLUTE/PRIVATE/KEY-DIRECTORY/acceptance.hex)
chmod 0600 /ABSOLUTE/PRIVATE/KEY-DIRECTORY/acceptance.hex
```

Create a minimal attributable override for the already reviewed anonymous
synthetic delivery. An empty change set is intentional: this exercises the
override binding without renaming or excluding files.

```yaml
override_version: "1.0"
reason: Anonymous synthetic release acceptance reviewed.
approved_by: acceptance-operator
```

Instantiate the candidate release-evidence directory before the execute stage
as described in [release evidence](release-evidence.md). Keep it private. The
real-host collector reads its safe candidate identity and checksum bindings; it
does not copy the full manifest, samplesheet, raw paths, command logs, or sample
names into the publishable evidence directory.

## Stage 1: prepare and create the exact profile

Choose a new absolute record directory. The script refuses an existing record,
creates it with mode `0700`, redirects every command's stdout and stderr below
its private `logs/` directory, and prints only fixed phase/status lines on the
controller console. On any failure it exits nonzero and retains every local and
remote artifact for review. It never cleans work, output, cache, state, or the
record directory.

Docker example:

```bash
scripts/real_host_acceptance.sh prepare \
  --record-dir /ABSOLUTE/PRIVATE/acceptance-record \
  --probe-alias acceptance-probe \
  --executor-alias acceptance-exec \
  --allowed-root /srv/biopipe/read \
  --dataset-root /srv/biopipe/read/anonymous-paired-fastq \
  --overrides /ABSOLUTE/PRIVATE/anonymous-overrides.yaml \
  --deploy-root /srv/biopipe/deployments \
  --work-root /srv/biopipe/work \
  --output-root /srv/biopipe/results \
  --cache-root /srv/biopipe/container-cache \
  --container-engine docker \
  --approval-key-id acceptance-controller-01 \
  --approval-key-file /ABSOLUTE/PRIVATE/KEY-DIRECTORY/acceptance.hex
```

For Apptainer, replace `--container-engine docker` and provide all six fixed
artifact bindings:

```bash
  --container-engine apptainer \
  --fastqc-sif /srv/biopipe/container-cache/fastqc-0.12.1.sif \
  --fastqc-sif-sha256 FASTQC_64_LOWERCASE_HEX_SHA256 \
  --fastp-sif /srv/biopipe/container-cache/fastp-1.3.6.sif \
  --fastp-sif-sha256 FASTP_64_LOWERCASE_HEX_SHA256 \
  --multiqc-sif /srv/biopipe/container-cache/multiqc-1.35.sif \
  --multiqc-sif-sha256 MULTIQC_64_LOWERCASE_HEX_SHA256
```

`prepare` runs this fixed order, with a dry-run immediately before every
stateful or remote controller command:

```text
source add preview -> source add
source verify preview -> source verify
fixed probe health -> ForceCommand proof
inspect preview -> inspect -> manifest show
apply-overrides preview -> apply-overrides
plan preview -> plan -> generate preview -> generate
validate preview -> validate -> test preview -> test
execution-profile create preview -> execution-profile create
```

`manifest show` and the health comparison are read-only and have no separate
dry-run mode. The planned workflow is fixed to paired FASTQ QC with trimming,
four CPUs, eight GiB, and the anonymous project name
`anonymous-fastq-qc`. The source/profile identifiers are fixed and the source
and execution host identities intentionally match; use separate SSH aliases
and accounts for the two roles.

Success ends with `STATUS PREPARED`. Inspect these private artifacts without
copying their contents into tickets or CI logs:

- `controller/project/generated/reports/validation.json` and `test.json` both
  report `passed`;
- the manifest summary has the expected anonymous pair count and no blocking
  issue;
- the planned work, result, and cache paths are children of the reviewed role
  roots; and
- `controller/execution-profiles/anonymous-real-host-local.json` contains the
  expected aliases, container bindings, approval key identifier, and roots.

Compute the exact profile SHA-256 privately. Install it as `profile_hash` in
the Remote Executor configuration, provision the same approval key through the
approved secret channel, and restart/reload only through the site's reviewed
service process. Do not put the HMAC key in shell history, source control,
terminal output, the record log, or a ticket.

## Stage 2: preflight, denial, approval, and status

Before starting, independently confirm that the dataset is still anonymous
synthetic data, the output target does not exist, the executor has no public
egress, and the profile hash/configuration match the prepared profile. Supply
the expected controller-visible paths where this run will publish the fixed
MultiQC HTML and `multiqc_data.json`; both files must be absent when `execute`
starts. The script rejects an earlier run, copied fixture, symlink, or existing
file. It requires both paths to equal the fixed locations below the prepared
profile's sole output root and later binds them to the terminal
`RunReport.result_dir`; after success they must be new non-empty regular files.
Their hashes are sanitized by the collector.

```bash
scripts/real_host_acceptance.sh execute \
  --record-dir /ABSOLUTE/PRIVATE/acceptance-record \
  --executor-alias acceptance-exec \
  --actor acceptance-operator \
  --candidate-evidence /ABSOLUTE/PRIVATE/candidate-evidence \
  --multiqc-report /srv/biopipe/results/anonymous-fastq-qc/multiqc/multiqc_report.html \
  --multiqc-data /srv/biopipe/results/anonymous-fastq-qc/multiqc/multiqc_data/multiqc_data.json \
  --bioprobe /ABSOLUTE/REVIEWED/bioprobe.pyz \
  --bioexec /ABSOLUTE/REVIEWED/bioexec.pyz
```

The fixed execute order is:

```text
fixed executor health -> ForceCommand proof
preflight preview -> preflight
snapshot audit -> preview denial -> run without approval: denied
snapshot and prove audit unchanged
approved run preview -> operator review/confirmation -> approved run
status preview -> bounded status polling: succeeded
verify MultiQC files -> snapshot final audit
create sanitized evidence -> verify sanitized evidence
```

After phase 40 passes, the script prints `PHASE 41 AWAITING_APPROVAL` and waits
on the controlling terminal without echo. Review the private phase-40 preview,
the validation/test/preflight reports, profile, manifest summary, exact target
paths, and container bindings. Only if every binding is correct and the data is
anonymous synthetic data, type this exact non-secret phrase and press Return:

```text
APPROVE-ANONYMOUS-SYNTHETIC-RUN
```

Any other input aborts without submission. The subsequent real command still
requires the attributable actor and `--approve-real-data`; the phrase is an
additional operator pause, not a replacement for the controller approval gate.
The script polls one exact locally recorded run ID for at most ten minutes and
records the UTC evidence-creation time only after terminal success. A
remote failure or timeout is a failed acceptance, not a partial pass. Do not
delete or rerun into the same output directory; preserve the record, work,
output, cache, and state roots for investigation.

The execute stage also rejects a symlinked or non-owned fixed record
subdirectory before opening new logs or snapshots. Do not move, replace, or
link anything below the prepared record between stages.

## Review and retain evidence

On success, the sanitized package is
`/ABSOLUTE/PRIVATE/acceptance-record/evidence`. The script creates it through
`collect_real_host_evidence.py create` and immediately runs `verify`. The
two-file package is supplemental evidence; do not overwrite or mutate the
sealed candidate directory or its pending placeholder. The
collector receives the fixed validation, test, preflight, run, status,
execution-profile, approval-denial, audit snapshots, health responses, MultiQC
files, remote zipapps, and candidate evidence. It retains only reviewed safe
fields, counts, states, and SHA-256 bindings. The bundle deliberately records
`remote_artifact_bytes_pending_independent_review`: hashing the supplied local
zipapps does not by itself prove that the same bytes were installed behind the
two constrained keys.

Before sign-off, a reviewer independent of the operator must:

1. rerun the collector's `verify` command against the retained directory;
2. confirm the terminal status is `succeeded` and the MultiQC bindings match
   the retained output;
3. confirm the no-approval attempt returned `APPROVAL_REQUIRED` and made no
   audit change;
4. verify audit ordering from approval through deployment, submission, status,
   and completion, including command/environment/return-code hash bindings;
5. compare the probe/executor zipapp SHA-256 values with the deployed files;
6. confirm no manifest, sample name, raw path, secret, raw health response,
   command output, HMAC material, private key, or full audit event was copied
   into publishable evidence; and
7. record the exact candidate commit, residual risks, blockers, date, and
   reviewer identity in the operator-only sign-off.

This evidence proves only the recorded isolated acceptance run. It is not a
release signature, does not authorize production data, and does not replace
the release checklist, independent reviewer sign-off, rollback owner, or key
rotation owner.
