# Remote Probe and Remote Executor deployment

Remote deployment is manual by design. The controller never creates remote
accounts, edits SSH configuration, accepts host keys, transfers raw reads,
installs a runtime, downloads a container, or changes a firewall. Perform the
steps below through the site's reviewed administration process.

## Deployment topology

Model these roles separately:

- **Controller Host** runs `biopipe`, stores full project artifacts and the
  controller-side approval key.
- **Source Host** exposes raw-data metadata through the read-only Remote Probe.
- **Execution Host** runs the fixed Remote Executor and Nextflow near the data.

The Source and Execution Hosts may be the same machine. Use distinct SSH
accounts or at least distinct constrained keys and SSH aliases so each key has
one fixed server-side command. If the hosts differ, the MVP supports execution
only when the execution host can already read the data through an explicit
shared-filesystem path mapping. It never stages FASTQs between hosts.

Example controller SSH aliases:

```sshconfig
Host hpc01-probe
    HostName hpc01.internal.example
    User bioprobe
    IdentityFile ~/.ssh/bioprobe_ed25519
    IdentitiesOnly yes

Host hpc01-exec
    HostName hpc01.internal.example
    User bioexec
    IdentityFile ~/.ssh/bioexec_ed25519
    IdentitiesOnly yes
```

Populate `known_hosts` through the site's authenticated process. Do not add
`StrictHostKeyChecking=no`; both controller transports require strict checking.

## Build and verify the artifacts

From the reviewed controller checkout:

```bash
SOURCE_DATE_EPOCH=315532800 \
  python remote_probe/build_zipapp.py --output remote_probe/dist/bioprobe.pyz
SOURCE_DATE_EPOCH=315532800 \
  python remote_executor/build_zipapp.py --output remote_executor/dist/bioexec.pyz
SOURCE_DATE_EPOCH=315532800 \
  python remote_executor/build_zipapp.py --artifact compute-preflight \
  --output remote_executor/dist/bioexec-compute-preflight
shasum -a 256 remote_probe/dist/bioprobe.pyz
shasum -a 256 remote_executor/dist/bioexec.pyz
shasum -a 256 remote_executor/dist/bioexec-compute-preflight
```

Record the hashes in the deployment ticket or equivalent audit system. Verify
the transferred files against those values on each remote host. Each zipapp
must contain a root `LICENSE` entry matching the reviewed checkout. The third
artifact is dormant M7 material: building or transferring it does not activate
the version-2 scheduler path.

## Deploy the read-only Remote Probe

The probe requires Linux/POSIX and Python 3.11 or newer. As its dedicated
account, install the reviewed zipapp and a strict configuration:

```bash
install -d -m 0700 "$HOME/.local/bin" "$HOME/.config/bioprobe"
install -m 0755 bioprobe.pyz "$HOME/.local/bin/bioprobe.pyz"
install -m 0600 config.json "$HOME/.config/bioprobe/config.json"
```

Start from `remote_probe/examples/config.json`. Its essential policy is:

```json
{
  "schema_version": "1.0",
  "allowed_roots": ["/data/raw"],
  "limits": {
    "max_depth": 6,
    "max_entries": 100000,
    "max_runtime_seconds": 300,
    "max_request_bytes": 1048576,
    "max_response_bytes": 10485760,
    "max_paths": 10000,
    "max_path_bytes": 4096,
    "max_sample_records_total": 100000,
    "max_content_bytes": 268435456,
    "max_input_bytes": 268435456,
    "max_fastq_line_bytes": 1048576
  },
  "follow_symlinks": false,
  "allow_mount_crossing": false
}
```

Every allowed root must be an existing absolute, non-symlink directory. Keep
the list as small as possible. Requests may lower configured budgets but cannot
raise them. Enable mount crossing only after reviewing the complete mounted
tree; it does not relax the allowlist.

The default configuration path is `~/.config/bioprobe/config.json`. An absolute
`BIOPROBE_CONFIG` can select another file, but a missing explicit file fails
closed. Do not put credentials, patient identifiers, or SSH material in this
configuration.

Constrain the SSH key in the probe account's `authorized_keys`. Replace the
paths and public key with reviewed values on the actual host:

```text
restrict,command="/usr/local/bin/python3.11 /home/bioprobe/.local/bin/bioprobe.pyz" ssh-ed25519 AAAA... controller-probe
```

Replace the interpreter path with the reviewed Python 3.11+ executable on that
host. `restrict` is the preferred modern OpenSSH shorthand for disabling forwarding,
PTY, and agent/X11 features. On older OpenSSH, use the equivalent explicit
`no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty` restrictions.
Do not grant the probe account a shared interactive-shell key.

Smoke-test the fixed command without including a data path:

```bash
printf '%s\n' \
  '{"protocol_version":"1.0","request_id":"health-1","operation":"health"}' \
  | ssh hpc01-probe
```

Register the same or narrower controller boundary, then verify through the real
controller transport:

```bash
biopipe source add hpc01 \
  --host hpc01-probe \
  --allowed-root /data/raw \
  --remote-probe-path '~/.local/bin/bioprobe.pyz'
biopipe source verify hpc01 --json
```

The controller SourceProfile does not replace the host-local allowlist. Both
must admit a path, and the probe performs the authoritative descriptor-based
filesystem check.

## Prepare the Remote Executor host

The executor requires Linux/POSIX and Python 3.9 or newer. Before configuring
it, the operator must install and review:

- an executable `java` and `nextflow` launcher;
- the exact local Nextflow one/shadow JAR and its full SHA-256;
- exactly one selected container runtime, `docker` or `apptainer`; and
- all digest-pinned Docker images or all hash-pinned local Apptainer SIF files.

The agent never downloads these dependencies. Executable leaf names must be
exactly `java`, `nextflow`, `docker`, and `apptainer`. The executables, JAR,
configuration, and their complete parent chains must be owned by root or the
agent account and must not be group/world-writable. The only writable-parent
exception is a root/agent-owned sticky directory such as `/tmp`.

Create non-overlapping role roots. Install the account-local files as the
`bioexec` account:

```bash
install -d -m 0700 "$HOME/.local/bin" "$HOME/.config/bioexec"
install -m 0755 bioexec.pyz "$HOME/.local/bin/bioexec.pyz"
```

Then have an administrator create the shared parent/runtime directory and
agent-owned writable roots (replace account/group names as needed):

```bash
sudo install -d -o root -g root -m 0755 \
  /srv/biopipe \
  /srv/biopipe/runtime
sudo install -d -o bioexec -g bioexec -m 0700 \
  /srv/biopipe/deployments \
  /srv/biopipe/work \
  /srv/biopipe/results \
  /srv/biopipe/container-cache \
  /srv/biopipe/private-state
```

All writable role roots must be stable non-symlink directories owned by root or
the agent account and not group/world-writable. `private-state` must have mode
`0700`. A configured read root may be owned by the data administrator, but it
also must not be group/world-writable and must not overlap or alias a writable
role root. Every submitted FASTQ must likewise be a regular non-symlink file
that is not group/world-writable. The executor compares both canonical paths
and filesystem identities. On a group-writable delivery tree, expose an
administrator-managed read-only projection rather than weakening the check.

Copy the reviewed Nextflow JAR to the runtime directory, make it immutable to
the service account, and record its hash. Provision SIFs below the cache root
and record each complete file hash. The exact commands are site-specific; do
not use a URL or a floating image tag in the executor configuration.

### Stage the dormant M7 compute worker

This step prepares only the separately reviewed M7 artifact. The current
version-1 ForceCommand, protocol, preflight, and execution lifecycle do not
invoke it. Scheduler config-v2 additionally fixes absolute paths with exact
leaves `python3`, `java`, `nextflow`, `apptainer`, and
`bioexec-compute-preflight`, plus the Nextflow JAR path and every full SHA-256.
Install the worker at one root-managed path visible with identical bytes on the
login and compute nodes:

```bash
sudo install -o root -g root -m 0755 \
  bioexec-compute-preflight \
  /srv/biopipe/runtime/bioexec-compute-preflight
```

The fixed batch template invokes the reviewed absolute Python path as
`<absolute-python3> -I -S /srv/biopipe/runtime/bioexec-compute-preflight`; it
never uses the archive shebang or `PATH`. Do not install either path as a symlink. The
service identity must not be able to replace the interpreter, worker, Java,
Nextflow launcher/JAR, Apptainer, SIFs, or their complete parent chains. The
path-based recheck and later process start are not one atomic operation, so
this administrator-owned deployment boundary remains mandatory before
activation.

Each future scheduler attempt uses the shared private layout
`private-state/scheduler-preflights-v1/<preflight_id>/{manifest,evidence}.json`.
The attempt directory is exact mode `0700`; both files are exact mode `0600`,
create-only, no-follow, bounded, canonical, and file/directory-fsynced. The
selected shared filesystem still needs real-cluster validation for these
semantics before scheduler activation.

The dormant M7.0d-e driver and M7.0d-f capability lifecycle are source-level
review surfaces, not an installed ForceCommand. State schema 1.2 records a
double-checked OS boot epoch and
boot-relative monotonic start in the create-only submit intent. Each call may
perform only the fixed action for the current phase and append at most one
journal revision. Exact worker evidence is copied as a bounded parsed object
into that private hash chain, so later handoff-file changes cannot alter the
recorded result. The driver stops at `candidate` and always returns a null
preflight token. The separate lifecycle can generate one raw token only after a
hash-only issuance revision is fsynced and replayed; a lost response cannot be
reissued, and lock/CAS consumption records trusted time, actor, and consumer
binding before success. It still does not start a workflow and must not be wired
into protocol version 2 until a create-only run permit and the remaining
activation blockers are reviewed. In particular, activation must add a
sleep-inclusive deadline recheck adjacent to scheduler process creation; the
current permit guard can precede filesystem validation, and a host suspend in
that interval cannot undo a later release. Raw capability responses must also
be excluded from application logs, core dumps, and swap according to site
policy.

## Create the controller approval key and profile

The SSH key and approval key are different controls. Create one random 32-byte
HMAC key on the controller without printing it to the terminal. Use a
site-approved absolute location outside every Git worktree, and fail if the
destination already exists:

```bash
install -d -m 0700 /secure/biopipe/controller-keys
python - <<'PY'
import os
import secrets

path = "/secure/biopipe/controller-keys/controller-2026-01.hex"
descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="ascii") as stream:
    stream.write(secrets.token_hex(32) + "\n")
    stream.flush()
    os.fsync(stream.fileno())
PY
```

The file must contain exactly 64 lowercase hexadecimal characters with an
optional final newline. Its path must be absolute in the execution profile. It
is read only when a submit, resume, or pending-abandon request must be signed;
the key bytes never enter the generated project, report, audit log, or response.

Create an Apptainer profile from the exact generated software lock. The
component names are the lock keys `fastqc`, `fastp`, and `multiqc` when trimming
is enabled; omit the `fastp` assignments when it is absent from the lock. First
preview the exact command by adding `--dry-run`; after review, execute the
command shown below:

```bash
biopipe execution-profile create hpc01-local \
  --source-host hpc01 \
  --execution-host hpc01 \
  --ssh-alias hpc01-exec \
  --software-lock projects/run42/generated/software.lock.yaml \
  --output-dir execution-profiles \
  --deploy-root /srv/biopipe/deployments \
  --work-root /srv/biopipe/work \
  --output-root /srv/biopipe/results \
  --cache-root /srv/biopipe/container-cache \
  --container-engine apptainer \
  --sif fastqc=/srv/biopipe/container-cache/fastqc-0.12.1.sif \
  --sif-sha256 fastqc=FASTQC_SIF_SHA256 \
  --sif fastp=/srv/biopipe/container-cache/fastp-1.3.6.sif \
  --sif-sha256 fastp=FASTP_SIF_SHA256 \
  --sif multiqc=/srv/biopipe/container-cache/multiqc-1.35.sif \
  --sif-sha256 multiqc=MULTIQC_SIF_SHA256 \
  --approval-key-id controller-2026-01 \
  --approval-key-file /secure/biopipe/controller-keys/controller-2026-01.hex \
  --json
```

Replace each uppercase placeholder with the corresponding 64-character
lowercase digest. For Docker, select `--container-engine docker` and omit every
`--sif` and `--sif-sha256`; the agent requires the locked images to be present
locally and configures `--pull=never` against the local Unix socket.

When Source and Execution Hosts expose the same shared filesystem under
different prefixes, repeat `--path-mapping SOURCE_PREFIX=EXECUTION_PREFIX`.
Without a reviewed shared mapping, preflight blocks execution.

The profile registry is create-only. Review it and record its exact hash:

```bash
biopipe execution-profile show hpc01-local \
  --profile-dir execution-profiles \
  --json
shasum -a 256 execution-profiles/hpc01-local.json
```

Changing the profile requires a new profile identifier and new create-only
profile file; never edit or replace a registered profile in place.

## Configure and constrain the Remote Executor

Start from `remote_executor/examples/config.json`. Build the real configuration
only inside an owner-only staging directory outside every Git worktree, and
replace every placeholder.
The `profile_hash` is the exact SHA-256 recorded above. `approval_hmac_key` is
the same secret value stored in the controller key file, provisioned through an
approved secret channel and never placed in shell history, source control, a
ticket, or a log.

```json
{
  "schema_version": "1.0",
  "profile_id": "hpc01-local",
  "profile_hash": "EXACT_CONTROLLER_PROFILE_SHA256",
  "read_roots": ["/data/raw"],
  "deploy_roots": ["/srv/biopipe/deployments"],
  "work_roots": ["/srv/biopipe/work"],
  "output_roots": ["/srv/biopipe/results"],
  "cache_roots": ["/srv/biopipe/container-cache"],
  "state_root": "/srv/biopipe/private-state",
  "executables": {
    "java": "/usr/bin/java",
    "nextflow": "/usr/local/bin/nextflow",
    "apptainer": "/usr/bin/apptainer",
    "docker": null
  },
  "nextflow_version": "26.04.6",
  "nextflow_jar": "/srv/biopipe/runtime/nextflow-26.04.6-one.jar",
  "nextflow_jar_sha256": "EXACT_NEXTFLOW_JAR_SHA256",
  "approval_key_id": "controller-2026-01",
  "approval_hmac_key": "PRIVATE_64_CHARACTER_LOWERCASE_HEX_VALUE",
  "limits": {}
}
```

The schema is exact: both container-runtime keys must be present, with the
unused runtime set to `null`. Install the final file with mode `0600`, owned by
root or the agent account, under a trusted parent chain:

```bash
install -m 0600 /secure/bioexec-staging/config.json \
  "$HOME/.config/bioexec/config.json"
```

Securely dispose of the plaintext staging copy under site policy after the
installed configuration and required secret backup have been verified.

The default discovery locations are `$XDG_CONFIG_HOME/bioexec/config.json`,
`~/.config/bioexec/config.json`, and `/etc/bioexec/config.json`. An absolute
`BIOEXEC_CONFIG` may override them; an invalid explicit override fails closed.

Constrain a separate SSH key to the fixed executor:

```text
restrict,command="/usr/bin/python3 /home/bioexec/.local/bin/bioexec.pyz" ssh-ed25519 AAAA... controller-exec
```

Smoke-test only the fixed health operation:

```bash
printf '%s\n' \
  '{"protocol_version":"1.0","request_id":"health-1","operation":"health","payload":{}}' \
  | ssh hpc01-exec
```

## Preflight and approved run lifecycle

The generated execution paths must be children of the profile's corresponding
role roots. Validation and the complete synthetic test must pass first:

```bash
biopipe validate projects/run42/generated --json
biopipe test projects/run42/generated --profile test --json
biopipe preflight projects/run42/generated \
  --execution-profile execution-profiles/hpc01-local.json \
  --json
```

Preflight does not deploy or run the workflow. It checks the exact profile and
project hashes, fixed runtime versions, path mapping, every raw input, storage,
free-space threshold, and container evidence, then writes
`reports/preflight.json` and private one-use state.

First verify the denial boundary or use `--dry-run`. A submission without both
an actor and `--approve-real-data` is blocked:

```bash
biopipe run projects/run42/generated \
  --execution-profile execution-profiles/hpc01-local.json \
  --actor operator_id
```

After reviewing every bound artifact and target, submit explicitly:

```bash
biopipe run projects/run42/generated \
  --execution-profile execution-profiles/hpc01-local.json \
  --actor operator_id \
  --approve-real-data \
  --json
```

The response contains a `run_id`. Status queries are exact and require the
locally recorded run:

```bash
biopipe run projects/run42/generated \
  --execution-profile execution-profiles/hpc01-local.json \
  --status run-0123456789abcdef0123456789abcdef \
  --json
```

Resume is allowed only from a recorded compatible terminal run and requires a
fresh resume preflight plus a new explicit approval:

```bash
biopipe preflight projects/run42/generated \
  --execution-profile execution-profiles/hpc01-local.json \
  --resume run-0123456789abcdef0123456789abcdef \
  --json

biopipe run projects/run42/generated \
  --execution-profile execution-profiles/hpc01-local.json \
  --resume run-0123456789abcdef0123456789abcdef \
  --actor operator_id \
  --approve-real-data \
  --json
```

If a submit response is lost, repeat exact status queries for the recorded run
ID; never resubmit as a retry. Only a locally recorded unresolved pending run
that exact status confirms absent can be reconciled with `--abandon-pending`,
and only after the fixed five-minute safety delay. This creates a signed remote
tombstone; it does not terminate a running process:

```bash
biopipe run projects/run42/generated \
  --execution-profile execution-profiles/hpc01-local.json \
  --abandon-pending run-0123456789abcdef0123456789abcdef \
  --json
```

The executor never deletes work or output. Apply site retention, monitoring,
job termination, and incident procedures outside this protocol. See the
[security model](security-model.md), [troubleshooting guide](troubleshooting.md),
and [known limitations](known-limitations.md).
