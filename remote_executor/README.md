# bioexec M5 remote execution agent

`bioexec` is a Python 3.9+ standard-library-only agent for the controlled M5
execution path. It accepts exactly one newline-terminated JSON request on
stdin, emits exactly one JSON response on stdout, and exits with the response
return code. It has only seven operations: `health`, `preflight`, `deploy`,
`submit`, `status`, `resume`, and signed `abandon`.

It is deliberately not a shell service. There is no command, argv, environment,
plugin, download, delete, or arbitrary file-upload API. Every subprocess uses
`shell=False` and a service-owned argv. The only uploaded files are a bounded,
create-only production Nextflow bundle; raw FASTQ/BAM/CRAM and test/report
trees are rejected.

The source tree also contains dormant M7 Slurm primitives plus strict config
and protocol version-2 validators. The current service does not import them:
`load_config`, request parsing, health, and dispatch remain exactly version 1,
and no scheduler process can be launched through this agent yet. See
[ADR 0003](../docs/adr/0003-m7-versioned-scheduler-contracts.md).

The follow-up compute-node preflight manifest, fixed-template, evidence, and
transition rules are likewise dormant. They do not submit a job or mint an
execution capability. See
[ADR 0004](../docs/adr/0004-m7-compute-preflight-contract.md).

M7.0d-a adds an explicit trusted-filesystem loader for the dormant version-2
configuration. It records startup identities and can recheck them before a
future scheduler mutation, but the version-1 service still does not import it
and it cannot execute Slurm. See
[ADR 0005](../docs/adr/0005-m7-trusted-scheduler-config-loader.md).

M7.0d-b adds a separate raw-byte, stdin-capable process transport behind six
fixed Slurm operations. It preserves timeout and lost-response ambiguity and
cannot accept caller-provided argv, environment, flags, or script bytes. The
transport is testable when imported directly, but no installed entry point or
version-1 operation imports it, so scheduler mutation remains inactive. See
[ADR 0006](../docs/adr/0006-m7-bounded-scheduler-transport.md).

M7.0d-c adds a separate owner-only, append-only scheduler-preflight state
namespace. Submit and release intents are create-only and must yield a live,
lease-bound one-shot permit before the fixed transport admits either mutation;
restart recovery never replays them. This layer is also absent from every
installed version-1 path and does not activate Slurm. See
[ADR 0007](../docs/adr/0007-m7-durable-scheduler-preflight-state.md).

## Build and install

The zipapp builder sorts sources and normalizes ZIP timestamps, permissions,
and compression, so identical sources and `SOURCE_DATE_EPOCH` produce
identical bytes:

```bash
SOURCE_DATE_EPOCH=315532800 python remote_executor/build_zipapp.py
sha256sum remote_executor/dist/bioexec.pyz
```

Installation is intentionally manual and should use a dedicated remote
account. Create role-separated roots; `private-state` must be mode `0700` and
the config should be mode `0600`. Configured writable roots, the config, Java,
Nextflow launcher, pinned Nextflow one/shadow JAR, and selected container
executable must be owned by root or the agent account and must not be
group/world-writable. Every parent directory is opened without following
symlinks and must have trusted ownership and permissions (a root/agent-owned
sticky directory such as `/tmp` is the only writable-parent exception).

```bash
install -d -m 0700 "$HOME/.config/bioexec" "$HOME/.local/bin"
install -m 0755 remote_executor/dist/bioexec.pyz "$HOME/.local/bin/bioexec.pyz"
install -m 0600 remote_executor/examples/config.json \
  "$HOME/.config/bioexec/config.json"
```

Without an override, the agent selects the first existing config from
`$XDG_CONFIG_HOME/bioexec/config.json` (when XDG is an absolute safe path),
`~/.config/bioexec/config.json`, then `/etc/bioexec/config.json`.
`BIOEXEC_CONFIG` may explicitly override discovery with an absolute path. An
explicit invalid or missing override fails closed instead of falling back. The
example is not ready to use: replace every root and executable with reviewed
paths, set `profile_hash` to the SHA-256 of the exact controller
execution-profile file, replace `approval_key_id` and the example HMAC key with
a controller-provisioned 32-byte secret, set the exact Nextflow version and
full SHA-256 of a locally installed trusted Nextflow one/shadow JAR, select
Docker or Apptainer, and create all configured roots before startup. Never
commit or log the real HMAC key.
Read, deploy, work, output, cache, and private state roles may not overlap.

For production, bind this program with an OpenSSH `ForceCommand`, retain normal
host-key verification, and give the account only the filesystem permissions
needed by its configured roots. Do not expose the agent through a shared shell
account.

## Fixed protocol and lifecycle

Every request uses this exact envelope; duplicate JSON keys, non-finite
numbers, extra fields, excessive nesting, multiple lines, and oversized input
are rejected before an operation can mutate state.

```json
{"protocol_version":"1.0","request_id":"health-1","operation":"health","payload":{}}
```

The intended lifecycle is:

1. `preflight` binds the execution profile and four core project hashes. It
   returns nine sorted remote checks and a short-lived one-use capability token
   only when runtime, raw-data reads, mapping, storage, space, container digest,
   and host relationship checks pass. The controller adds its successful strict
   SSH transport check, producing the required ten-check final report.
2. `deploy` accepts the token-bound deployment directory and an exact
   production allowlist. Every file has a size and SHA-256; the agent recomputes
   the canonical bundle hash and publishes to a new direct child only.
3. `submit` requires explicit approval bound to the profile, project, validation,
   tests, preflight report, bundle, and compatibility hashes. It first creates a
   hash-bound run reservation while holding a job lease, then reopens inputs,
   inventories and hashes the complete deployment, and rechecks storage. Only
   after those side-effect-free checks pass does it atomically consume the
   preflight token and create private work/output directories. Their device,
   inode, owner, and mode become immutable resume evidence.
4. A detached supervisor runs one fixed local-executor Nextflow argv and updates
   durable state. The same locked file descriptor is inherited by the real
   Nextflow process, so supervisor death cannot make a still-running job appear
   abandoned. `status` reconciles a released lease to a durable failed terminal
   state and returns fixed command/environment hashes, but never arbitrary paths.
5. `resume` requires a fresh resume preflight, a new attempt ID, the same
   deployment/profile/project/bundle compatibility, and the exact previous
   work/output/cache paths. It adds only Nextflow's fixed `-resume` flag.
6. `abandon` is an HMAC-authenticated, create-only tombstone for a controller
   submission whose response was lost. Whichever reaches the run ID first—the
   tombstone or the signed submission reservation—wins atomically. Exact
   tombstone retries are idempotent; changed bindings and late submissions fail.

Initial output and work targets must not exist. The agent never automatically
deletes deployments, work directories, results, or logs, including after a
failed or timed-out run.

Submit, resume, and abandon mutations carry an HMAC-SHA256 controller
attestation over the complete operation payload, with only the signature field
removed. The agent verifies the configured key ID and signature before reading
or creating run state and before consuming the preflight token. Neither the
secret nor request signature is copied into responses, logs, or durable run
records.

## Offline execution policy

The agent creates a private final config overlay whose first statement includes
the hash-verified project config. Later statements force the local executor,
disable Wave/Tower/Fusion, force exactly the selected container engine, and add
Docker `--network none --pull=never` or Apptainer network-namespace isolation.
Nextflow is launched with `-C` so user, home, and launch-directory configs are
ignored. The environment is rebuilt from an allowlist and always sets
`NXF_OFFLINE=true`. `JAVA_CMD`, `NXF_VER`, and `NXF_BIN` bind the reviewed Java,
version, and fully re-hashed local JAR. Every preflight and run receives new
mode-`0700` `HOME`, `NXF_HOME`, `TMPDIR`, Docker config, and Apptainer config
directories under private agent state; proxy, context, TLS, credential, loader,
and inherited Nextflow variables are not passed. Docker is pinned to the local
`unix:///var/run/docker.sock` endpoint.

For Apptainer, the final overlay also maps the fixed FASTQ-QC process labels to
the exact local SIF paths checked by preflight. The agent records each SIF's
device, inode, size, timestamps, and full SHA-256, then reopens and re-hashes it
immediately before submission; OCI references are never left for an offline
Apptainer run to pull. Apptainer/Singularity runs force `--containall`,
`--no-home`, `--cleanenv`, and an isolated network namespace.

Host firewalling remains the recommended outer control. The agent cannot prove
that a locally administered container runtime or kernel network namespace is
correct; preflight verifies the reviewed runtime and pinned local image
evidence and then fails closed if any fixed check changes.

Raw inputs must remain immutable for the entire job. The agent descriptor-checks
device, inode, size, timestamps, permissions, and parent chain immediately
before launch, but Nextflow later reopens sample paths. Likewise, process-group
termination cannot prove that a privileged container daemon cleaned up every
runtime-created descendant; operators should retain host-level cgroup/runtime
monitoring and cleanup policy.

## Tests

All fixtures are synthetic and contain no biological or patient data:

```bash
PYTHONPATH=remote_executor/src pytest remote_executor/tests
ruff check remote_executor
mypy --strict --python-version 3.11 remote_executor/src/bioexec \
  remote_executor/build_zipapp.py
```

The suite covers strict JSONL framing, duplicate keys and budgets, role/path
confinement, symlinks, mapping and host checks, Docker/Apptainer evidence,
production allowlisting, create-only deployment, tamper detection, approval,
one-use tokens, input replacement, output collision, asynchronous status and
job-lifetime leases, signed abandonment races, compatible resume, executable,
JAR, config and ancestor trust, dormant scheduler-config startup identities and
mutation-boundary rechecks, append-only scheduler state, one-shot mutation
permits, restart and corruption recovery, isolated client environments, and
reproducible zipapp execution.
