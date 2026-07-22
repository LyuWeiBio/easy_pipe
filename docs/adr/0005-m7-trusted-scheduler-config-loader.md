# ADR 0005: Load scheduler configuration through trusted filesystem identities

- **Status:** Accepted for dormant implementation
- **Date:** 2026-07-19
- **Scope:** M7.0d-a trusted version-2 scheduler configuration loading

## Context

The version-2 scheduler configuration introduced in M7.0b validates decoded
values only. It deliberately does not open the configuration file, configured
roots, scheduler executables, or the pinned Nextflow JAR. M7.0c therefore could
describe compute-node preflight identities but could not safely connect them to
installed filesystem objects.

The version-1 loader cannot simply be reused. Version 2 must remain unreachable
from the current service, must not be selected by environment-variable or
default-path discovery, and must reject intermediate symlinks rather than
canonicalizing through them. A future scheduler mutation also needs to prove
that the object used is the same object reviewed at service startup.

## Decision

### 1. Add a separate, explicit version-2 loader

M7.0d-a adds a scheduler-only loader which accepts one explicit absolute
configuration path. It does not consult `BIOEXEC_CONFIG`, `XDG_CONFIG_HOME`,
the account home directory, or `/etc`, and it does not auto-dispatch between
schema versions.

The loader reads a bounded regular file through a descriptor-relative,
component-by-component no-follow walk. The file and every parent must have
trusted ownership and permissions. JSON must be strict UTF-8, duplicate-free,
finite, bounded, and accepted by the existing pure version-2 parser.

### 2. Bind startup identities for every filesystem role

The loaded object retains the pure scheduler configuration together with:

- the configuration file identity and complete SHA-256;
- device, inode, owner, and mode for every configured root;
- identity plus a bounded full SHA-256 for all seven executable roles fixed at
  M7.0d-a;
  and
- identity plus the full expected SHA-256 for the pinned Nextflow JAR.

ADR 0008 later adds the absolute Python interpreter and fixed compute-preflight
worker, and ADR 0011 adds the compute bootstrap. The current closed set is ten
roles, all subject to the same startup identity, full-hash, and
mutation-boundary rechecks.

Writable roots and the state root must be owned by root or the service account;
the state root remains private. Read roots may retain a data-administrator
owner, but no configured root may be group/world writable. Role separation is
checked by both canonical path relationship and device/inode alias, so an
alternate filesystem identity path cannot bypass the syntax contract.

Executables must be fixed-leaf, bounded, regular, executable,
root/service-owned, and not group/world writable. Their startup hashes are
captured by the loader. The JAR must be non-empty, trusted, and match its
configured full SHA-256.

### 3. Recheck identities at every future scheduler mutation boundary

The loader exposes role-specific rechecks. A recheck repeats the no-follow
parent walk and compares the exact startup identity. Executables and the JAR
are fully re-hashed, with stable metadata required across each read.
Replacement, permission changes, parent-chain changes, or content mutation fail
closed. These checks are prerequisites for a future scheduler adapter; they do
not themselves authorize a scheduler command. The next runner slice must place
the executable recheck immediately beside process creation; this loader does
not claim to eliminate a local same-account race after it returns.

### 4. Keep the slice dormant and side-effect free

The version-1 config loader, protocol, dispatcher, preflight, deployment, and
runner do not import the scheduler loader. Loading or rechecking performs no
filesystem writes, process execution, scheduler access, network access, token
generation, or durable-state mutation.

This slice does not create a compute-worker binding, submit `sbatch`, release a
held job, issue a capability, or start a workflow. Synthetic filesystem tests
are not cluster acceptance evidence.

## Consequences

### Positive

- Syntax-level scheduler policy is now separable from trusted installed
  identity evidence.
- Future scheduler mutations can fail closed when a reviewed object or parent
  chain changes after startup.
- Version 1 remains isolated and semantically unchanged.

### Costs

- Strict parent ownership and mode rules may require administrator-managed,
  read-only projections on permissive HPC filesystems.
- Full executable and JAR re-hashing adds bounded I/O at safety-critical
  mutation boundaries.
- No scheduler operation becomes reachable in this slice.

## Next step

M7.0d-b adds the separate raw-bytes, bounded, stdin-capable scheduler transport
described by ADR 0006. M7.0d-c adds the durable scheduler-preflight state and
one-shot mutation permits described by ADR 0007. M7.0d-d extends this loader's
closed executable set with the absolute Python interpreter and fixed compute
worker, then binds their hashes into manifest 1.1 as described by ADR 0008.
M7.0d-e joins them only through the dormant driver-to-candidate boundary in ADR
0009. M7.0d-f adds hash-only capability persistence in ADR 0010, and M7.0d-g
adds the bootstrap binding and run-start recheck in
[ADR 0011](0011-m7-durable-run-bootstrap.md). Active version-2 dispatch, fixed
workload execution, and real-cluster acceptance remain required before
activation.
