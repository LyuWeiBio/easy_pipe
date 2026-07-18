# Security policy

Security and privacy failures in `easy_pipe` can expose biological-data
metadata or weaken a real-data execution gate. Please report them privately and
do not include real sample names, paths, FASTQ content, credentials, private
keys, approval keys, hostnames, or unredacted logs in a public issue.

## Supported versions

Until a stable release policy is announced, security fixes are made only on the
latest tagged `0.1.x` release and the current default branch. Older commits,
forks, locally modified templates/registries, and unpinned remote agents are not
supported.

| Version | Security fixes |
|---|---|
| Latest `0.1.x` tag | Yes |
| Default branch | Best effort; may be pre-release |
| Older snapshots | No |

The public artifact schemas and remote protocols use version `1.0`; that schema
version is independent of the Python package release version.

## Report a vulnerability

Use the repository's private **Security → Report a vulnerability** workflow:

<https://github.com/LyuWeiBio/easy_pipe/security/advisories/new>

If private vulnerability reporting is unavailable, open a public issue that
contains only a request for a private contact channel. Do not describe the
vulnerability or affected infrastructure in that issue.

Include, when it can be shared safely:

- the affected controller, probe, executor, registry, compiler, and protocol
  versions;
- the operating system and deployment role;
- a minimal reproduction using synthetic data and placeholder paths;
- expected and observed behavior;
- whether raw-read disclosure, path escape, command execution, approval bypass,
  signature forgery/replay, overwrite, secret exposure, or audit corruption is
  possible; and
- suggested mitigations or a patch, if available.

Do not test against infrastructure or data you are not authorized to access.
Do not attach a production config or full diagnostic archive.

## Response process

Maintainers will acknowledge a usable private report, reproduce it with
synthetic fixtures, assess affected versions, and coordinate a fix and release.
Timing depends on severity and maintainer availability; no fixed SLA is
currently offered. Please allow time for a coordinated release before public
disclosure.

## Immediate operator actions

For suspected compromise:

1. stop new approvals and submissions;
2. preserve controller and remote audit/state evidence without printing it;
3. disable the affected constrained SSH key;
4. rotate the approval HMAC key on both controller and executor and replace the
   bound execution profile/configuration;
5. quarantine affected zipapps, executables, JARs, images, deployments, and
   results for hash comparison; and
6. follow the site's incident-response, data-governance, and notification
   procedures.

`--abandon-pending` is not a running-job kill switch. Use the site's process,
container, scheduler, and account controls for containment.

The design assumptions, controls, and residual risks are documented in the
[security and threat model](docs/security-model.md).
