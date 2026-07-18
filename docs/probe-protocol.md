# Remote Probe protocol v1

The Remote Probe is a deliberately narrow, read-only program that runs on the
Source Host. It accepts one UTF-8 JSON object per input line and emits exactly
one JSON object per output line. The protocol never provides shell, Python,
download, write, move, or delete operations.

## Trust boundary

The probe reads its allowed roots from a host-local configuration file. A
request cannot expand that allowlist. Paths are resolved canonically on the
Source Host and must remain under one configured root. Symlinks are rejected by
default, including symlinks whose targets happen to remain inside the root.

The default configuration location is:

```text
${XDG_CONFIG_HOME:-~/.config}/bioprobe/config.json
```

Example configuration:

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
    "max_path_bytes": 4096
  },
  "follow_symlinks": false,
  "allow_mount_crossing": false
}
```

`BIOPROBE_CONFIG` may point to an absolute configuration path. Otherwise the
probe checks the XDG path above, `~/.bioprobe.json`, and finally
`/etc/bioprobe/config.json`. If no file exists, `health` remains available but
all path operations fail closed because the allowlist is empty.

The configuration and zipapp are installed manually. `biopipe` does not write
them to a remote host in M1.

On the supported Linux/POSIX target, the probe pins every allowed root by
device and inode, opens path components relative to directory descriptors with
`O_NOFOLLOW`, and scans by descriptor. A concurrent rename or symlink
replacement therefore cannot redirect a checked traversal. Hosts without the
required descriptor APIs fail closed.

## Request envelope

```json
{
  "protocol_version": "1.0",
  "request_id": "scan-001",
  "operation": "list_tree",
  "root": "/data/raw/run42",
  "paths": [],
  "policy": {
    "inspection_level": "metadata_only",
    "max_depth": 6,
    "max_entries": 100000,
    "follow_symlinks": false,
    "sample_fastq_records": 0,
    "return_sequences": false,
    "return_qualities": false,
    "return_read_names": false
  }
}
```

M1 supports:

- `health`: protocol and runtime health; no path is required.
- `list_tree`: bounded metadata traversal below `root` using `os.scandir`.
- `stat_files`: metadata for the absolute paths in `paths`.

Other protocol names are reserved for later milestones and return an
unsupported-operation response until implemented.

Each input line is capped by the host-local `max_request_bytes` setting. JSON
nesting is additionally capped at 128 container levels before decoding so that
maliciously deep input is rejected consistently across supported Python
versions with `INVALID_JSON`.

## Response envelope

Success:

```json
{
  "protocol_version": "1.0",
  "request_id": "scan-001",
  "success": true,
  "return_code": 0,
  "result": {"entries": []},
  "error": null
}
```

Failure:

```json
{
  "protocol_version": "1.0",
  "request_id": "scan-001",
  "success": false,
  "return_code": 20,
  "result": null,
  "error": {
    "code": "PATH_OUTSIDE_ALLOWLIST",
    "message": "path is not within a configured allowed root",
    "context": {},
    "remediation": ["Choose a path below a configured allowed root."]
  }
}
```

## Return codes

| Code | Meaning |
|---:|---|
| 0 | Success |
| 10 | Invalid JSON, protocol, schema, or configuration |
| 11 | Operation is not implemented or allowlisted |
| 20 | Path is outside the configured allowlist |
| 21 | Path does not exist or is not readable |
| 22 | Symlink or canonical-path escape was detected |
| 30 | Depth, entry, request-size, response-size, or another scan budget was exceeded |
| 31 | Runtime budget was exceeded |
| 40 | Unsupported file format (reserved for M2) |
| 41 | Invalid FASTQ structure (reserved for M2) |
| 50 | Internal failure with sanitized diagnostic data |

## Privacy guarantees

M1 operations return filesystem metadata only: path, entry type, size,
timestamps, permissions, and traversal summaries. They do not open file
contents and cannot return FASTQ sequences, qualities, full read identifiers,
credentials, environment dumps, or arbitrary file lines.

The complete JSONL response, including its newline, is capped by the host-local
`max_response_bytes` limit. Collection operations account for encoded metadata
before retaining it and return a bounded code-30 error rather than a partial
success when the response budget would be exceeded.
