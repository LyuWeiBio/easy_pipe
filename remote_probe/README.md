# bioprobe M2 remote probe

`bioprobe` is a Python 3.11+ standard-library-only, read-only filesystem
probe. It accepts bounded JSON Lines on stdin and writes one JSON response per
line on stdout. It has five fixed operations: `health`, `list_tree`,
`stat_files`, `detect_formats`, and `summarize_fastq`. It contains no shell,
`eval`, plugin loader, arbitrary execution, download, or raw-data write
operation. Content reads are limited to FASTQ format detection and bounded
record aggregation; raw lines are never returned.

## Configuration discovery

Requests cannot provide allowlisted roots. At startup, the first existing JSON
configuration is used:

1. the absolute path in `BIOPROBE_CONFIG` (when set; a missing file is an error),
2. `$XDG_CONFIG_HOME/bioprobe/config.json` or `~/.config/bioprobe/config.json`,
3. `~/.bioprobe.json`,
4. `/etc/bioprobe/config.json`.

If no default config exists, `health` remains available but the allowlist is
empty, so every path operation fails closed. See
[`examples/config.json`](examples/config.json). Config files and allowed roots
must exist; neither may itself be a symlink.

## Protocol

Each request contains `protocol_version`, `request_id`, `operation`, optional
`root`, optional `paths`, and optional `policy`. Client budgets can reduce but
cannot raise configured ceilings. `follow_symlinks: true` is always rejected.
`stat_files` requires one or more absolute `paths`; its optional `root`
further confines those paths. `list_tree` requires an absolute directory
`root` and uses descriptor-based `os.scandir` without loading an unbounded
directory listing.

```json
{"protocol_version":"1.0","request_id":"health-1","operation":"health"}
{"protocol_version":"1.0","request_id":"tree-1","operation":"list_tree","root":"/data/raw/run42","policy":{"max_depth":6,"max_entries":100000,"max_runtime_seconds":300,"follow_symlinks":false}}
{"protocol_version":"1.0","request_id":"stat-1","operation":"stat_files","root":"/data/raw/run42","paths":["/data/raw/run42/sample_R1.fastq.gz"]}
{"protocol_version":"1.0","request_id":"detect-1","operation":"detect_formats","root":"/data/raw/run42","paths":["/data/raw/run42/sample_R1.fastq.gz"],"policy":{"inspection_level":"format_summary","sample_fastq_records":1}}
{"protocol_version":"1.0","request_id":"summary-1","operation":"summarize_fastq","root":"/data/raw/run42","paths":["/data/raw/run42/sample_R1.fastq.gz"],"policy":{"inspection_level":"format_summary","sample_fastq_records":1000}}
```

Run from source:

```bash
BIOPROBE_CONFIG=/absolute/path/to/config.json \
  PYTHONPATH=remote_probe/src python -m bioprobe < requests.jsonl
```

Every response has `protocol_version`, `request_id`, `success`, `return_code`,
`result`, and `error`. Successful tree metadata contains only paths, relative
paths, names, entry kinds, sizes, nanosecond mtimes, permission modes, and
depths. FASTQ operations add only format/compression, sampled-record counts,
read-length aggregates, likely quality encoding, header family, and aggregate
mate-marker counts.

Stable return codes are 0 success, 10 protocol/schema failure, 11 unsupported
operation, 20 outside allowlist, 21 missing/unreadable path, 22 symlink/path or
mount escape, 30 scan budget exceeded, 31 elapsed-time budget exceeded, 40
unsupported format, 41 invalid FASTQ, and 50 sanitized internal failure. For a
multi-line invocation, processing continues and the process exits with the
first nonzero response code.

Request-line size, depth, entry, or explicit-path exhaustion returns code 30
for the whole request; `list_tree` never reports a truncated result as success.
The server-only `limits.max_response_bytes` setting defaults to 10 MiB and
counts the complete JSONL response including its newline. `list_tree` and
`stat_files`, `detect_formats`, and `summarize_fastq` account for each encoded
item before retaining it; an
overflow is replaced by a bounded `RESPONSE_BUDGET_EXCEEDED` response with code
30.

FASTQ content reads have three additional server-only ceilings. The defaults
are 100,000 structurally valid records per request
(`max_sample_records_total`), 256 MiB of decompressed stream bytes per request
(`max_content_bytes`), 256 MiB of underlying plain/compressed input reads per
request (`max_input_bytes`), and 1 MiB per FASTQ line
(`max_fastq_line_bytes`). The record and byte counters are shared across every
path in a `detect_formats` or `summarize_fastq` request; a request cannot reset
them by supplying more files. Underlying files are read unbuffered through a
deadline-aware meter, including gzip headers, optional names/comments, and
compressed deflate input. Line terminators count toward the decompressed
content-byte budget. Reaching a ceiling exactly is permitted, while any
overrun fails the whole request with `SCAN_BUDGET_EXCEEDED` and return code 30.
An otherwise valid record with an overlong line is also a budget failure,
never an `INVALID_FASTQ` classification.

## Descriptor security and portability

Every allowlist root is pinned by device and inode. Each request opens its
canonical root one component at a time, then traverses only with directory file
descriptors, `openat` semantics, `O_NOFOLLOW`, `fstat`/`fstatat`, and fd-based
`os.scandir`. A name replaced by a symlink between metadata inspection and open
therefore cannot redirect the probe. Directory descriptors are retained only
along the active recursion path, which is capped by `max_depth`.

This security model requires a POSIX host whose Python exposes `O_DIRECTORY`,
`O_NOFOLLOW`, `dir_fd`, `follow_symlinks=False`, and fd-based `os.scandir`—the
supported deployment target is Linux. Unsupported platforms fail closed with
`PLATFORM_UNSUPPORTED` (return code 50). Elapsed-time checks are monotonic and
cooperative between filesystem calls; a blocked kernel or network-filesystem
call still requires the controller's outer SSH/subprocess timeout.

The monotonic elapsed-time guard is directly testable as
`bioprobe.operations.Deadline(seconds, clock=callable)`; production operations
use `time.monotonic`.

## Reproducible zipapp and manual deployment

Build twice with the same sources and `SOURCE_DATE_EPOCH` to obtain identical
bytes:

```bash
SOURCE_DATE_EPOCH=315532800 python remote_probe/build_zipapp.py
sha256sum remote_probe/dist/bioprobe.pyz
```

The builder normalizes archive ordering, timestamps, permissions, and storage
format. It writes only to the requested output path. Installation is deliberately
manual; for example, as the dedicated remote account:

```bash
mkdir -p "$HOME/.local/bin" "$HOME/.config/bioprobe"
install -m 0755 remote_probe/dist/bioprobe.pyz "$HOME/.local/bin/bioprobe.pyz"
install -m 0600 remote_probe/examples/config.json "$HOME/.config/bioprobe/config.json"
```

Edit the copied config before use. The project never creates or modifies those
deployment directories automatically. A production SSH account should also use
normal host-key checking, least-privilege filesystem permissions, and a fixed
server-side command such as OpenSSH `ForceCommand`.
