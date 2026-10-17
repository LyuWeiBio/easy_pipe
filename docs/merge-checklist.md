# Merge checklist

Every pull request merged into `main` must satisfy all of the items below.
The release checklist (`docs/release-checklist.md`) covers release
candidates; this page covers the bar for merging ordinary changes.

## Automated gates (must be green)

- [ ] `ruff check .` and `ruff format --check .` pass without modifying the
      tree.
- [ ] Strict `mypy` passes for `src`, `remote_probe/src`,
      `remote_executor/src`, and the scripts listed in
      `.github/workflows/ci.yml`.
- [ ] The full `pytest` suite passes. Pre-existing environment failures
      (missing docker/java, uninstalled package entry points) are tracked,
      not fixed in passing; any *new* failure blocks the merge.
- [ ] `python scripts/generate_supply_chain_inventory.py verify` passes
      offline. CI runs this on every PR: a stale committed inventory fails
      the build.

## Supply-chain inventory regeneration (fail-closed)

`environments/locks/` binds the exact remote runtime artifacts
(`remote-zipapps.json`: reproducible zipapp builds of `remote_probe` and
`remote_executor`), the conda platform locks, the container digests, and
`SHA256SUMS` over the whole bundle.

- [ ] If the diff touches **any** of the following, the inventory was
      regenerated with `scripts/generate_supply_chain_inventory.py generate`
      (to a fresh directory, then atomically swapped over
      `environments/locks/`) **in the same PR**, and `SHA256SUMS` inside the
      bundle was regenerated with it:
  - `remote_probe/src/**` or `remote_probe/build_zipapp.py`
  - `remote_executor/src/**` or `remote_executor/build_zipapp.py`
  - `environments/m4-test.yml`
  - `src/biopipe/registry/data/**` (container digests feed
    `containers.json`)
  - `scripts/generate_supply_chain_inventory.py` itself
- [ ] The regeneration diff was reviewed: only the expected files changed
      (normally just `remote-zipapps.json` and `SHA256SUMS` for a remote-code
      change). Unexpected churn in the conda platform locks is a red flag —
      do not merge until it is explained.
- [ ] `verify` passes on the regenerated bundle before merge.

Rationale: the deployed remote artifacts are the zipapps hashed in
`remote-zipapps.json`, not the source tree. Merging remote-side code without
regenerating the inventory leaves the committed hashes pointing at the
previous build — a silent mismatch between reviewed code and shipped
bytes that CI's `verify` step is designed to catch.

## Change hygiene

- [ ] The diff contains only intended changes: no generated caches, local
      profiles, private state, real reports, real data, or secrets.
- [ ] No new `*_TOKEN`/`*_KEY`/`*_SECRET` values are committed; test
      fixtures use obviously synthetic values.
- [ ] Shared parsing/security primitives were not forked: JSON handling goes
      through `biopipe._jsonutil`, bounded file reads through
      `biopipe.execution._fsutil`, and each remote package keeps its own
      constants (no cross-package imports between the controller and the
      remote deployment bundles).
- [ ] New fail-closed behavior is covered by regression tests that fail on
      the pre-fix code.
- [ ] User-facing error/remediation strings name the real expected format
      (e.g. `run-<32 lowercase hex>`, not a stale placeholder).
