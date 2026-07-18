# Reproducible environment and supply-chain inventory

These files are generated create-only from `environments/m4-test.yml`,
`pyproject.toml`, the fixed component registry, and the two remote zipapp source
trees. Run `python scripts/generate_supply_chain_inventory.py verify` for a
fully offline integrity and contract check.

The explicit locks are cross-platform solver transactions, not proof that the
environments ran on native hosts. Native Linux and macOS runtime validation is
`pending` and belongs to release-acceptance CI. Container identities come from
the reviewed registry, but exact-image digest material verification and full
container-content license review are also `pending`; this directory does not
authorize a release or replace reviewer sign-off.

Generation uses only the public `conda-forge` and `bioconda` channels, fixed
virtual packages, an empty temporary solver root, and strict channel priority.
The output directory is published atomically and must not already exist.
