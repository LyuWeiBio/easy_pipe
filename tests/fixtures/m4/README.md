# M4 synthetic FASTQ fixtures

These tiny records are deliberately artificial and use the reserved `SYNTHETIC_`
identifier prefix. They contain no patient, donor, instrument, accession, or real
biological sequence data. The M4 loader enforces their size, structure, pairing,
identifier prefix, and fixture-root confinement before any workflow command runs.
