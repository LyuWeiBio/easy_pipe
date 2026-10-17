"""Cross-end allowlist consistency: controller vs remote executor.

The controller (biopipe.execution.deploy) and the remote executor
(bioexec.deployment) each keep their own copy of the deployment allowlist
— cross-package imports are forbidden because the remote bundle is
self-contained. This test locks the two copies together: identical
constant sets, and identical _is_production_file verdicts on a battery
of path samples, including the old controller hole (any modules/*.nf).
"""

from __future__ import annotations

import pytest

import bioexec.deployment as remote_deployment
import biopipe.execution.deploy as controller_deploy


def test_allowlist_constants_are_identical_across_ends() -> None:
    assert controller_deploy._FIXED_FILES == remote_deployment._FIXED_FILES
    assert controller_deploy._MODULE_FILES == remote_deployment._MODULE_FILES
    assert controller_deploy._REQUIRED_PRODUCTION_FILES == remote_deployment._REQUIRED_FILES


# (path, expected verdict on both ends)
_PATH_SAMPLES: tuple[tuple[str, bool], ...] = (
    # Fixed files: exact match.
    ("LICENSE", True),
    ("README.md", True),
    ("main.nf", True),
    ("nextflow.config", True),
    ("pipeline.spec.yaml", True),
    ("execution.plan.yaml", True),
    ("software.lock.yaml", True),
    ("dataset.manifest.resolved.json", True),
    ("assets/samplesheet.csv", True),
    ("audit/events.jsonl", True),
    ("conf/base.config", True),
    ("conf/local.config", True),
    # Declared module allowlist.
    ("modules/fastp/main.nf", True),
    ("modules/fastqc/post_trim.nf", True),
    ("modules/fastqc/raw.nf", True),
    ("modules/multiqc/main.nf", True),
    # The old controller hole: arbitrary modules/*.nf must be rejected.
    ("modules/evil.nf", False),
    ("modules/a/b.nf", False),
    ("modules/fastqc/evil.nf", False),
    ("modules/.nf", False),
    ("modules", False),
    ("modules/", False),
    # Absolute paths and traversal.
    ("/modules/fastqc/raw.nf", False),
    ("/main.nf", False),
    ("../main.nf", False),
    ("modules/../main.nf", False),
    ("a/../../main.nf", False),
    # Near-misses on fixed files.
    ("main.nf ", False),
    ("MAIN.NF", False),
    ("Main.nf", False),
    ("conf/base.config.bak", False),
    ("conf/evil.config", False),
    ("README", False),
    # Raw biological data is never a production file.
    ("data/sample.fastq", False),
    ("data/sample.fastq.gz", False),
    ("modules/evil.fastq", False),
    ("run.bam", False),
    # Backslashes are not separators (PurePosixPath treats them literally).
    ("modules\\fastqc\\raw.nf", False),
    ("", False),
)


@pytest.mark.parametrize(("path", "expected"), _PATH_SAMPLES)
def test_is_production_file_agrees_across_ends(path: str, expected: bool) -> None:
    controller = controller_deploy._is_production_file(path)
    remote = remote_deployment._is_production_file(path)
    assert controller is expected, f"controller verdict for {path!r}"
    assert remote is expected, f"remote verdict for {path!r}"
    assert controller == remote, f"ends disagree on {path!r}"
