"""Cross-module _JOB_ID consistency: compute_worker vs slurm.

Both modules validate Slurm job IDs with their own ``_JOB_ID`` copy (kept
as literals rather than a shared import to avoid coupling the worker's
minimal import surface to the scheduler driver). This test locks the two
patterns together and pins the accepted range.
"""

from __future__ import annotations

import bioexec.compute_worker as worker_module
import bioexec.slurm as slurm_module


def test_job_id_patterns_are_identical() -> None:
    assert worker_module._JOB_ID.pattern == slurm_module._JOB_ID.pattern
    assert worker_module._JOB_ID.flags & slurm_module._JOB_ID.flags


def test_job_id_accepts_canonical_slurm_range() -> None:
    for module in (worker_module, slurm_module):
        assert module._JOB_ID.fullmatch("1") is not None
        assert module._JOB_ID.fullmatch("4294967295") is not None


def test_job_id_rejects_non_canonical_forms() -> None:
    for module in (worker_module, slurm_module):
        assert module._JOB_ID.fullmatch("0") is None
        assert module._JOB_ID.fullmatch("01") is None
        assert module._JOB_ID.fullmatch("12345678901") is None  # > 10 digits
        assert module._JOB_ID.fullmatch("12a") is None
        assert module._JOB_ID.fullmatch("") is None
