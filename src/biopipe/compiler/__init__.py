"""Deterministic Nextflow DSL2 project compiler."""

from biopipe.version import COMPILER_VERSION

from .compiler import (
    GeneratedProject,
    NextflowCompiler,
    PlannedPipelineLike,
    compile_nextflow_project,
)
from .store import ProjectBundleStore
from .templates import StrictTemplateRenderer, groovy_quote

__version__ = COMPILER_VERSION

__all__ = [
    "GeneratedProject",
    "NextflowCompiler",
    "PlannedPipelineLike",
    "ProjectBundleStore",
    "StrictTemplateRenderer",
    "__version__",
    "compile_nextflow_project",
    "groovy_quote",
]
