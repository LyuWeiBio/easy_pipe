"""Controlled remote-execution models, transport, deployment, and approval API."""

from biopipe.execution.client import ExecutionOperation, OpenSSHExecutionClient
from biopipe.execution.deploy import DeploymentBundle, DeploymentFile, build_deployment_bundle
from biopipe.execution.gate import ApprovalGate, assert_resume_compatible
from biopipe.execution.models import (
    AllowedExecutionRoots,
    ApprovalArtifactPaths,
    ApprovalInputs,
    ApprovalRequest,
    ApprovalSigner,
    AuthorizationArtifactHashes,
    ContainerArtifact,
    CoreArtifactHashes,
    DiskThreshold,
    ExecutionPathMapping,
    ExecutionProfile,
    LocalExecutionRuntime,
    PreflightCheck,
    PreflightEvidence,
    PreflightReport,
    RunAuthorization,
    RunPolicy,
    compute_input_set_hash,
    compute_project_hash,
)
from biopipe.execution.profiles import ExecutionProfileRegistry
from biopipe.execution.reports import ReconciliationReport, RunReport, StatusReport

__all__ = [
    "AllowedExecutionRoots",
    "ApprovalArtifactPaths",
    "ApprovalGate",
    "ApprovalInputs",
    "ApprovalRequest",
    "ApprovalSigner",
    "AuthorizationArtifactHashes",
    "ContainerArtifact",
    "CoreArtifactHashes",
    "DeploymentBundle",
    "DeploymentFile",
    "DiskThreshold",
    "ExecutionOperation",
    "ExecutionPathMapping",
    "ExecutionProfile",
    "ExecutionProfileRegistry",
    "LocalExecutionRuntime",
    "OpenSSHExecutionClient",
    "PreflightCheck",
    "PreflightEvidence",
    "PreflightReport",
    "ReconciliationReport",
    "RunAuthorization",
    "RunPolicy",
    "RunReport",
    "StatusReport",
    "assert_resume_compatible",
    "build_deployment_bundle",
    "compute_input_set_hash",
    "compute_project_hash",
]
