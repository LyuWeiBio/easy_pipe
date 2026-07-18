"""Strict contracts for reviewed workflow components and their registry."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import PurePosixPath
from typing import Literal

from pydantic import Field, field_validator, model_validator

from biopipe.models import StrictModel

RegistrySchemaVersion = Literal["1.0"]
ComponentSchemaVersion = Literal["1.0"]
ArtifactType = Literal[
    "single_fastq",
    "paired_fastq",
    "trimmed_single_fastq",
    "trimmed_paired_fastq",
    "fastqc_reports",
    "fastp_reports",
    "multiqc_report",
]

_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_SEMVER_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_CLI_FLAG_PATTERN = re.compile(r"^--[a-z][a-z0-9_-]*$")
_PINNED_VERSION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
_TAGGED_IMAGE_PATTERN = re.compile(
    r"^[a-z0-9.-]+(?::[0-9]+)?(?:/[a-z0-9._-]+)+:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$"
)


def _identifier(value: str, field_name: str) -> str:
    if not _IDENTIFIER_PATTERN.fullmatch(value):
        raise ValueError(f"{field_name} must be a safe identifier")
    return value


def _pinned_image(value: str) -> str:
    if not _TAGGED_IMAGE_PATTERN.fullmatch(value):
        raise ValueError("container image must be a safe tagged OCI reference")
    if "@" in value:
        raise ValueError("container image and digest must be stored separately")
    final_segment = value.rsplit("/", maxsplit=1)[-1]
    if ":" not in final_segment:
        raise ValueError("container images require an explicit versioned tag")
    tag = final_segment.rsplit(":", maxsplit=1)[-1]
    if not tag or tag.casefold() == "latest":
        raise ValueError("container images must not use the latest tag")
    return value


class ComponentTool(StrictModel):
    """Pinned, reviewed software identity used by one or more components."""

    name: str
    version: str
    license: str

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        return _identifier(value, "tool.name")

    @field_validator("version")
    @classmethod
    def validate_version(cls, value: str) -> str:
        if (
            not value
            or value.casefold() == "latest"
            or not _PINNED_VERSION_PATTERN.fullmatch(value)
        ):
            raise ValueError("tool.version must be a pinned version")
        return value

    @field_validator("license")
    @classmethod
    def validate_license(cls, value: str) -> str:
        if not value or any(ord(character) < 32 for character in value):
            raise ValueError("tool.license must be reviewed text")
        return value


class ControlledIntegerParameter(StrictModel):
    """One allowlisted integer mapped to a single reviewed CLI flag."""

    type: Literal["integer"] = "integer"
    cli_flag: str
    default: int = Field(strict=True)
    minimum: int = Field(strict=True)
    maximum: int = Field(strict=True)

    @field_validator("cli_flag")
    @classmethod
    def validate_cli_flag(cls, value: str) -> str:
        if not _CLI_FLAG_PATTERN.fullmatch(value):
            raise ValueError("cli_flag must be one long option without a value or shell syntax")
        return value

    @model_validator(mode="after")
    def validate_bounds(self) -> ControlledIntegerParameter:
        if not self.minimum <= self.default <= self.maximum:
            raise ValueError("parameter bounds must satisfy minimum <= default <= maximum")
        return self


class ComponentResources(StrictModel):
    """Reviewed default resource request for a component."""

    cpus: int = Field(ge=1, le=1_024, strict=True)
    memory_gb: int = Field(ge=1, le=16_384, strict=True)


class ComponentContainer(StrictModel):
    """A tagged image plus its immutable registry digest."""

    image: str
    digest: str

    @field_validator("image")
    @classmethod
    def validate_image(cls, value: str) -> str:
        return _pinned_image(value)

    @field_validator("digest")
    @classmethod
    def validate_digest(cls, value: str) -> str:
        if not _DIGEST_PATTERN.fullmatch(value):
            raise ValueError("container digest must be a lowercase sha256 digest")
        if value == f"sha256:{'0' * 64}":
            raise ValueError("container digest must not be an all-zero placeholder")
        return value

    @property
    def immutable_reference(self) -> str:
        """Return the OCI reference used by generated workflow processes."""

        repository = self.image.rsplit(":", maxsplit=1)[0]
        return f"{repository}@{self.digest}"


class ComponentTemplate(StrictModel):
    """Allowlisted compiler template identity and repository-relative path."""

    key: str
    nextflow: str

    @field_validator("key")
    @classmethod
    def validate_key(cls, value: str) -> str:
        return _identifier(value, "template.key")

    @field_validator("nextflow")
    @classmethod
    def validate_nextflow_path(cls, value: str) -> str:
        path = PurePosixPath(value)
        if path.is_absolute() or ".." in path.parts or path.suffix != ".j2":
            raise ValueError("template.nextflow must be a safe relative .j2 path")
        if not value.startswith("templates/components/"):
            raise ValueError("component templates must stay below templates/components")
        return str(path)


class ComponentDefinition(StrictModel):
    """A reviewed, versioned component that cannot accept arbitrary CLI text."""

    component_schema_version: ComponentSchemaVersion = "1.0"
    component_id: str
    tool: ComponentTool
    accepts: tuple[ArtifactType, ...] = Field(min_length=1)
    produces: dict[str, ArtifactType] = Field(min_length=1)
    parameters: dict[str, ControlledIntegerParameter] = Field(default_factory=dict)
    resources: ComponentResources
    container: ComponentContainer
    template: ComponentTemplate

    @field_validator("component_id")
    @classmethod
    def validate_component_id(cls, value: str) -> str:
        return _identifier(value, "component_id")

    @field_validator("accepts")
    @classmethod
    def validate_accepts(cls, values: tuple[ArtifactType, ...]) -> tuple[ArtifactType, ...]:
        if len(values) != len(set(values)):
            raise ValueError("component accepts must not contain duplicates")
        return values

    @field_validator("produces", "parameters")
    @classmethod
    def validate_mapping_keys(cls, values: dict[str, object]) -> dict[str, object]:
        for key in values:
            _identifier(key, "component mapping key")
        return values


class RegistryDocument(StrictModel):
    """The complete reviewed component registry loaded from one artifact."""

    registry_schema_version: RegistrySchemaVersion = "1.0"
    registry_version: str
    released_at: datetime
    components: tuple[ComponentDefinition, ...] = Field(min_length=1)

    @field_validator("registry_version")
    @classmethod
    def validate_registry_version(cls, value: str) -> str:
        if not _SEMVER_PATTERN.fullmatch(value):
            raise ValueError("registry_version must be semantic version x.y.z")
        return value

    @field_validator("released_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("released_at must include a timezone")
        return value

    @model_validator(mode="after")
    def validate_components(self) -> RegistryDocument:
        component_ids = [component.component_id for component in self.components]
        if len(component_ids) != len(set(component_ids)):
            raise ValueError("component_id values must be unique within a registry")

        tool_locks: dict[str, tuple[ComponentTool, ComponentContainer]] = {}
        for component in self.components:
            candidate = component.tool, component.container
            existing = tool_locks.setdefault(component.tool.name, candidate)
            if existing != candidate:
                raise ValueError(
                    "components for the same tool must share version, license, image, and digest"
                )
        return self


__all__ = [
    "ArtifactType",
    "ComponentContainer",
    "ComponentDefinition",
    "ComponentResources",
    "ComponentTemplate",
    "ComponentTool",
    "ControlledIntegerParameter",
    "RegistryDocument",
]
