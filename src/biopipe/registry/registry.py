"""Read-only access to the reviewed component registry."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from importlib import resources
from pathlib import Path
from types import MappingProxyType

from biopipe.io import read_model
from biopipe.models import LockedComponent, SoftwareLock
from biopipe.registry.models import (
    ArtifactType,
    ComponentDefinition,
    ControlledIntegerParameter,
    RegistryDocument,
)

_DEFAULT_COMPONENT_IDS = frozenset(
    {
        "fastqc_raw_v1",
        "fastp_single_v1",
        "fastp_paired_v1",
        "fastqc_post_trim_v1",
        "multiqc_v1",
    }
)


class RegistryValidationError(ValueError):
    """A stable registry or component-graph validation failure."""


class ComponentRegistry:
    """An immutable lookup facade over a validated registry document."""

    def __init__(self, document: RegistryDocument) -> None:
        self._document = document.model_copy(deep=True)
        self._components: Mapping[str, ComponentDefinition] = MappingProxyType(
            {
                component.component_id: component.model_copy(deep=True)
                for component in sorted(
                    self._document.components,
                    key=lambda item: item.component_id,
                )
            }
        )

    @property
    def version(self) -> str:
        """Return the reviewed registry version used for deterministic generation."""

        return self._document.registry_version

    @property
    def document(self) -> RegistryDocument:
        """Return an isolated copy of the source document."""

        return self._document.model_copy(deep=True)

    @property
    def components(self) -> Mapping[str, ComponentDefinition]:
        """Return components keyed deterministically by component ID."""

        return MappingProxyType(
            {
                component_id: component.model_copy(deep=True)
                for component_id, component in self._components.items()
            }
        )

    def get(self, component_id: str) -> ComponentDefinition:
        """Return one component or fail closed for an unknown ID."""

        try:
            return self._components[component_id].model_copy(deep=True)
        except KeyError as exc:
            raise RegistryValidationError(f"unknown component_id: {component_id}") from exc

    def validate_parameters(
        self,
        component_id: str,
        values: Mapping[str, int],
    ) -> dict[str, int]:
        """Resolve only registered integer parameters and validate their bounds."""

        component = self.get(component_id)
        unknown = sorted(set(values) - set(component.parameters))
        if unknown:
            raise RegistryValidationError(
                f"component {component_id} does not allow parameters: {', '.join(unknown)}"
            )

        resolved: dict[str, int] = {}
        for name, definition in sorted(component.parameters.items()):
            value = values.get(name, definition.default)
            self._validate_parameter_value(component_id, name, definition, value)
            resolved[name] = value
        return resolved

    @staticmethod
    def _validate_parameter_value(
        component_id: str,
        name: str,
        definition: ControlledIntegerParameter,
        value: int,
    ) -> None:
        if isinstance(value, bool) or not isinstance(value, int):
            raise RegistryValidationError(f"parameter {component_id}.{name} must be an integer")
        if not definition.minimum <= value <= definition.maximum:
            raise RegistryValidationError(
                f"parameter {component_id}.{name} must be between "
                f"{definition.minimum} and {definition.maximum}"
            )

    def validate_graph(
        self,
        component_ids: Sequence[str],
        input_type: ArtifactType,
    ) -> tuple[ComponentDefinition, ...]:
        """Validate ordered component compatibility without inventing adapters."""

        if not component_ids:
            raise RegistryValidationError("a component graph must contain at least one component")
        if len(component_ids) != len(set(component_ids)):
            raise RegistryValidationError("a component graph must not contain duplicate nodes")

        available: set[ArtifactType] = {input_type}
        selected: list[ComponentDefinition] = []
        for component_id in component_ids:
            component = self.get(component_id)
            compatible_inputs = available.intersection(component.accepts)
            if not compatible_inputs:
                accepted = ", ".join(component.accepts)
                offered = ", ".join(sorted(available))
                raise RegistryValidationError(
                    f"component {component_id} accepts [{accepted}] but graph provides [{offered}]"
                )
            selected.append(component)
            available.update(component.produces.values())
        return tuple(selected)

    def software_lock(self, component_ids: Sequence[str]) -> SoftwareLock:
        """Build a deterministic tool-level lock for the selected component graph."""

        selected = [self.get(component_id) for component_id in component_ids]
        components: dict[str, LockedComponent] = {}
        for component in selected:
            candidate = LockedComponent(
                version=component.tool.version,
                image=component.container.image,
                digest=component.container.digest,
                license=component.tool.license,
            )
            existing = components.setdefault(component.tool.name, candidate)
            if existing != candidate:
                raise RegistryValidationError(
                    f"selected components disagree on the {component.tool.name} software lock"
                )
        return SoftwareLock(
            components={name: components[name] for name in sorted(components)},
            resolved_at=self._document.released_at,
            resolver_version=f"component-registry/{self.version}",
        )


def load_registry(path: str | Path) -> ComponentRegistry:
    """Load a strict registry document from JSON or YAML."""

    return ComponentRegistry(read_model(path, RegistryDocument))


def load_default_registry() -> ComponentRegistry:
    """Load and self-check the fixed FASTQ-QC component registry."""

    resource = resources.files("biopipe.registry").joinpath("data").joinpath("fastq_qc.v1.yaml")
    with resources.as_file(resource) as path:
        registry = load_registry(path)
    component_ids = set(registry.components)
    if component_ids != _DEFAULT_COMPONENT_IDS:
        missing = sorted(_DEFAULT_COMPONENT_IDS - component_ids)
        unexpected = sorted(component_ids - _DEFAULT_COMPONENT_IDS)
        raise RegistryValidationError(
            f"default registry component set mismatch; missing={missing}, unexpected={unexpected}"
        )

    registry.validate_graph(
        ("fastqc_raw_v1", "multiqc_v1"),
        "single_fastq",
    )
    registry.validate_graph(
        ("fastqc_raw_v1", "multiqc_v1"),
        "paired_fastq",
    )
    registry.validate_graph(
        (
            "fastqc_raw_v1",
            "fastp_single_v1",
            "fastqc_post_trim_v1",
            "multiqc_v1",
        ),
        "single_fastq",
    )
    registry.validate_graph(
        (
            "fastqc_raw_v1",
            "fastp_paired_v1",
            "fastqc_post_trim_v1",
            "multiqc_v1",
        ),
        "paired_fastq",
    )
    return registry


__all__ = [
    "ComponentRegistry",
    "RegistryValidationError",
    "load_default_registry",
    "load_registry",
]
