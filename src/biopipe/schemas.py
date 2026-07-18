"""JSON Schema export for the versioned public data contracts."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel

from biopipe.io import write_text_atomic
from biopipe.models import PUBLIC_MODELS


def export_json_schemas(output_dir: str | Path) -> tuple[Path, ...]:
    """Write deterministic JSON Schema documents for every public model."""

    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for model in PUBLIC_MODELS:
        path = destination / f"{model.__name__}.schema.json"
        payload = json.dumps(
            model.model_json_schema(), ensure_ascii=False, indent=2, sort_keys=True
        )
        write_text_atomic(payload + "\n", path)
        written.append(path)
    return tuple(written)


def schema_for(model: type[BaseModel]) -> dict[str, object]:
    """Return a public model's JSON Schema as a plain mapping."""

    return model.model_json_schema()


__all__ = ["export_json_schemas", "schema_for"]
