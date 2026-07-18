"""Strict, deterministic rendering for reviewed Nextflow templates."""

from __future__ import annotations

from jinja2 import Environment, PackageLoader, StrictUndefined, TemplateNotFound
from jinja2.exceptions import TemplateError

from biopipe.errors import BioPipeError, ErrorCode


def groovy_quote(value: str) -> str:
    """Return one safely escaped Groovy single-quoted string literal."""

    if not value or any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise BioPipeError(
            ErrorCode.VALIDATION_FAILED,
            "A generated Groovy string contains unsupported characters.",
        )
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    return f"'{escaped}'"


class StrictTemplateRenderer:
    """Render only fixed template names with ``StrictUndefined`` enabled."""

    def __init__(self) -> None:
        self._environment = Environment(
            loader=PackageLoader("biopipe.compiler", "_templates"),
            autoescape=False,
            undefined=StrictUndefined,
            keep_trailing_newline=True,
            lstrip_blocks=True,
            trim_blocks=True,
        )
        self._environment.filters["groovy_quote"] = groovy_quote

    def render(self, template_name: str, context: dict[str, object]) -> bytes:
        """Render one fixed template to normalized UTF-8 bytes."""

        try:
            template = self._environment.get_template(template_name)
            text = template.render(**context)
        except (OSError, TemplateError, TemplateNotFound) as exc:
            raise BioPipeError(
                ErrorCode.ARTIFACT_WRITE_FAILED,
                "A reviewed Nextflow template could not be rendered.",
                context={"template": template_name},
            ) from exc
        normalized = text.replace("\r\n", "\n").replace("\r", "\n")
        if not normalized.endswith("\n"):
            normalized += "\n"
        return normalized.encode("utf-8")


__all__ = ["StrictTemplateRenderer", "groovy_quote"]
