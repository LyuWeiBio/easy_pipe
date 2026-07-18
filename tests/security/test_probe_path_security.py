"""Path and filename security boundaries for the Remote Probe."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest


def _list_request(root: str, request_id: str = "tree-security") -> str:
    return (
        json.dumps(
            {
                "protocol_version": "1.0",
                "request_id": request_id,
                "operation": "list_tree",
                "root": root,
                "policy": {
                    "inspection_level": "metadata_only",
                    "max_depth": 6,
                    "max_entries": 100,
                    "follow_symlinks": False,
                },
            }
        )
        + "\n"
    )


def test_path_outside_allowlist_is_rejected(
    tmp_path: Path,
    allowed_root: Path,
    probe_config: Path,
    invoke_probe: Callable[[Path, str, Path], tuple[dict[str, Any], object]],
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "must-not-leak.txt").write_text("outside secret", encoding="utf-8")

    response, completed = invoke_probe(probe_config, _list_request(str(outside)), tmp_path)

    assert response["success"] is False
    assert response["return_code"] == 20
    assert "must-not-leak" not in json.dumps(response)
    assert "outside secret" not in completed.stdout


def test_parent_traversal_is_rejected(
    tmp_path: Path,
    allowed_root: Path,
    probe_config: Path,
    invoke_probe: Callable[[Path, str, Path], tuple[dict[str, Any], object]],
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    traversal = str(allowed_root / ".." / outside.name)

    response, _ = invoke_probe(probe_config, _list_request(traversal), tmp_path)

    assert response["success"] is False
    assert response["return_code"] in {20, 22}


def test_symlink_escape_is_rejected(
    tmp_path: Path,
    allowed_root: Path,
    probe_config: Path,
    invoke_probe: Callable[[Path, str, Path], tuple[dict[str, Any], object]],
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    link = allowed_root / "escape-link"
    link.symlink_to(outside, target_is_directory=True)

    response, _ = invoke_probe(probe_config, _list_request(str(link)), tmp_path)

    assert response["success"] is False
    assert response["return_code"] == 22


def test_list_tree_rejects_nested_symlink_entry(
    tmp_path: Path,
    allowed_root: Path,
    probe_config: Path,
    invoke_probe: Callable[[Path, str, Path], tuple[dict[str, Any], object]],
) -> None:
    target = allowed_root / "target.txt"
    target.write_text("synthetic", encoding="utf-8")
    (allowed_root / "nested-link").symlink_to(target)

    response, _ = invoke_probe(
        probe_config,
        _list_request(str(allowed_root)),
        tmp_path,
    )

    assert response["success"] is False
    assert response["return_code"] == 22


def test_command_like_filename_is_metadata_not_code(
    tmp_path: Path,
    allowed_root: Path,
    probe_config: Path,
    invoke_probe: Callable[[Path, str, Path], tuple[dict[str, Any], object]],
) -> None:
    command_like_name = "$(touch PROBE_PWNED)"
    content = "SYNTHETIC_FILE_CONTENT_MUST_NOT_LEAK"
    (allowed_root / command_like_name).write_text(content, encoding="utf-8")
    marker = tmp_path / "PROBE_PWNED"

    response, completed = invoke_probe(
        probe_config,
        _list_request(str(allowed_root)),
        tmp_path,
    )

    assert response["success"] is True
    assert command_like_name in completed.stdout
    assert content not in completed.stdout
    assert not marker.exists()


@pytest.mark.parametrize("link_name", ["inside-file-link", "inside-directory-link"])
def test_symlinks_are_rejected_even_when_target_stays_inside_allowlist(
    tmp_path: Path,
    allowed_root: Path,
    probe_config: Path,
    invoke_probe: Callable[[Path, str, Path], tuple[dict[str, Any], object]],
    link_name: str,
) -> None:
    target = allowed_root / "target"
    if link_name.endswith("directory-link"):
        target.mkdir()
    else:
        target.write_text("synthetic", encoding="utf-8")
    link = allowed_root / link_name
    link.symlink_to(target, target_is_directory=target.is_dir())

    response, _ = invoke_probe(probe_config, _list_request(str(link)), tmp_path)

    assert response["success"] is False
    assert response["return_code"] == 22
