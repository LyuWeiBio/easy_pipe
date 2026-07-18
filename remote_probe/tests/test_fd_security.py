"""Focused tests for response and descriptor-traversal security boundaries."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from bioprobe.config import AllowedRoot, load_config
from bioprobe.errors import ProbeFailure, ReturnCode
from bioprobe.paths import AuthorizedStat, OpenedDirectory, PathGuard
from bioprobe.protocol import decode_json_line, encode_response_line
from bioprobe.service import handle_request


def _config(tmp_path: Path, root: Path, *, max_response_bytes: int = 4096) -> Path:
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "allowed_roots": [str(root)],
                "limits": {
                    "max_entries": 100,
                    "max_response_bytes": max_response_bytes,
                },
                "follow_symlinks": False,
            }
        ),
        encoding="utf-8",
    )
    return config


def test_json_nesting_limit_is_deterministic_and_ignores_string_content() -> None:
    accepted = b"[" * 128 + b"0" + b"]" * 128
    assert decode_json_line(accepted) is not None
    assert decode_json_line(json.dumps({"value": "[{" * 1000}).encode()) == {"value": "[{" * 1000}

    with pytest.raises(ProbeFailure) as captured:
        decode_json_line(b"[" * 129 + b"0" + b"]" * 129)

    assert captured.value.return_code == ReturnCode.PROTOCOL_ERROR
    assert captured.value.code == "INVALID_JSON"


@pytest.mark.parametrize("operation", ["list_tree", "stat_files"])
def test_collection_response_limit_returns_bounded_code_30(tmp_path: Path, operation: str) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    files = []
    for index in range(12):
        path = root / f"{index:02d}-{'x' * 80}.txt"
        path.write_text("metadata only", encoding="utf-8")
        files.append(str(path))
    config = load_config(_config(tmp_path, root, max_response_bytes=900))
    request: dict[str, Any] = {
        "protocol_version": "1.0",
        "request_id": f"response-{operation}",
        "operation": operation,
    }
    if operation == "list_tree":
        request["root"] = str(root)
    else:
        request["paths"] = files

    response = handle_request(request, config)

    assert response["success"] is False
    assert response["return_code"] == ReturnCode.BUDGET_EXCEEDED
    assert response["error"]["code"] == "RESPONSE_BUDGET_EXCEEDED"
    assert len(encode_response_line(response)) <= config.limits.max_response_bytes


def test_component_replaced_by_symlink_cannot_redirect_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "allowed"
    victim = root / "victim"
    outside = tmp_path / "outside"
    victim.mkdir(parents=True)
    outside.mkdir()
    config = load_config(_config(tmp_path, root))
    guard = PathGuard(config)
    original = guard._open_allowed_root

    def open_then_swap(allowed_root: AllowedRoot) -> int:
        root_fd = original(allowed_root)
        victim.rename(root / "original-victim")
        victim.symlink_to(outside, target_is_directory=True)
        return root_fd

    monkeypatch.setattr(guard, "_open_allowed_root", open_then_swap)

    with pytest.raises(ProbeFailure) as captured:
        guard.open_directory(str(victim))

    assert captured.value.return_code == ReturnCode.SYMLINK_OR_ESCAPE


def test_config_file_symlink_is_never_followed(tmp_path: Path) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    real_config = _config(tmp_path, root)
    linked_config = tmp_path / "linked-config.json"
    linked_config.symlink_to(real_config)

    with pytest.raises(ProbeFailure) as captured:
        load_config(linked_config)

    assert captured.value.code == "CONFIG_INVALID"


def test_scandir_child_swap_to_symlink_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "allowed"
    victim = root / "victim"
    outside = tmp_path / "outside"
    victim.mkdir(parents=True)
    outside.mkdir()
    (outside / "must-not-appear.txt").write_text("secret", encoding="utf-8")
    config = load_config(_config(tmp_path, root))
    original = PathGuard.stat_child
    swapped = False

    def stat_then_swap(guard: PathGuard, parent: OpenedDirectory, name: str) -> AuthorizedStat:
        nonlocal swapped
        result = original(guard, parent, name)
        if name == "victim" and not swapped:
            victim.rename(root / "original-victim")
            victim.symlink_to(outside, target_is_directory=True)
            swapped = True
        return result

    monkeypatch.setattr(PathGuard, "stat_child", stat_then_swap)
    response = handle_request(
        {
            "protocol_version": "1.0",
            "request_id": "swap-child",
            "operation": "list_tree",
            "root": str(root),
        },
        config,
    )

    assert response["success"] is False
    assert response["return_code"] == ReturnCode.SYMLINK_OR_ESCAPE
    assert b"must-not-appear" not in encode_response_line(response)
