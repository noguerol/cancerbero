"""Tests for JSON stability and determinism (task 74)."""

from __future__ import annotations

import json
from pathlib import Path

from cancerbero.audit import CheckOptions, run_check
from cancerbero.report import canonical_json
from tests.fixtures_factory import write_gguf


class TestJsonStability:
    """Task 74: Same artifact, config, and bundle should produce identical canonical JSON."""

    def test_same_input_produces_identical_json(self, tmp_path: Path) -> None:
        """Running the same check twice should produce byte-identical JSON."""
        path = write_gguf(tmp_path / "model.gguf")
        options = CheckOptions(targets=(path,))
        report1 = run_check(options, command=["cancerbero", "check", str(path)])
        report2 = run_check(options, command=["cancerbero", "check", str(path)])
        json1 = canonical_json(report1)
        json2 = canonical_json(report2)
        assert json1 == json2

    def test_json_has_no_timestamp_fields(self, tmp_path: Path) -> None:
        """The canonical JSON should not contain timestamp or date fields."""
        path = write_gguf(tmp_path / "model.gguf")
        options = CheckOptions(targets=(path,))
        report = run_check(options, command=["cancerbero", "check", str(path)])
        json_str = canonical_json(report)
        data = json.loads(json_str)
        # Check that there are no timestamp fields at the top level
        # Note: "runtimes" is a valid field, not a temporal field
        temporal_keywords = ("timestamp", "created_at", "updated_at", "date")
        for key in data:
            for keyword in temporal_keywords:
                assert keyword not in key.lower(), f"Unexpected temporal field: {key}"

    def test_json_is_valid_json(self, tmp_path: Path) -> None:
        """The canonical JSON should be valid JSON."""
        path = write_gguf(tmp_path / "model.gguf")
        options = CheckOptions(targets=(path,))
        report = run_check(options, command=["cancerbero", "check", str(path)])
        json_str = canonical_json(report)
        data = json.loads(json_str)
        assert isinstance(data, dict)

    def test_json_has_required_fields(self, tmp_path: Path) -> None:
        """The canonical JSON should have all required fields."""
        path = write_gguf(tmp_path / "model.gguf")
        options = CheckOptions(targets=(path,))
        report = run_check(options, command=["cancerbero", "check", str(path)])
        json_str = canonical_json(report)
        data = json.loads(json_str)
        required_fields = [
            "schema_version",
            "cancerbero_version",
            "command",
            "targets",
            "artifacts",
            "findings",
            "verdict",
            "exit_code",
            "coverage",
            "limitations",
        ]
        for field in required_fields:
            assert field in data, f"Missing required field: {field}"

    def test_json_verdict_is_string(self, tmp_path: Path) -> None:
        """The verdict in JSON should be a string, not an enum."""
        path = write_gguf(tmp_path / "model.gguf")
        options = CheckOptions(targets=(path,))
        report = run_check(options, command=["cancerbero", "check", str(path)])
        json_str = canonical_json(report)
        data = json.loads(json_str)
        assert isinstance(data["verdict"], str)
        assert data["verdict"] in ("suitable", "not_suitable", "undetermined")
