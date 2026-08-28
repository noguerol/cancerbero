"""Tests for report format outputs."""

from __future__ import annotations

import json
from pathlib import Path

from cancerbero.domain import (
    AuditReport,
    Confidence,
    Finding,
    Severity,
    Status,
    Target,
    TargetKind,
    Verdict,
)
from cancerbero.report import canonical_json, render_markdown, render_sarif, render_terminal


def _make_report() -> AuditReport:
    """Create a test report with various finding types."""
    return AuditReport(
        schema_version="1.0",
        cancerbero_version="0.1.0",
        command=["cancerbero", "check", "model.gguf"],
        targets=[Target(Path("model.gguf"), TargetKind.GGUF, "magic")],
        artifacts=[],
        runtimes=[],
        findings=[
            Finding(
                id="cbr.test.suspicious",
                head="loading",
                check="test",
                status=Status.SUSPICIOUS,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                summary="Test suspicious finding",
                action="Update runtime",
                references=["https://example.com"],
            ),
            Finding(
                id="cbr.test.error",
                head="loading",
                check="test",
                status=Status.ERROR,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                summary="Test error",
                evidence={"artifact": "/path/to/model.gguf", "explanation": "Test explanation"},
            ),
            Finding(
                id="cbr.test.unchecked",
                head="loading",
                check="test",
                status=Status.UNCHECKED,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                summary="Test unchecked",
                mandatory=True,
            ),
        ],
        bundle=None,
        verdict=Verdict.NOT_SUITABLE,
        exit_code=1,
    )


class TestMarkdownFormat:
    def test_markdown_contains_sections(self) -> None:
        report = _make_report()
        md = render_markdown(report)
        assert "# Cancerbero Audit Report" in md
        assert "## Targets" in md
        assert "## ⚠️ Findings" in md
        assert "## ❌ Errors" in md
        assert "## ❓ Not Checked" in md
        assert "## Coverage" in md
        assert "## Reproduction" in md

    def test_markdown_contains_verdict(self) -> None:
        report = _make_report()
        md = render_markdown(report)
        assert "NOT_SUITABLE" in md or "NOT SUITABLE" in md

    def test_markdown_contains_finding_details(self) -> None:
        report = _make_report()
        md = render_markdown(report)
        assert "Test suspicious finding" in md
        assert "Update runtime" in md
        assert "https://example.com" in md

    def test_markdown_contains_error_explanation(self) -> None:
        report = _make_report()
        md = render_markdown(report)
        assert "Test explanation" in md


class TestSarifFormat:
    def test_sarif_is_valid_json(self) -> None:
        report = _make_report()
        sarif = render_sarif(report)
        data = json.loads(sarif)
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1

    def test_sarif_contains_tool_info(self) -> None:
        report = _make_report()
        sarif = render_sarif(report)
        data = json.loads(sarif)
        driver = data["runs"][0]["tool"]["driver"]
        assert driver["name"] == "Cancerbero"
        assert driver["version"] == "0.1.0"

    def test_sarif_contains_results(self) -> None:
        report = _make_report()
        sarif = render_sarif(report)
        data = json.loads(sarif)
        results = data["runs"][0]["results"]
        assert len(results) >= 1  # At least the suspicious finding

    def test_sarif_contains_rules(self) -> None:
        report = _make_report()
        sarif = render_sarif(report)
        data = json.loads(sarif)
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) >= 1


class TestTerminalFormat:
    def test_terminal_has_verdict(self) -> None:
        report = _make_report()
        text = render_terminal(report)
        assert "NOT SUITABLE" in text

    def test_terminal_has_findings(self) -> None:
        report = _make_report()
        text = render_terminal(report)
        assert "Test suspicious finding" in text

    def test_terminal_has_errors(self) -> None:
        report = _make_report()
        text = render_terminal(report)
        assert "Test error" in text

    def test_terminal_has_coverage(self) -> None:
        report = _make_report()
        text = render_terminal(report)
        assert "COVERAGE" in text


class TestJsonFormat:
    def test_json_is_deterministic(self) -> None:
        report = _make_report()
        j1 = canonical_json(report)
        j2 = canonical_json(report)
        assert j1 == j2

    def test_json_excludes_observations_by_default(self) -> None:
        report = _make_report()
        report.observations = {"test": "value"}
        j = canonical_json(report)
        data = json.loads(j)
        assert "observations" not in data

    def test_json_includes_observations_when_requested(self) -> None:
        report = _make_report()
        report.observations = {"test": "value"}
        j = canonical_json(report, include_observations=True)
        data = json.loads(j)
        assert data["observations"]["test"] == "value"
