"""Tests for the advisory join engine."""

from __future__ import annotations

from pathlib import Path

from cancerbero.domain import (
    AdvisoryRule,
    ArtifactFacts,
    Confidence,
    RuntimeFacts,
    Severity,
    Status,
)
from cancerbero.engine import evaluate_advisories, evaluate_advisory


def _make_rule(
    *,
    rule_id: str = "CVE-TEST-0001",
    component: str = "llama.cpp",
    version_scheme: str = "llama_cpp_build",
    affected: dict | None = None,
    fixed: dict | None = None,
) -> AdvisoryRule:
    return AdvisoryRule(
        id=rule_id,
        title="Test advisory",
        source="https://example.com",
        component=component,
        version_scheme=version_scheme,
        affected=affected or {"lte": 100},
        fixed=fixed or {"gte": 200},
        artifact_predicates=(
            {"field": "format", "operator": "present"},
            {"field": "format", "operator": "equals", "value": "gguf"},
        ),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        explanation="Test explanation.",
        action="Update runtime.",
        published="2026-01-01",
        reviewed="2026-08-27",
    )


def _make_artifact() -> ArtifactFacts:
    return ArtifactFacts(
        path=Path("test.gguf"),
        file_size=1000,
        gguf_version=2,
        tensor_count=0,
        metadata_count=3,
        metadata_end=200,
        tensor_data_offset=256,
        alignment=32,
        architecture="llama",
    )


def _make_runtime(build: int | None = 50) -> RuntimeFacts:
    return RuntimeFacts(
        path=Path("llama-cli"),
        component="llama-cli",
        build=build,
        detection_method="explicit_override",
        confidence=Confidence.HIGH,
    )


class TestAffectedBuild:
    def test_affected_build_produces_suspicious(self) -> None:
        rule = _make_rule(affected={"lte": 100}, fixed={"gte": 200})
        finding = evaluate_advisory(rule, _make_artifact(), _make_runtime(50))
        assert finding.status is Status.SUSPICIOUS
        assert finding.severity is Severity.HIGH


class TestFixedBuild:
    def test_fixed_build_produces_verified(self) -> None:
        rule = _make_rule(affected={"lte": 100}, fixed={"gte": 200})
        finding = evaluate_advisory(rule, _make_artifact(), _make_runtime(200))
        assert finding.status is Status.VERIFIED


class TestUnknownBuild:
    def test_unknown_build_produces_unchecked(self) -> None:
        rule = _make_rule()
        finding = evaluate_advisory(rule, _make_artifact(), _make_runtime(None))
        assert finding.status is Status.UNCHECKED


class TestNotApplicable:
    def test_wrong_format_produces_not_applicable(self) -> None:
        rule = _make_rule()
        runtime = _make_runtime(50)
        finding = evaluate_advisory(rule, None, runtime)
        assert finding.status is Status.NOT_APPLICABLE


class TestComponentMatching:
    def _make_ollama_rule(self) -> AdvisoryRule:
        # CVE-2026-7482: heap out-of-bounds read in the Ollama GGUF loader.
        return _make_rule(
            rule_id="CVE-2026-7482",
            component="ollama",
            version_scheme="semver",
            affected={"lt": "0.17.1"},
            fixed={"gte": "0.17.1"},
        )

    def _make_ollama_runtime(self, version: str) -> RuntimeFacts:
        return RuntimeFacts(
            path=Path("ollama"),
            component="ollama",
            version=version,
            detection_method="explicit_override",
            confidence=Confidence.HIGH,
        )

    def test_ollama_rule_does_not_fire_for_llama_cli_runtime(self) -> None:
        """CVE-2026-7482 must not fire when the detected runtime is llama-cli."""
        rule = self._make_ollama_rule()
        # Affected Ollama version, but the runtime is a llama.cpp binary.
        runtime = RuntimeFacts(
            path=Path("llama-cli"),
            component="llama-cli",
            version="0.16.0",
            detection_method="explicit_override",
            confidence=Confidence.HIGH,
        )
        finding = evaluate_advisory(rule, _make_artifact(), runtime)
        assert finding.status is Status.NOT_APPLICABLE
        assert finding.severity is Severity.INFO

    def test_ollama_rule_does_fire_for_ollama_runtime(self) -> None:
        rule = self._make_ollama_rule()
        finding = evaluate_advisory(rule, _make_artifact(), self._make_ollama_runtime("0.16.0"))
        assert finding.status is Status.SUSPICIOUS
        assert finding.severity is rule.severity

    def test_llama_cli_runtime_is_canonicalized_for_llama_cpp_rule(self) -> None:
        """A llama.cpp advisory still fires for any llama.cpp binary name."""
        rule = _make_rule(affected={"lte": 100}, fixed={"gte": 200})
        finding = evaluate_advisory(rule, _make_artifact(), _make_runtime(50))
        assert finding.status is Status.SUSPICIOUS
        assert finding.severity is Severity.HIGH


class TestGapBetweenAffectedAndFixed:
    def test_gap_produces_unchecked(self) -> None:
        rule = _make_rule(affected={"lt": 100}, fixed={"gte": 200})
        finding = evaluate_advisory(rule, _make_artifact(), _make_runtime(150))
        assert finding.status is Status.UNCHECKED


class TestEvaluateAdvisories:
    def test_multiple_rules_sorted(self) -> None:
        rules = (
            _make_rule(rule_id="CVE-2026-0001", affected={"lte": 50}, fixed={"gte": 100}),
            _make_rule(rule_id="CVE-2024-0001", affected={"lte": 50}, fixed={"gte": 100}),
        )
        findings = evaluate_advisories(_make_artifact(), _make_runtime(25), rules)
        assert findings[0].id < findings[1].id
