"""Tests for configuration hardening recommendations (v0.5 Phase 8).

Based on research from:
- Tech Insider: llama.cpp Tutorial 2026
- Hyperion Consulting: Ollama Enterprise Deployment Guide 2026
- SitePoint: Local LLM Security Best Practices 2026
- Medium: 4 llama.cpp Settings That Matter
- SentinelOne: CVE-2026-27940 Analysis
- daily.dev: Running LLMs Locally in 2026
"""

from __future__ import annotations

from pathlib import Path

from cancerbero.domain import Confidence, Finding, Severity, Status
from cancerbero.hardening import (
    HardeningRecommendation,
    generate_hardening_recommendations,
)


class TestHardeningRecommendations:
    """Test hardening recommendation generation."""

    def test_clean_findings_produce_general_recommendations(self) -> None:
        """Clean findings should produce general recommendations."""
        findings = (
            Finding(
                id="cbr.gguf.parsed",
                head="loading",
                check="gguf_structure",
                status=Status.CLEAN,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                summary="GGUF file parsed successfully.",
            ),
        )
        recommendations = generate_hardening_recommendations(findings)
        assert len(recommendations) >= 2  # At least general recommendations

    def test_vulnerable_runtime_produces_critical_recommendation(self) -> None:
        """A vulnerable runtime should produce a critical recommendation."""
        findings = (
            Finding(
                id="cbr.join.CVE-2026-27940",
                head="loading",
                check="runtime_advisory_join",
                status=Status.SUSPICIOUS,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                summary="Vulnerable runtime",
            ),
        )
        recommendations = generate_hardening_recommendations(findings)
        critical = [r for r in recommendations if r.priority == "critical"]
        assert len(critical) >= 1
        assert any("update" in r.title.lower() for r in critical)

    def test_network_access_produces_high_recommendation(self) -> None:
        """Network access should produce a high recommendation."""
        findings = ()
        recommendations = generate_hardening_recommendations(
            findings,
            has_network_access=True,
        )
        high = [r for r in recommendations if r.priority == "high"]
        assert len(high) >= 1
        assert any("network" in r.title.lower() for r in high)

    def test_api_key_in_args_produces_high_recommendation(self) -> None:
        """API key in arguments should produce a high recommendation."""
        findings = (
            Finding(
                id="cbr.runtime_config.api_key_in_args",
                head="loading",
                check="runtime_config_security",
                status=Status.SUSPICIOUS,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                summary="API key in command line",
            ),
        )
        recommendations = generate_hardening_recommendations(findings)
        high = [r for r in recommendations if r.priority == "high"]
        assert len(high) >= 1
        assert any("api" in r.title.lower() or "environment" in r.title.lower() for r in high)

    def test_dangerous_template_produces_critical_recommendation(self) -> None:
        """A dangerous template should produce a critical recommendation."""
        findings = (
            Finding(
                id="cbr.template.poison.dangerous_function",
                head="loading",
                check="template_poison_detection",
                status=Status.SUSPICIOUS,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                summary="Dangerous function in template",
            ),
        )
        recommendations = generate_hardening_recommendations(findings)
        critical = [r for r in recommendations if r.priority == "critical"]
        assert len(critical) >= 1
        assert any("template" in r.title.lower() for r in critical)

    def test_pickle_deserialization_produces_critical_recommendation(self) -> None:
        """Pickle deserialization should produce a critical recommendation."""
        findings = (
            Finding(
                id="cbr.config.companion_security_pickle_deserialization",
                head="loading",
                check="companion_config",
                status=Status.SUSPICIOUS,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                summary="Pickle deserialization detected",
            ),
        )
        recommendations = generate_hardening_recommendations(findings)
        critical = [r for r in recommendations if r.priority == "critical"]
        assert len(critical) >= 1
        assert any("pickle" in r.title.lower() for r in critical)

    def test_hardening_recommendation_has_required_fields(self) -> None:
        """Hardening recommendations should have all required fields."""
        findings = ()
        recommendations = generate_hardening_recommendations(findings)
        for rec in recommendations:
            assert isinstance(rec, HardeningRecommendation)
            assert rec.category
            assert rec.priority in ("critical", "high", "medium", "low")
            assert rec.title
            assert rec.description
            assert rec.action
            assert isinstance(rec.references, list)


class TestHardeningIntegration:
    """Integration tests for hardening recommendations."""

    def test_recommendations_included_in_report(self, tmp_path: Path) -> None:
        """Hardening recommendations should be included in the report."""
        from cancerbero.audit import CheckOptions, run_check
        from tests.fixtures_factory import write_gguf

        path = write_gguf(tmp_path / "model.gguf")
        options = CheckOptions(targets=(path,))
        report = run_check(options, command=["test"])

        # Should have hardening recommendations
        assert report.hardening_recommendations is not None
        assert len(report.hardening_recommendations) >= 2  # At least general recommendations

    def test_recommendations_have_correct_types(self, tmp_path: Path) -> None:
        """Hardening recommendations should have correct types."""
        from cancerbero.audit import CheckOptions, run_check
        from tests.fixtures_factory import write_gguf

        path = write_gguf(tmp_path / "model.gguf")
        options = CheckOptions(targets=(path,))
        report = run_check(options, command=["test"])

        for rec in report.hardening_recommendations:
            assert isinstance(rec, HardeningRecommendation)
            assert rec.priority in ("critical", "high", "medium", "low")
