"""Tests for static chat-template analysis."""

from __future__ import annotations

from cancerbero.template import (
    TemplateReference,
    analyze_chat_template,
    analyze_template,
    compare_template_reference,
)


class TestSafeTemplate:
    def test_simple_template_has_no_evidence(self) -> None:
        template = "Hello {{ name }}, welcome!"
        analysis = analyze_chat_template(template)
        assert analysis.parsed is True
        assert analysis.syntax_error is None
        assert len(analysis.evidence) == 0


class TestRiskyConstructs:
    def test_call_detected(self) -> None:
        template = "{{ some_func() }}"
        analysis = analyze_chat_template(template)
        assert any(e.kind == "call" for e in analysis.evidence)

    def test_import_detected(self) -> None:
        template = "{% import 'other.jinja' as helpers %}{{ helpers.foo() }}"
        analysis = analyze_chat_template(template)
        assert any(e.kind == "template_import" for e in analysis.evidence)

    def test_include_detected(self) -> None:
        template = "{% include 'header.html' %}"
        analysis = analyze_chat_template(template)
        assert any(e.kind == "template_include" for e in analysis.evidence)


class TestSyntaxErrors:
    def test_bad_syntax_produces_error(self) -> None:
        template = "{% if True %}never closed"
        analysis = analyze_chat_template(template)
        assert analysis.parsed is False
        assert analysis.syntax_error is not None


class TestLimits:
    def test_oversized_template_rejected(self) -> None:
        template = "x" * 200
        analysis = analyze_chat_template(template, max_bytes=100)
        assert analysis.limit_exceeded is True


class TestFindings:
    def test_template_with_constructs_produces_findings(self) -> None:
        analysis = analyze_chat_template("{{ func() }}")
        findings = analysis.findings
        # Template with call should produce unchecked findings
        assert len(findings) >= 1

    def test_risky_construct_produces_unchecked_finding(self) -> None:
        analysis = analyze_chat_template("{{ func() }}")
        findings = analysis.findings
        assert any(f.status.value == "unchecked" for f in findings)


class TestReferenceComparison:
    def test_identical_template(self) -> None:
        ref = TemplateReference("llama", "instruct", "3.1", "{{ content }}")
        result = compare_template_reference(
            "{{ content }}", family="llama", variant="instruct", revision="3.1", reference=ref
        )
        assert result.classification == "identical"
        assert result.exact_match is True

    def test_cosmetic_difference(self) -> None:
        ref = TemplateReference("llama", "instruct", "3.1", "{{ content }}")
        result = compare_template_reference(
            "{{  content  }}", family="llama", variant="instruct", revision="3.1", reference=ref
        )
        assert result.classification == "cosmetic"

    def test_incompatible_identity(self) -> None:
        ref = TemplateReference("llama", "instruct", "3.1", "{{ content }}")
        result = compare_template_reference(
            "{{ content }}", family="mistral", variant="instruct", revision="3.1", reference=ref
        )
        assert result.classification == "not_applicable"

    def test_analyze_template_with_reference(self) -> None:
        ref = TemplateReference("llama", "instruct", "3.1", "{{ content }}")
        analysis = analyze_template(
            "{{ content }}",
            family="llama",
            variant="instruct",
            revision="3.1",
            reference=ref,
        )
        assert analysis.comparison is not None
        assert analysis.comparison.classification == "identical"
