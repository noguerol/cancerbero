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
from cancerbero.report import canonical_json, render_markdown, render_terminal


def make_report() -> AuditReport:
    return AuditReport(
        schema_version="1.0",
        cancerbero_version="0.1.0",
        command=["cancerbero", "check", "model.gguf"],
        targets=[Target(Path("model.gguf"), TargetKind.GGUF, "magic")],
        artifacts=[],
        runtimes=[],
        findings=[
            Finding(
                id="cbr.identity.digest_absent",
                head="provenance",
                check="expected_digest",
                status=Status.UNCHECKED,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                summary="No expected digest was supplied.",
                mandatory=True,
            )
        ],
        bundle=None,
        verdict=Verdict.SUITABLE,
        exit_code=0,
    )


def test_json_is_stable_and_has_no_observations() -> None:
    report = make_report()
    report.observations = {"duration_seconds": 1.2}
    assert canonical_json(report) == canonical_json(report)
    assert "duration_seconds" not in canonical_json(report)


def test_terminal_has_fixed_coverage_sections_and_disclaimer() -> None:
    text = render_terminal(make_report())
    assert "not a safety certification" in text
    assert "NOT CHECKED" in text
    assert "PASS" not in text
    assert "SUITABLE" in text
    assert "COVERAGE" in text
    assert "unchecked" in text


def test_markdown_escapes_untrusted_finding_summary_and_evidence() -> None:
    """Markdown-significant characters in findings must be escaped."""
    report = make_report()
    report.findings = [
        Finding(
            id="cbr.test.summary_escape",
            head="loading",
            check="test_escape",
            status=Status.SUSPICIOUS,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            summary="model name bad|pipe with *emphasis* and [link] <tag>",
        ),
        Finding(
            id="cbr.test.evidence_escape",
            head="loading",
            check="test_escape",
            status=Status.ERROR,
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            summary="evidence injection check",
            evidence={"explanation": "evidence value bad|pipe and *emphasis*"},
        ),
    ]
    text = render_markdown(report)
    # Escaped forms are present.
    assert r"bad\|pipe" in text
    assert r"\*emphasis\*" in text
    assert r"\[link\]" in text
    assert r"\<tag\>" in text
    # Raw Markdown-significant forms must not survive.
    assert "bad|pipe" not in text
    assert "*emphasis*" not in text
    assert "[link]" not in text
    assert "<tag>" not in text
