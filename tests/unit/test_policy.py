"""Tests for the verdict policy."""

from __future__ import annotations

from pathlib import Path

from cancerbero.audit import CheckOptions, run_check
from cancerbero.domain import Confidence, Finding, Severity, Status, Verdict
from cancerbero.policy import evaluate_verdict
from tests.fixtures_factory import write_gguf


def _finding(
    status: Status,
    *,
    check: str = "test",
    mandatory: bool = True,
    confidence: Confidence = Confidence.HIGH,
    severity: Severity = Severity.INFO,
    classification: Confidence = Confidence.HIGH,
) -> Finding:
    return Finding(
        id="cbr.test",
        head="loading",
        check=check,
        status=status,
        severity=severity,
        confidence=confidence,
        classification=classification,
        mandatory=mandatory,
    )


def _core_finding(status: Status, check: str = "gguf_structure") -> Finding:
    """Create a finding for a core check."""
    return _finding(status, check=check)


class TestSuitable:
    def test_no_findings_is_undetermined(self) -> None:
        """No findings at all means we have no evidence → undetermined."""
        verdict, code = evaluate_verdict(())
        # With no findings, core checks are missing → undetermined
        assert verdict is Verdict.UNDETERMINED
        assert code == 2

    def test_all_core_checks_clean(self) -> None:
        """All core checks clean → suitable."""
        findings = (
            _core_finding(Status.CLEAN, "gguf_structure"),
            _core_finding(Status.CLEAN, "chat_template_static"),
            _core_finding(Status.VERIFIED, "runtime_advisory_join"),
        )
        verdict, code = evaluate_verdict(findings)
        assert verdict is Verdict.SUITABLE
        assert code == 0

    def test_optional_unchecked_does_not_block(self) -> None:
        """Non-core unchecked findings don't block if core checks pass."""
        findings = (
            _core_finding(Status.CLEAN, "gguf_structure"),
            _core_finding(Status.CLEAN, "chat_template_static"),
            _core_finding(Status.VERIFIED, "runtime_advisory_join"),
            _finding(Status.UNCHECKED, check="optional_check", mandatory=False),
        )
        verdict, code = evaluate_verdict(findings)
        assert verdict is Verdict.SUITABLE
        assert code == 0


class TestNotSuitable:
    def test_critical_high_classification_blocks(self) -> None:
        """Critical severity + high classification → not suitable."""
        findings = (
            _finding(
                Status.SUSPICIOUS,
                severity=Severity.CRITICAL,
                classification=Confidence.HIGH,
            ),
        )
        verdict, code = evaluate_verdict(findings)
        assert verdict is Verdict.NOT_SUITABLE
        assert code == 1

    def test_critical_medium_classification_blocks(self) -> None:
        """Critical severity + medium classification → not suitable."""
        findings = (
            _finding(
                Status.SUSPICIOUS,
                severity=Severity.CRITICAL,
                classification=Confidence.MEDIUM,
            ),
        )
        verdict, code = evaluate_verdict(findings)
        assert verdict is Verdict.NOT_SUITABLE
        assert code == 1

    def test_high_high_classification_blocks(self) -> None:
        """High severity + high classification → not suitable."""
        findings = (
            _finding(
                Status.SUSPICIOUS,
                severity=Severity.HIGH,
                classification=Confidence.HIGH,
            ),
        )
        verdict, code = evaluate_verdict(findings)
        assert verdict is Verdict.NOT_SUITABLE
        assert code == 1


class TestUndetermined:
    def test_critical_low_classification_undetermined(self) -> None:
        """Critical severity + low classification → undetermined."""
        findings = (
            _finding(
                Status.SUSPICIOUS,
                severity=Severity.CRITICAL,
                classification=Confidence.LOW,
            ),
        )
        verdict, code = evaluate_verdict(findings)
        assert verdict is Verdict.UNDETERMINED
        assert code == 2

    def test_high_medium_classification_undetermined(self) -> None:
        """High severity + medium classification → undetermined."""
        findings = (
            _finding(
                Status.SUSPICIOUS,
                severity=Severity.HIGH,
                classification=Confidence.MEDIUM,
            ),
        )
        verdict, code = evaluate_verdict(findings)
        assert verdict is Verdict.UNDETERMINED
        assert code == 2

    def test_medium_high_classification_undetermined(self) -> None:
        """Medium severity + high classification → undetermined."""
        findings = (
            _finding(
                Status.SUSPICIOUS,
                severity=Severity.MEDIUM,
                classification=Confidence.HIGH,
            ),
        )
        verdict, code = evaluate_verdict(findings)
        assert verdict is Verdict.UNDETERMINED
        assert code == 2

    def test_mandatory_unchecked_produces_undetermined(self) -> None:
        findings = (_finding(Status.UNCHECKED),)
        verdict, code = evaluate_verdict(findings)
        assert verdict is Verdict.UNDETERMINED
        assert code == 2

    def test_mandatory_error_produces_undetermined(self) -> None:
        findings = (_finding(Status.ERROR),)
        verdict, code = evaluate_verdict(findings)
        assert verdict is Verdict.UNDETERMINED
        assert code == 2

    def test_missing_core_check_produces_undetermined(self) -> None:
        """If a core check is missing (unchecked), verdict is undetermined."""
        findings = (
            _core_finding(Status.CLEAN, "gguf_structure"),
            # chat_template_static is missing
            # runtime_advisory_join is missing
        )
        verdict, code = evaluate_verdict(findings)
        assert verdict is Verdict.UNDETERMINED
        assert code == 2

    def test_core_check_error_produces_undetermined(self) -> None:
        """If a core check errors, verdict is undetermined."""
        findings = (
            _core_finding(Status.CLEAN, "gguf_structure"),
            _core_finding(Status.ERROR, "chat_template_static"),
            _core_finding(Status.VERIFIED, "runtime_advisory_join"),
        )
        verdict, code = evaluate_verdict(findings)
        assert verdict is Verdict.UNDETERMINED
        assert code == 2


class TestTemplatedModelSuitable:
    """H1: a parseable chat template must provide positive core-check evidence."""

    def test_templated_model_reaches_suitable(self, tmp_path: Path) -> None:
        """A model with a valid chat template and a safe runtime is SUITABLE."""
        path = write_gguf(
            tmp_path / "model.gguf",
            chat_template=(
                "{% for message in messages %}{{ message['role'] }}: "
                "{{ message['content'] }}\n{% endfor %}"
            ),
        )
        binary = tmp_path / "llama-cli"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        binary.chmod(0o755)
        (tmp_path / "build-info.txt").write_text("build = 9500")

        report = run_check(
            CheckOptions(
                targets=(path,), runtime=binary, runtime_version="9500"
            ),
            command=["test"],
        )
        assert report.verdict is Verdict.SUITABLE
        assert report.exit_code == 0

    def test_templated_model_emits_parsed_finding(self, tmp_path: Path) -> None:
        """A successfully parsed template emits cbr.template.parsed (CLEAN)."""
        path = write_gguf(
            tmp_path / "model.gguf",
            chat_template="{{ bos_token }}{{ message['content'] }}",
        )
        report = run_check(CheckOptions(targets=(path,)), command=["test"])
        parsed = [f for f in report.findings if f.id == "cbr.template.parsed"]
        assert len(parsed) == 1
        assert parsed[0].check == "chat_template_static"
        assert parsed[0].status is Status.CLEAN
        assert parsed[0].severity is Severity.INFO
        assert parsed[0].confidence is Confidence.HIGH
        assert parsed[0].mandatory is False
