"""Fickling adapter for optional pickle safety analysis."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from cancerbero.delegates.base import DEFAULT_LIMITS, DelegateLimits, DelegateResult, DelegateRunner

_SEVERITY_MAP = {
    "LIKELY_OVERTLY_MALICIOUS": "critical",
    "LIKELY_MALICIOUS": "critical",
    "LIKELY_UNSAFE": "high",
    "POSSIBLY_UNSAFE": "medium",
    "SUSPICIOUS": "medium",
}


class FicklingDelegate(DelegateRunner):
    """Normalize Fickling's JSON report and finding exit code."""

    name = "fickling"
    command = "fickling"

    def get_version(self) -> str | None:
        if not self.is_available():
            return None
        returncode, stdout, stderr, _ = self._execute(
            [self.command, "--version"],
            limits=DelegateLimits(timeout_seconds=10, max_output_bytes=16 * 1024),
        )
        if returncode != 0:
            return None
        return (stdout or stderr).strip() or None

    def run(
        self,
        target: Path,
        *,
        limits: DelegateLimits = DEFAULT_LIMITS,
        extra_args: list[str] | None = None,
    ) -> DelegateResult:
        """Scan *target*; exit code 1 represents an unsafe assessment."""

        if not self.is_available():
            return self._not_available_result()

        with tempfile.TemporaryDirectory(prefix="cancerbero-fickling-") as temp_directory:
            report_path = Path(temp_directory) / "report.json"
            args = [
                self.command,
                "--check-safety",
                "--json-output",
                str(report_path),
                str(target),
            ]
            if extra_args:
                args.extend(extra_args)
            returncode, stdout, stderr, duration_ms = self._execute(args, limits=limits)
            try:
                raw_report = report_path.read_text(encoding="utf-8")
                document = json.loads(raw_report)
                if not isinstance(document, dict):
                    raise ValueError("Fickling JSON root is not an object")
                assessment = str(document.get("severity", "UNKNOWN")).upper()
                findings: list[dict[str, object]] = []
                if assessment in _SEVERITY_MAP:
                    findings.append(
                        {
                            "id": assessment.lower().replace("_", "-"),
                            "severity": _SEVERITY_MAP[assessment],
                            "message": str(document.get("analysis", "Fickling safety finding")),
                            "assessment": assessment,
                            "details": document.get("detailed_results", {}),
                        }
                    )
                parse_error = None
            except (OSError, json.JSONDecodeError, TypeError, ValueError) as error:
                findings = []
                parse_error = f"Invalid Fickling JSON report: {error}"

        success = returncode in {0, 1} and parse_error is None
        if returncode == 1 and not findings and parse_error is None:
            success = False
            parse_error = "Fickling reported an unsafe file without a recognized assessment"
        error_text = parse_error
        if returncode not in {0, 1}:
            error_text = stderr.strip() or stdout.strip() or f"Fickling exited with {returncode}"
        return DelegateResult(
            tool=self.name,
            version=self.get_version(),
            available=True,
            success=success,
            findings=findings if success else [],
            raw_output=stdout,
            error=error_text,
            duration_ms=duration_ms,
            telemetry_disabled=True,
        )
