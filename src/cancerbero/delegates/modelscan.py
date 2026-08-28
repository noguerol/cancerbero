"""ModelScan adapter for optional multi-framework model scanning."""

from __future__ import annotations

import json
from pathlib import Path

from cancerbero.delegates.base import DEFAULT_LIMITS, DelegateLimits, DelegateResult, DelegateRunner


def _extract_json(output: str) -> dict[str, object]:
    """Extract ModelScan's JSON document after its informational preamble."""

    start = output.find("{")
    end = output.rfind("}")
    if start < 0 or end < start:
        raise ValueError("ModelScan did not emit a JSON document")
    document = json.loads(output[start : end + 1])
    if not isinstance(document, dict):
        raise ValueError("ModelScan JSON root is not an object")
    return document


class ModelScanDelegate(DelegateRunner):
    """Normalize ModelScan JSON and finding exit codes."""

    name = "modelscan"
    command = "modelscan"

    def get_version(self) -> str | None:
        if not self.is_available():
            return None
        returncode, stdout, stderr, _ = self._execute(
            [self.command, "scan", "--version"],
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
        """Scan *target*; exit code 1 represents detected issues."""

        if not self.is_available():
            return self._not_available_result()
        args = [self.command, "scan", "--path", str(target), "--reporting-format", "json"]
        if extra_args:
            args.extend(extra_args)
        returncode, stdout, stderr, duration_ms = self._execute(args, limits=limits)

        findings: list[dict[str, object]] = []
        parse_error: str | None = None
        try:
            document = _extract_json(stdout)
            issues = document.get("issues", [])
            errors = document.get("errors", [])
            if not isinstance(issues, list) or not isinstance(errors, list):
                raise ValueError("ModelScan issues/errors fields must be arrays")
            for index, issue in enumerate(issues):
                if not isinstance(issue, dict):
                    continue
                scanner = str(issue.get("scanner", "modelscan"))
                operator = str(issue.get("operator", index))
                findings.append(
                    {
                        "id": f"{scanner.rsplit('.', 1)[-1]}-{operator}",
                        "severity": str(issue.get("severity", "info")),
                        "message": str(issue.get("description", "ModelScan finding")),
                        "scanner": scanner,
                        "file": str(issue.get("source", "")),
                    }
                )
            if errors:
                parse_error = f"ModelScan reported {len(errors)} scanner error(s)"
        except (json.JSONDecodeError, TypeError, ValueError) as error:
            parse_error = f"Invalid ModelScan JSON output: {error}"

        success = returncode in {0, 1} and parse_error is None
        error_text = parse_error
        if returncode not in {0, 1}:
            error_text = stderr.strip() or f"ModelScan exited with status {returncode}"
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
