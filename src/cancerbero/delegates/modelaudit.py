"""ModelAudit adapter for broad, optional model-file scanning."""

from __future__ import annotations

import json
from pathlib import Path

from cancerbero.delegates.base import DEFAULT_LIMITS, DelegateLimits, DelegateResult, DelegateRunner


class ModelAuditDelegate(DelegateRunner):
    """Normalize ModelAudit JSON and its documented exit-code contract."""

    name = "modelaudit"
    command = "modelaudit"

    def get_version(self) -> str | None:
        executable = self._command_path()
        if executable is None:
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
        """Scan a local target; exit code 1 means findings, not failure."""

        if not self.is_available():
            return self._not_available_result()
        args = [
            self.command,
            "scan",
            str(target),
            "--format",
            "json",
            "--no-cache",
        ]
        if extra_args:
            args.extend(extra_args)
        returncode, stdout, stderr, duration_ms = self._execute(args, limits=limits)

        findings: list[dict[str, object]] = []
        parse_error: str | None = None
        try:
            document = json.loads(stdout)
            issues = document.get("issues", [])
            if not isinstance(issues, list):
                raise ValueError("ModelAudit JSON field 'issues' is not an array")
            for index, issue in enumerate(issues):
                if not isinstance(issue, dict):
                    continue
                findings.append(
                    {
                        "id": issue.get("rule_code") or issue.get("type") or f"issue-{index}",
                        "severity": str(issue.get("severity", "info")),
                        "message": str(issue.get("message", "ModelAudit finding")),
                        "location": str(issue.get("location", "")),
                        "details": issue.get("details", {}),
                    }
                )
            if document.get("has_errors"):
                parse_error = "ModelAudit reported scanner errors"
        except (json.JSONDecodeError, TypeError, ValueError) as error:
            parse_error = f"Invalid ModelAudit JSON output: {error}"

        # ModelAudit documents: 0 clean, 1 findings, 2 scan error.
        success = returncode in {0, 1} and parse_error is None
        error_text = parse_error
        if returncode not in {0, 1}:
            error_text = stderr.strip() or f"ModelAudit exited with status {returncode}"

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
