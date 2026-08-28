"""PickleScan adapter for optional pickle bytecode analysis."""

from __future__ import annotations

import re
from pathlib import Path

from cancerbero.delegates.base import DEFAULT_LIMITS, DelegateLimits, DelegateResult, DelegateRunner

_FINDING_LINE = re.compile(
    r"^(?P<file>.+?):\s+(?P<kind>dangerous|suspicious)\s+import\s+"
    r"'(?P<import>[^']+)'\s+FOUND\s*$",
    re.IGNORECASE,
)


class PickleScanDelegate(DelegateRunner):
    """Normalize PickleScan's text output and exit-code contract."""

    name = "picklescan"
    command = "picklescan"

    def get_version(self) -> str | None:
        """PickleScan's current CLI does not expose a version option."""

        return None

    def run(
        self,
        target: Path,
        *,
        limits: DelegateLimits = DEFAULT_LIMITS,
        extra_args: list[str] | None = None,
    ) -> DelegateResult:
        """Scan *target*; exit code 1 represents detected imports."""

        if not self.is_available():
            return self._not_available_result()
        args = [self.command, "--path", str(target), "--log", "INFO"]
        if extra_args:
            args.extend(extra_args)
        returncode, stdout, stderr, duration_ms = self._execute(args, limits=limits)

        findings: list[dict[str, object]] = []
        for index, line in enumerate(stdout.splitlines()):
            match = _FINDING_LINE.match(line)
            if match is None:
                continue
            kind = match.group("kind").lower()
            imported = match.group("import")
            findings.append(
                {
                    "id": f"{kind}-import-{index}",
                    "severity": "critical" if kind == "dangerous" else "medium",
                    "message": f"PickleScan found {kind} import: {imported}",
                    "import": imported,
                    "file": match.group("file"),
                }
            )

        # PickleScan uses 0 for clean and 1 for findings. A finding exit without
        # a parseable finding is treated as an adapter error, never as clean.
        parse_error = None
        if returncode == 1 and not findings:
            parse_error = "PickleScan reported findings but emitted no parseable finding records"
        success = returncode in {0, 1} and parse_error is None
        error_text = parse_error
        if returncode not in {0, 1}:
            error_text = stderr.strip() or stdout.strip() or f"PickleScan exited with {returncode}"
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
