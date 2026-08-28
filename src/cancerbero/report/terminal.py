"""User-friendly terminal reporting for Cancerbero."""

from __future__ import annotations

from pathlib import Path

from cancerbero.domain import (
    AuditReport,
    BundleInfo,
    Finding,
    Status,
    Verdict,
    coverage_summary,
)

_VERDICT_LINES = {
    Verdict.SUITABLE: (
        "SUITABLE",
        "No blocking conditions found within the checks performed.",
    ),
    Verdict.NOT_SUITABLE: (
        "NOT SUITABLE",
        "A confirmed risk condition was found. See findings below.",
    ),
    Verdict.UNDETERMINED: (
        "UNDETERMINED",
        "Required evidence was missing or a check could not complete.",
    ),
}


def _truncate(text: str, maximum: int = 80) -> str:
    return text if len(text) <= maximum else text[: maximum - 1] + "…"


def _finding_block(finding: Finding, *, verbose: bool) -> list[str]:
    lines: list[str] = []
    severity = finding.severity.value.upper()
    lines.append(f"  [{severity}] {finding.summary or finding.id}")
    if finding.action:
        lines.append(f"         → {finding.action}")
    if verbose:
        lines.append(f"         Check: {finding.check} ({finding.status.value})")
        if finding.evidence:
            evidence = ", ".join(
                f"{key}={value!r}" for key, value in sorted(finding.evidence.items())
            )
            lines.append(f"         Evidence: {_truncate(evidence, 120)}")
        for reference in sorted(finding.references):
            lines.append(f"         Ref: {reference}")
    return lines


def _render_artifact_summary(report: AuditReport) -> list[str]:
    lines: list[str] = []
    for artifact in report.artifacts:
        name = artifact.name or artifact.path.name
        arch = artifact.architecture or "unknown"
        quants = []
        if artifact.file_type is not None:
            quants.append(f"type={artifact.file_type}")
        if artifact.quantization_version is not None:
            quants.append(f"quant_v{artifact.quantization_version}")
        quant_str = f", {', '.join(quants)}" if quants else ""
        lines.append(
            f"  Artifact : {name}"
            f"  (GGUF v{artifact.gguf_version}, {arch}, "
            f"{artifact.tensor_count} tensors{quant_str})"
        )
        lines.append(f"  File     : {artifact.path}")
        if artifact.has_chat_template:
            tpl_len = len(artifact.chat_template) if artifact.chat_template else 0
            lines.append(f"  Template : present ({tpl_len} chars)")
        else:
            lines.append("  Template : none")
    return lines


def _render_runtime_summary(report: AuditReport) -> list[str]:
    lines: list[str] = []
    for runtime in report.runtimes:
        version_str = runtime.version or (
            f"build {runtime.build}" if runtime.build is not None else "unknown"
        )
        commit_str = f", commit {runtime.commit[:12]}" if runtime.commit else ""
        lines.append(
            f"  Runtime  : {runtime.component} {version_str}{commit_str}"
            f"  ({runtime.detection_method})"
        )
        lines.append(f"  Path     : {runtime.path}")
    return lines


def _render_bundle_info(bundle: BundleInfo | None) -> list[str]:
    if bundle is None:
        return ["  Bundle   : unavailable"]
    lines = [
        f"  Bundle   : {bundle.bundle_version}"
        f"  (digest {bundle.digest_sha256[:16]}…, {bundle.integrity})"
    ]
    # Check bundle freshness
    try:
        from datetime import datetime, timezone

        expires = datetime.fromisoformat(bundle.expires_at.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        days_left = (expires - now).days
        if days_left < 0:
            lines.append(
                f"  ⚠ Bundle expired {abs(days_left)} days ago — advisory coverage is undetermined"
            )
        elif days_left < 30:
            lines.append(f"  ⚠ Bundle expires in {days_left} days — consider updating")
    except (ValueError, AttributeError):
        pass
    return lines


def render_terminal(report: AuditReport, *, verbose: bool = False) -> str:
    """Render a clear, user-friendly assessment."""
    counts = coverage_summary(report.findings)
    verdict_label, verdict_explanation = _VERDICT_LINES[report.verdict]

    lines: list[str] = []

    # Header
    lines.append("")
    lines.append("━" * 60)
    lines.append(f"  Cancerbero — {verdict_label}")
    lines.append(f"  {verdict_explanation}")
    lines.append("━" * 60)
    lines.append("")

    # Targets
    lines.append("TARGETS")
    lines.extend(_render_artifact_summary(report))
    lines.extend(_render_runtime_summary(report))
    lines.extend(_render_bundle_info(report.bundle))
    lines.append("")

    # Suspicious findings (the important stuff)
    blocking = [f for f in report.findings if f.status is Status.SUSPICIOUS]
    if blocking:
        lines.append("⚠  FINDINGS")
        for finding in blocking:
            lines.extend(_finding_block(finding, verbose=verbose))
        lines.append("")

    # Errors — grouped by artifact for clarity
    errors = [f for f in report.findings if f.status is Status.ERROR]
    if errors:
        lines.append("✖  ERRORS")
        # Group errors by artifact path
        by_artifact: dict[str, list[Finding]] = {}
        for finding in errors:
            artifact_path = finding.evidence.get("artifact", "")
            by_artifact.setdefault(artifact_path, []).append(finding)
        for artifact_path, findings in by_artifact.items():
            if artifact_path:
                artifact_name = Path(artifact_path).name
                lines.append("")
                lines.append(f"  ▸ {artifact_name}")
                lines.append(f"    {artifact_path}")
            for finding in findings:
                lines.append("")
                lines.append(f"    ✖ {finding.summary}")
                explanation = finding.evidence.get("explanation")
                if explanation:
                    lines.append(f"      {explanation}")
                origin = finding.evidence.get("origin")
                if origin:
                    lines.append(f"      Likely cause: {origin}")
                if finding.action:
                    lines.append(f"      → {finding.action}")
                if verbose:
                    lines.append(f"      Check: {finding.check} ({finding.status.value})")
        lines.append("")

    # What was not checked (only mandatory unchecked, not informational)
    mandatory_unchecked = [
        f for f in report.findings if f.status is Status.UNCHECKED and f.mandatory
    ]
    if mandatory_unchecked:
        lines.append("?  NOT CHECKED")
        for finding in mandatory_unchecked:
            lines.append(f"  - {finding.summary or finding.id}")
        lines.append("")

    # Informational notes (non-mandatory unchecked, clean, verified, etc.)
    informational = [
        f
        for f in report.findings
        if f.status in {Status.CLEAN, Status.VERIFIED, Status.NOT_APPLICABLE}
        or (f.status is Status.UNCHECKED and not f.mandatory)
    ]
    if informational and verbose:
        lines.append("ℹ  NOTES")
        for finding in informational[:10]:  # cap at 10 to avoid flooding
            lines.append(f"  - {finding.summary or finding.id}")
        if len(informational) > 10:
            lines.append(f"  ... and {len(informational) - 10} more")
        lines.append("")

    # Coverage summary
    lines.append("COVERAGE")
    parts = []
    if counts["verified"]:
        parts.append(f"{counts['verified']} verified")
    if counts["clean"]:
        parts.append(f"{counts['clean']} clean")
    if counts["not_applicable"]:
        parts.append(f"{counts['not_applicable']} not applicable")
    if counts["unchecked"]:
        parts.append(f"{counts['unchecked']} unchecked")
    if counts["error"]:
        parts.append(f"{counts['error']} errors")
    lines.append(f"  {' · '.join(parts) if parts else 'no checks performed'}")
    lines.append("")

    # Hardening recommendations
    if report.hardening_recommendations:
        lines.append("💡 RECOMMENDATIONS")
        # Show critical and high priority first
        critical_high = [
            r for r in report.hardening_recommendations if r.priority in ("critical", "high")
        ]
        medium_low = [
            r for r in report.hardening_recommendations if r.priority in ("medium", "low")
        ]
        for rec in critical_high[:5]:  # Cap at 5
            lines.append(f"  [{rec.priority.upper()}] {rec.title}")
            lines.append(f"    {rec.description}")
            lines.append(f"    → {rec.action}")
            lines.append("")
        if medium_low and verbose:
            for rec in medium_low[:3]:  # Cap at 3
                lines.append(f"  [{rec.priority.upper()}] {rec.title}")
                lines.append(f"    {rec.description}")
                lines.append("")
        lines.append("")

    # Disclaimer
    lines.append("  This is a suitability assessment, not a safety certification.")
    lines.append("  Absence of findings does not prove the artifact is safe.")
    lines.append("")

    return "\n".join(lines)
