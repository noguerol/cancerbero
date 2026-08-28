"""Markdown report generation for Cancerbero."""

from __future__ import annotations

import re
from pathlib import Path

from cancerbero.domain import (
    AuditReport,
    Status,
    Verdict,
    coverage_summary,
)

# Markdown characters that must be escaped when interpolating untrusted text:
# backslash, pipe, backtick, emphasis, link, and autolink/HTML delimiters.
# Escaping prevents value content from breaking tables, emphasis, links, code
# spans, or inline HTML in the rendered report.
_MD_ESCAPE_RE = re.compile(r"([`|*_\[\]<>\\])")


def _md_escape(text: str) -> str:
    """Escape Markdown-special characters in untrusted text.

    Applied to finding summaries, string evidence values, and any other
    dynamic content before it is interpolated into the report template.
    """
    return _MD_ESCAPE_RE.sub(r"\\\1", text)


def _severity_icon(severity: str) -> str:
    """Return an icon for the severity level."""
    return {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
        "info": "⚪",
    }.get(severity, "⚪")


def _status_icon(status: str) -> str:
    """Return an icon for the status."""
    return {
        "verified": "✅",
        "clean": "✅",
        "suspicious": "⚠️",
        "unchecked": "❓",
        "not_applicable": "➖",
        "error": "❌",
    }.get(status, "❓")


def _verdict_badge(verdict: Verdict) -> str:
    """Return a badge for the verdict."""
    return {
        Verdict.SUITABLE: "![SUITABLE](https://img.shields.io/badge/SUITABLE-green)",
        Verdict.NOT_SUITABLE: "![NOT SUITABLE](https://img.shields.io/badge/NOT%20SUITABLE-red)",
        Verdict.UNDETERMINED: "![UNDETERMINED](https://img.shields.io/badge/UNDETERMINED-yellow)",
    }.get(verdict, "![UNKNOWN](https://img.shields.io/badge/UNKNOWN-gray)")


def render_markdown(report: AuditReport, *, include_observations: bool = False) -> str:
    """Render the report as Markdown suitable for documentation."""
    counts = coverage_summary(report.findings)
    lines: list[str] = []

    # Header
    lines.append("# Cancerbero Audit Report")
    lines.append("")
    lines.append(f"**Verdict:** {report.verdict.value.upper()}")
    lines.append(f"**Version:** {report.cancerbero_version}")
    lines.append(f"**Schema:** {report.schema_version}")
    lines.append("")

    # Disclaimer
    lines.append(
        "> **Note:** This is a suitability assessment for the checks performed, "
        "not a safety certification. Absence of findings does not prove the "
        "artifact is safe."
    )
    lines.append("")

    # Targets section
    lines.append("## Targets")
    lines.append("")

    if report.artifacts:
        lines.append("### Artifacts")
        lines.append("")
        lines.append("| Name | Architecture | Version | Tensors | Template |")
        lines.append("|------|--------------|---------|---------|----------|")
        for artifact in report.artifacts:
            name = _md_escape(artifact.name or artifact.path.name)
            arch = _md_escape(artifact.architecture or "unknown")
            tpl = "present" if artifact.has_chat_template else "none"
            lines.append(
                f"| {name} | {arch} | GGUF v{artifact.gguf_version} | "
                f"{artifact.tensor_count} | {tpl} |"
            )
        lines.append("")

    if report.runtimes:
        lines.append("### Runtimes")
        lines.append("")
        lines.append("| Component | Version | Detection |")
        lines.append("|-----------|---------|-----------|")
        for runtime in report.runtimes:
            version = runtime.version or (
                f"build {runtime.build}" if runtime.build is not None else "unknown"
            )
            lines.append(
                f"| {_md_escape(runtime.component)} | {_md_escape(version)} | "
                f"{_md_escape(runtime.detection_method)} |"
            )
        lines.append("")

    # Findings section
    suspicious = [f for f in report.findings if f.status is Status.SUSPICIOUS]
    errors = [f for f in report.findings if f.status is Status.ERROR]
    unchecked = [f for f in report.findings if f.status is Status.UNCHECKED and f.mandatory]

    if suspicious:
        lines.append("## ⚠️ Findings")
        lines.append("")
        for finding in suspicious:
            icon = _severity_icon(finding.severity.value)
            lines.append(f"### {icon} {_md_escape(finding.summary or finding.id)}")
            lines.append("")
            lines.append(f"- **ID:** `{finding.id}`")
            lines.append(f"- **Severity:** {finding.severity.value}")
            lines.append(f"- **Confidence:** {finding.confidence.value}")
            if finding.action:
                lines.append(f"- **Action:** {_md_escape(finding.action)}")
            if finding.references:
                lines.append("- **References:**")
                for ref in finding.references:
                    lines.append(f"  - {_md_escape(ref)}")
            lines.append("")

    if errors:
        lines.append("## ❌ Errors")
        lines.append("")
        for finding in errors:
            artifact_path = finding.evidence.get("artifact", "")
            if artifact_path:
                artifact_path = str(artifact_path)
                lines.append(f"### {_md_escape(Path(artifact_path).name)}")
                lines.append("")
                lines.append(f"**Path:** `{_md_escape(artifact_path)}`")
            else:
                lines.append(f"### {_md_escape(finding.id)}")
            lines.append("")
            lines.append(f"**Error:** {_md_escape(finding.summary)}")
            explanation = finding.evidence.get("explanation")
            if explanation:
                lines.append(f"**Explanation:** {_md_escape(str(explanation))}")
            origin = finding.evidence.get("origin")
            if origin:
                lines.append(f"**Likely cause:** {_md_escape(str(origin))}")
            lines.append("")

    if unchecked:
        lines.append("## ❓ Not Checked")
        lines.append("")
        for finding in unchecked:
            lines.append(f"- {_md_escape(finding.summary or finding.id)}")
        lines.append("")

    # Coverage section
    lines.append("## Coverage")
    lines.append("")
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
    lines.append(f"{' · '.join(parts) if parts else 'No checks performed'}")
    lines.append("")

    # Bundle info
    if report.bundle:
        lines.append("## Knowledge Bundle")
        lines.append("")
        lines.append(f"- **Version:** {_md_escape(report.bundle.bundle_version)}")
        lines.append(f"- **Digest:** `{_md_escape(report.bundle.digest_sha256[:16])}…`")
        lines.append(f"- **Integrity:** {_md_escape(report.bundle.integrity)}")
        lines.append(f"- **Expires:** {_md_escape(report.bundle.expires_at)}")
        lines.append("")

    # Reproduction section
    lines.append("## Reproduction")
    lines.append("")
    lines.append("```bash")
    lines.append(" ".join(_md_escape(part) for part in report.command))
    lines.append("```")
    lines.append("")

    # Observations (if requested)
    if include_observations and report.observations:
        lines.append("## Observations")
        lines.append("")
        for key, value in sorted(report.observations.items()):
            lines.append(f"- **{_md_escape(key)}:** {_md_escape(str(value))}")
        lines.append("")

    return "\n".join(lines)


__all__ = ["render_markdown"]
