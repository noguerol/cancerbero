"""Runtime configuration security analysis (v0.5 Phase 5).

Detects security issues in llama.cpp runtime configuration files and flags.

Based on research from:
- CVE-2026-27940: Integer overflow in gguf_init_from_file_impl
- CVE-2026-21869: Negative parameter triggers OOB write
- CVE-2026-2069: Stack-based buffer overflow in GBNF grammar handler
- CVE-2026-43631: llama.cpp builds b7492-b9060 vulnerabilities
- oss-security 2026-05-15: Six GGUF parser weaknesses
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from cancerbero.domain import Confidence, Finding, Severity, Status

# Patterns that indicate dangerous runtime configuration
# Conservative: only high-signal patterns that directly affect security
_DANGEROUS_RUNTIME_PATTERNS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    # --- Network exposure ---
    # --host 0.0.0.0: Binds to all interfaces
    (
        re.compile(r"--host\s+0\.0\.0\.0", re.IGNORECASE),
        "bind_all_interfaces",
        "Runtime binds to all network interfaces. This exposes the server to the network. "
        "Use --host 127.0.0.1 to restrict to localhost.",
    ),
    # --api-key: API key in command line
    (
        re.compile(r"--api-key\s+\S+", re.IGNORECASE),
        "api_key_in_args",
        "Runtime passes API key in command line arguments. This may expose the key in process listings. "
        "Use environment variables instead.",
    ),
)

# High-risk runtime patterns
_HIGH_RISK_RUNTIME_PATTERNS: frozenset[str] = frozenset(
    {
        "bind_all_interfaces",
        "api_key_in_args",
    }
)


@dataclass(frozen=True, slots=True)
class RuntimeConfigAnalysis:
    """Analysis of runtime configuration."""

    findings: tuple[Finding, ...]
    flags_detected: tuple[str, ...]
    has_network_access: bool = False
    has_sandboxing_disabled: bool = False


def analyze_runtime_config(
    config_text: str,
    config_path: str,
) -> RuntimeConfigAnalysis:
    """Analyze runtime configuration for security issues.

    Args:
        config_text: Configuration file content
        config_path: Path to configuration file (for reporting)

    Returns:
        RuntimeConfigAnalysis with findings
    """
    findings: list[Finding] = []
    flags_detected: list[str] = []
    has_network_access = False
    has_sandboxing_disabled = False

    for pattern, kind, detail in _DANGEROUS_RUNTIME_PATTERNS:
        match = pattern.search(config_text)
        if match:
            is_high_risk = kind in _HIGH_RISK_RUNTIME_PATTERNS
            findings.append(
                Finding(
                    id=f"cbr.runtime_config.{kind}",
                    head="loading",
                    check="runtime_config_security",
                    status=Status.SUSPICIOUS if is_high_risk else Status.UNCHECKED,
                    severity=Severity.HIGH if is_high_risk else Severity.LOW,
                    confidence=Confidence.HIGH,
                    summary=detail,
                    evidence={
                        "pattern": kind,
                        "match": match.group(0)[:200],
                        "file": config_path,
                    },
                    mandatory=is_high_risk,
                )
            )
            flags_detected.append(kind)

            if kind in ("bind_all_interfaces", "network_port"):
                has_network_access = True
            if kind in ("allow_spawn", "no_mmap"):
                has_sandboxing_disabled = True

    return RuntimeConfigAnalysis(
        findings=tuple(findings),
        flags_detected=tuple(flags_detected),
        has_network_access=has_network_access,
        has_sandboxing_disabled=has_sandboxing_disabled,
    )


def analyze_runtime_flags(
    flags: list[str],
) -> RuntimeConfigAnalysis:
    """Analyze runtime command-line flags for security issues.

    Args:
        flags: List of command-line flags

    Returns:
        RuntimeConfigAnalysis with findings
    """
    findings: list[Finding] = []
    flags_detected: list[str] = []
    has_network_access = False
    has_sandboxing_disabled = False

    # Join flags for pattern matching
    flags_text = " ".join(flags)

    for pattern, kind, detail in _DANGEROUS_RUNTIME_PATTERNS:
        match = pattern.search(flags_text)
        if match:
            is_high_risk = kind in _HIGH_RISK_RUNTIME_PATTERNS
            findings.append(
                Finding(
                    id=f"cbr.runtime_config.{kind}",
                    head="loading",
                    check="runtime_config_security",
                    status=Status.SUSPICIOUS if is_high_risk else Status.UNCHECKED,
                    severity=Severity.HIGH if is_high_risk else Severity.LOW,
                    confidence=Confidence.HIGH,
                    summary=detail,
                    evidence={
                        "pattern": kind,
                        "match": match.group(0)[:200],
                        "flags": flags,
                    },
                    mandatory=is_high_risk,
                )
            )
            flags_detected.append(kind)

            if kind in ("bind_all_interfaces", "network_port"):
                has_network_access = True
            if kind in ("allow_spawn", "no_mmap"):
                has_sandboxing_disabled = True

    return RuntimeConfigAnalysis(
        findings=tuple(findings),
        flags_detected=tuple(flags_detected),
        has_network_access=has_network_access,
        has_sandboxing_disabled=has_sandboxing_disabled,
    )


__all__ = [
    "RuntimeConfigAnalysis",
    "analyze_runtime_config",
    "analyze_runtime_flags",
]
