"""Supply chain verification (v0.1).

Detects supply chain risks in model artifacts before loading them.

Based on research from:
- Hive Security: Hugging Face supply chain attacks
- ReversingLabs: nullifAI technique
- BeyondScale: Open source AI model security
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cancerbero.domain import Confidence, Finding, Severity, Status

# Known suspicious patterns (conservative, high-signal only)
_SUSPICIOUS_SUPPLY_CHAIN_PATTERNS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    # --- Fake quantization (impossible types) ---
    (
        re.compile(r"(?:Q0_[KS]|Q0_0|Q1_[KS])", re.IGNORECASE),
        "impossible_quantization",
        "Model claims impossible quantization type. This may be a fake or malicious model.",
    ),
    # --- Suspicious file types ---
    (
        re.compile(r"\.(?:exe|bat|cmd|ps1|sh|py|js|vbs|wsf)$", re.IGNORECASE),
        "suspicious_file_type",
        "Model has suspicious file extension. This may be a malicious file disguised as a model.",
    ),
)

# High-risk supply chain patterns
_HIGH_RISK_SUPPLY_CHAIN_PATTERNS: frozenset[str] = frozenset(
    {
        "impossible_quantization",
        "suspicious_file_type",
    }
)


@dataclass(frozen=True, slots=True)
class SupplyChainAnalysis:
    """Analysis of supply chain risks."""

    findings: tuple[Finding, ...]
    risks_detected: tuple[str, ...]


def analyze_supply_chain(
    model_name: str | None,
    model_path: Path,
    metadata: dict[str, Any] | None = None,
) -> SupplyChainAnalysis:
    """Analyze supply chain risks for a model artifact.

    Args:
        model_name: Model name from metadata
        model_path: Path to model file
        metadata: Additional metadata (repo_url, uploader, etc.)

    Returns:
        SupplyChainAnalysis with findings
    """
    findings: list[Finding] = []
    risks_detected: list[str] = []

    # Check file path for suspicious patterns
    file_name = model_path.name
    for pattern, kind, detail in _SUSPICIOUS_SUPPLY_CHAIN_PATTERNS:
        match = pattern.search(file_name)
        if match:
            is_high_risk = kind in _HIGH_RISK_SUPPLY_CHAIN_PATTERNS
            findings.append(
                Finding(
                    id=f"cbr.supply_chain.{kind}",
                    head="loading",
                    check="supply_chain_verification",
                    status=Status.SUSPICIOUS if is_high_risk else Status.UNCHECKED,
                    severity=Severity.HIGH if is_high_risk else Severity.LOW,
                    confidence=Confidence.HIGH,  # Detection confidence
                    classification=Confidence.HIGH if is_high_risk else Confidence.MEDIUM,
                    summary=detail,
                    evidence={
                        "pattern": kind,
                        "match": match.group(0)[:200],
                        "file_name": file_name,
                    },
                    mandatory=is_high_risk,
                )
            )
            risks_detected.append(kind)

    # Check metadata for suspicious repository URLs
    if metadata:
        repo_url = metadata.get("general.repo_url") or metadata.get("general.base_model.0.repo_url")
        if repo_url:
            # Check for known suspicious domains (conservative list)
            suspicious_domains = [
                "malicious-models.com",
                "fake-huggingface.co",
            ]
            for domain in suspicious_domains:
                if domain in repo_url:
                    findings.append(
                        Finding(
                            id="cbr.supply_chain.suspicious_repo",
                            head="loading",
                            check="supply_chain_verification",
                            status=Status.SUSPICIOUS,
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            classification=Confidence.HIGH,
                            summary=f"Model repository URL contains known suspicious domain: {domain}",
                            evidence={
                                "repo_url": repo_url,
                                "suspicious_domain": domain,
                            },
                            mandatory=True,
                        )
                    )
                    risks_detected.append("suspicious_repo")

    return SupplyChainAnalysis(
        findings=tuple(findings),
        risks_detected=tuple(risks_detected),
    )


__all__ = [
    "SupplyChainAnalysis",
    "analyze_supply_chain",
]
