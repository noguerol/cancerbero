"""Configuration hardening recommendations (v0.5 Phase 8).

Generates actionable security recommendations based on findings from all phases.

Based on research from:
- Tech Insider: llama.cpp Tutorial 2026
- Hyperion Consulting: Ollama Enterprise Deployment Guide 2026
- SitePoint: Local LLM Security Best Practices 2026
- Medium: 4 llama.cpp Settings That Matter
- SentinelOne: CVE-2026-27940 Analysis
- daily.dev: Running LLMs Locally in 2026
"""

from __future__ import annotations

from dataclasses import dataclass

from cancerbero.domain import Finding, Status


@dataclass(frozen=True, slots=True)
class HardeningRecommendation:
    """A security hardening recommendation."""

    category: str
    priority: str  # "critical", "high", "medium", "low"
    title: str
    description: str
    action: str
    references: list[str]


def generate_hardening_recommendations(
    findings: tuple[Finding, ...],
    runtime_version: str | None = None,
    has_network_access: bool = False,
    has_sandboxing_disabled: bool = False,
) -> tuple[HardeningRecommendation, ...]:
    """Generate hardening recommendations based on findings.

    Args:
        findings: All findings from the check
        runtime_version: Runtime version if detected
        has_network_access: Whether runtime has network access
        has_sandboxing_disabled: Whether sandboxing is disabled

    Returns:
        Tuple of hardening recommendations
    """
    recommendations: list[HardeningRecommendation] = []

    # Analyze findings and generate recommendations
    _check_runtime_recommendations(findings, runtime_version, recommendations)
    _check_network_recommendations(findings, has_network_access, recommendations)
    _check_template_recommendations(findings, recommendations)
    _check_companion_recommendations(findings, recommendations)
    _check_supply_chain_recommendations(findings, recommendations)
    _check_general_recommendations(findings, recommendations)

    return tuple(recommendations)


def _check_runtime_recommendations(
    findings: tuple[Finding, ...],
    runtime_version: str | None,
    recommendations: list[HardeningRecommendation],
) -> None:
    """Generate runtime-related recommendations."""
    # Check for vulnerable runtime
    vulnerable_findings = [f for f in findings if f.status is Status.SUSPICIOUS and "CVE" in f.id]
    if vulnerable_findings:
        recommendations.append(
            HardeningRecommendation(
                category="runtime",
                priority="critical",
                title="Update llama.cpp to latest version",
                description=(
                    "Your llama.cpp installation has known vulnerabilities. "
                    "Update to the latest version to patch security issues."
                ),
                action="Run: git pull && make clean && make",
                references=[
                    "https://github.com/ggml-org/llama.cpp/releases",
                    "https://www.sentinelone.com/vulnerability-database/cve-2026-27940/",
                ],
            )
        )

    # Check for unknown runtime
    unknown_runtime = [
        f for f in findings if "runtime" in f.id.lower() and f.status is Status.UNCHECKED
    ]
    if unknown_runtime:
        recommendations.append(
            HardeningRecommendation(
                category="runtime",
                priority="medium",
                title="Provide runtime version for accurate checks",
                description=(
                    "Cancerbero could not identify your runtime version. "
                    "Provide --runtime-version for accurate advisory matching."
                ),
                action="Run: cancerbero check ./model.gguf --runtime ./llama-cli --runtime-version b8146",
                references=[
                    "https://github.com/ggml-org/llama.cpp",
                ],
            )
        )


def _check_network_recommendations(
    findings: tuple[Finding, ...],
    has_network_access: bool,
    recommendations: list[HardeningRecommendation],
) -> None:
    """Generate network-related recommendations."""
    if has_network_access:
        recommendations.append(
            HardeningRecommendation(
                category="network",
                priority="high",
                title="Restrict network access",
                description=(
                    "Your runtime is configured to accept network connections. "
                    "Restrict access to localhost or use a firewall."
                ),
                action="Use --host 127.0.0.1 instead of --host 0.0.0.0",
                references=[
                    "https://tech-insider.org/llama-cpp-tutorial-2026/",
                    "https://hyperion-consulting.io/en/insights/ollama-enterprise-deployment-guide-2026",
                ],
            )
        )

    # Check for API key in arguments
    api_key_findings = [f for f in findings if "api_key" in f.id.lower()]
    if api_key_findings:
        recommendations.append(
            HardeningRecommendation(
                category="network",
                priority="high",
                title="Use environment variables for API keys",
                description=(
                    "API keys in command-line arguments can be exposed in process listings. "
                    "Use environment variables instead."
                ),
                action="Set LLAMA_API_KEY environment variable instead of --api-key",
                references=[
                    "https://tech-insider.org/llama-cpp-tutorial-2026/",
                ],
            )
        )


def _check_template_recommendations(
    findings: tuple[Finding, ...],
    recommendations: list[HardeningRecommendation],
) -> None:
    """Generate template-related recommendations."""
    # Check for dangerous template patterns
    dangerous_template = [
        f for f in findings if "template" in f.id.lower() and f.status is Status.SUSPICIOUS
    ]
    if dangerous_template:
        recommendations.append(
            HardeningRecommendation(
                category="template",
                priority="critical",
                title="Do not load models with suspicious templates",
                description=(
                    "The model template contains patterns consistent with "
                    "inference-time attacks. Do not load this model."
                ),
                action="Obtain the model from a trusted source with a verified template.",
                references=[
                    "https://www.pillar.security/blog/llm-backdoors-at-the-inference-level-the-threat-of-poisoned-templates",
                ],
            )
        )

    # Check for template extraction attempts
    extraction_findings = [f for f in findings if "extraction" in f.id.lower()]
    if extraction_findings:
        recommendations.append(
            HardeningRecommendation(
                category="template",
                priority="medium",
                title="Review template for extraction attempts",
                description=(
                    "The template contains patterns that could be used to "
                    "extract system prompts or other sensitive information."
                ),
                action="Review the template manually and remove extraction patterns.",
                references=[
                    "https://owasp.org/Top10/LLM07_2025-System_Prompt_Leakage/",
                ],
            )
        )


def _check_companion_recommendations(
    findings: tuple[Finding, ...],
    recommendations: list[HardeningRecommendation],
) -> None:
    """Generate companion file-related recommendations."""
    # Check for pickle deserialization
    pickle_findings = [
        f for f in findings if "pickle" in f.id.lower() and f.status is Status.SUSPICIOUS
    ]
    if pickle_findings:
        recommendations.append(
            HardeningRecommendation(
                category="companion",
                priority="critical",
                title="Remove pickle dependencies",
                description=(
                    "Companion files contain pickle deserialization code "
                    "which can execute arbitrary code during loading."
                ),
                action="Replace pickle with safetensors or other safe formats.",
                references=[
                    "https://www.reversinglabs.com/blog/rl-identifies-malware-ml-model-hosted-on-hugging-face",
                    "https://arxiv.org/abs/2602.19818",
                ],
            )
        )

    # Check for hardcoded credentials
    credential_findings = [
        f for f in findings if "credential" in f.id.lower() or "api_key" in f.id.lower()
    ]
    if credential_findings:
        recommendations.append(
            HardeningRecommendation(
                category="companion",
                priority="critical",
                title="Remove hardcoded credentials",
                description=(
                    "Companion files contain hardcoded credentials. "
                    "Move them to environment variables or secure vaults."
                ),
                action="Use environment variables for all credentials.",
                references=[
                    "https://labs.cloudsecurityalliance.org/research/csa-research-note-model-poisoning-self-hosted-llm-stealer-20/",
                ],
            )
        )

    # Check for trust_remote_code
    trust_remote = [f for f in findings if "trust_remote" in f.id.lower()]
    if trust_remote:
        recommendations.append(
            HardeningRecommendation(
                category="companion",
                priority="high",
                title="Disable trust_remote_code",
                description=(
                    "Configuration enables trust_remote_code which allows "
                    "executing code from remote repositories."
                ),
                action="Set trust_remote_code: false in configuration.",
                references=[
                    "https://huggingface.co/blog/huseyingulsin/ai-for-organizations-2-risk-of-pickle",
                ],
            )
        )


def _check_supply_chain_recommendations(
    findings: tuple[Finding, ...],
    recommendations: list[HardeningRecommendation],
) -> None:
    """Generate supply chain-related recommendations."""
    # Check for suspicious model names
    suspicious_name = [
        f for f in findings if "supply_chain" in f.id.lower() and f.status is Status.SUSPICIOUS
    ]
    if suspicious_name:
        recommendations.append(
            HardeningRecommendation(
                category="supply_chain",
                priority="high",
                title="Verify model source",
                description=(
                    "The model has suspicious characteristics that may indicate "
                    "a supply chain attack. Verify the source."
                ),
                action="Download models only from official repositories.",
                references=[
                    "https://hivesecurity.gitlab.io/blog/huggingface-ai-supply-chain-attacks-2026/",
                ],
            )
        )

    # Check for uncensored models
    uncensored = [f for f in findings if "uncensored" in f.id.lower()]
    if uncensored:
        recommendations.append(
            HardeningRecommendation(
                category="supply_chain",
                priority="medium",
                title="Verify uncensored model source",
                description=(
                    "The model claims to be uncensored/unfiltered. "
                    "Verify this is from a legitimate source."
                ),
                action="Check the model card and repository for legitimacy.",
                references=[
                    "https://beyondscale.tech/blog/open-source-ai-model-security-hugging-face",
                ],
            )
        )


def _check_general_recommendations(
    findings: tuple[Finding, ...],
    recommendations: list[HardeningRecommendation],
) -> None:
    """Generate general recommendations."""
    # Always recommend checking before loading
    recommendations.append(
        HardeningRecommendation(
            category="general",
            priority="low",
            title="Always check before loading",
            description=(
                "Run Cancerbero before loading any model to identify potential security issues."
            ),
            action="cancerbero check ./model.gguf --runtime ./llama-cli --runtime-version b8146",
            references=[
                "https://github.com/noguerol/cancerbero",
            ],
        )
    )

    # Recommend keeping Cancerbero updated
    recommendations.append(
        HardeningRecommendation(
            category="general",
            priority="low",
            title="Keep Cancerbero updated",
            description=(
                "Update Cancerbero regularly to get the latest advisory "
                "database and detection patterns."
            ),
            action="pip install --upgrade cancerbero",
            references=[
                "https://github.com/noguerol/cancerbero",
            ],
        )
    )

    # Recommend using safetensors
    recommendations.append(
        HardeningRecommendation(
            category="general",
            priority="medium",
            title="Prefer safetensors format",
            description=(
                "Safetensors is a safer alternative to pickle-based formats. "
                "Prefer models in safetensors format when available."
            ),
            action="Convert models to safetensors format when possible.",
            references=[
                "https://huggingface.co/blog/huseyingulsin/ai-for-organizations-2-risk-of-pickle",
            ],
        )
    )


__all__ = [
    "HardeningRecommendation",
    "generate_hardening_recommendations",
]
