"""End-to-end orchestration for the non-executing ``check`` command."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cancerbero import __version__
from cancerbero.config import inspect_companion_config
from cancerbero.discovery import classify_target, discover_targets
from cancerbero.domain import (
    ArtifactFacts,
    AuditReport,
    BundleInfo,
    Confidence,
    Finding,
    RuntimeFacts,
    Severity,
    Status,
    Target,
    TargetKind,
)
from cancerbero.engine import evaluate_advisories
from cancerbero.gguf.inspector import inspect_gguf
from cancerbero.gguf.limits import DEFAULT_LIMITS, ParserLimits
from cancerbero.hardening import generate_hardening_recommendations
from cancerbero.hashing import hash_file
from cancerbero.knowledge.loader import load_bundle
from cancerbero.knowledge.schema import BundleError
from cancerbero.policy import evaluate_verdict
from cancerbero.runtime.inspector import RuntimeInspectionError, inspect_runtime
from cancerbero.runtime_config import analyze_runtime_flags
from cancerbero.supply_chain import analyze_supply_chain
from cancerbero.template import analyze_chat_template


class ProgressCallback:
    """Callback for reporting progress during checks."""

    def on_bundle_loaded(self, version: str) -> None:
        """Called when the knowledge bundle is loaded."""
        pass

    def on_discovery_start(self, target_count: int) -> None:
        """Called when target discovery starts."""
        pass

    def on_artifact_inspected(self, path: Path, success: bool) -> None:
        """Called after each artifact is inspected."""
        pass

    def on_runtime_inspected(self, path: Path, success: bool) -> None:
        """Called after runtime is inspected."""
        pass

    def on_template_analyzed(self, has_template: bool) -> None:
        """Called after template analysis."""
        pass

    def on_hash_complete(self, path: Path, digest: str) -> None:
        """Called after hash computation."""
        pass

    def on_advisory_join(self, rule_count: int) -> None:
        """Called after advisory join."""
        pass


@dataclass(frozen=True, slots=True)
class CheckOptions:
    targets: tuple[Path, ...]
    runtime: Path | None = None
    runtime_version: str | None = None
    full_hash: bool = False
    expected_sha256: str | None = None
    allow_runtime_exec: bool = False
    # Delegate flags
    use_modelaudit: bool = False
    use_picklescan: bool = False
    use_fickling: bool = False
    use_modelscan: bool = False
    use_all_delegates: bool = False


def _inspect_artifact(
    path: Path, limits: ParserLimits
) -> tuple[ArtifactFacts | None, list[Finding]]:
    """Inspect a GGUF artifact and return facts plus any structural findings."""
    findings: list[Finding] = []
    try:
        facts, structural_findings = inspect_gguf(path, limits=limits)
        findings.extend(structural_findings)
        return facts, findings
    except Exception as exc:
        error_text = str(exc)
        explanation, origin = _explain_gguf_error(error_text)
        findings.append(
            Finding(
                id="cbr.gguf.inspection_error",
                head="loading",
                check="gguf_structure",
                status=Status.ERROR,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                summary=f"{error_text}",
                evidence={
                    "artifact": str(path),
                    "error": error_text,
                    "explanation": explanation,
                    "origin": origin,
                },
            )
        )
        return None, findings


def _explain_gguf_error(error_text: str) -> tuple[str, str]:
    """Return a user-friendly explanation and likely origin for a GGUF error."""
    lower = error_text.lower()
    if "zero-sized dimension" in lower:
        return (
            "A tensor declares a dimension of size zero, which is invalid. "
            "This is typically a conversion or quantization artifact.",
            "The model was likely converted with a tool that produced an invalid tensor layout.",
        )
    if "truncated" in lower or "truncat" in lower:
        return (
            "The file ends before a declared structure is complete. "
            "The download may have been interrupted or the file corrupted.",
            "Incomplete download, storage issue, or file corruption.",
        )
    if "magic" in lower:
        return (
            "The file does not start with the GGUF magic bytes. It may not be a GGUF file at all.",
            "Wrong file format, or file renamed from a different format.",
        )
    if "version" in lower:
        return (
            "The GGUF version is not supported. Cancerbero handles v2 and v3.",
            "The file was created with a newer or incompatible GGUF version.",
        )
    if "duplicate" in lower:
        return (
            "A metadata key or tensor name appears more than once. "
            "This violates the GGUF specification.",
            "The model was converted or patched with a tool that introduced duplicate entries.",
        )
    if "limit" in lower or "budget" in lower:
        return (
            "A parser safety limit was exceeded. Cancerbero rejects files "
            "that require excessive memory or iterations to parse.",
            "The file has unusually large metadata, strings, or arrays. "
            "This is rare in well-formed models.",
        )
    if "alignment" in lower:
        return (
            "The tensor data alignment is invalid. GGUF requires power-of-two "
            "alignment of at least 8 bytes.",
            "The model was converted with a tool that wrote incorrect alignment metadata.",
        )
    if "overlap" in lower:
        return (
            "Two tensors claim overlapping byte ranges. This is a structural "
            "corruption that could cause data corruption at load time.",
            "The model file is structurally damaged or was created by a buggy converter.",
        )
    if "utf-8" in lower:
        return (
            "A metadata string contains invalid UTF-8 bytes. "
            "The GGUF specification requires all strings to be valid UTF-8.",
            "The model was converted on a system with a different encoding, "
            "or the file is partially corrupted.",
        )
    return (
        f"The GGUF parser encountered an unexpected error: {error_text}",
        "Unknown. The file may be corrupted or use an unsupported feature.",
    )


def _inspect_runtime(
    path: Path,
    *,
    version_override: str | None = None,
    allow_execution: bool = False,
    limits: ParserLimits = DEFAULT_LIMITS,
) -> tuple[RuntimeFacts | None, list[Finding]]:
    """Inspect a runtime and return facts plus any detection findings."""
    findings: list[Finding] = []
    try:
        facts = inspect_runtime(
            path,
            version_override=version_override,
            allow_execution=allow_execution,
            limits=limits,
        )
        if not facts.is_identified:
            findings.append(
                Finding(
                    id="cbr.runtime.unknown_build",
                    head="loading",
                    check="runtime_identity",
                    status=Status.UNCHECKED,
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    summary="Runtime build could not be identified from static evidence.",
                    evidence={
                        "path": str(path),
                        "detection_method": facts.detection_method,
                    },
                )
            )
        if facts.writable_by_others:
            findings.append(
                Finding(
                    id="cbr.runtime.writable_by_others",
                    head="loading",
                    check="runtime_permissions",
                    status=Status.SUSPICIOUS,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    summary="Runtime binary is writable by others.",
                    evidence={"path": str(path)},
                    action="Restrict write permissions on the runtime binary.",
                )
            )
        return facts, findings
    except (RuntimeInspectionError, OSError) as exc:
        findings.append(
            Finding(
                id="cbr.runtime.inspection_error",
                head="loading",
                check="runtime_identity",
                status=Status.ERROR,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                summary=f"Runtime inspection failed: {exc}",
                evidence={"error": str(exc)},
            )
        )
        return None, findings


def _analyze_template(artifact: ArtifactFacts) -> list[Finding]:
    """Analyze chat template if present."""
    if not artifact.has_chat_template or artifact.chat_template is None:
        return [
            Finding(
                id="cbr.template.absent",
                head="loading",
                check="chat_template_static",
                status=Status.NOT_APPLICABLE,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                summary="No chat template was found in the artifact.",
                mandatory=False,
            )
        ]
    from cancerbero.template import (
        analyze_template_poison_risk_from_analysis,
    )

    findings: list[Finding] = []
    # Standard AST analysis — run ONCE and reuse for both the structural
    # finding and the poison risk pass (M3).
    analysis = analyze_chat_template(artifact.chat_template)
    findings.extend(analysis.findings)
    # A successfully parsed template provides positive evidence for the
    # chat_template_static core check (H1). The limit-exceeded path can set
    # parsed=True while carrying a syntax_error, so require both conditions.
    if analysis.parsed and analysis.syntax_error is None:
        findings.append(
            Finding(
                id="cbr.template.parsed",
                head="loading",
                check="chat_template_static",
                status=Status.CLEAN,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                summary="Chat template parsed successfully; static syntax is well-formed.",
                evidence={
                    "ast_nodes": analysis.ast_node_count,
                    "bytes": analysis.byte_length,
                },
                mandatory=False,
            )
        )
    # Poisoned template attack detection (Pillar Security, 2025-07).
    # Reuses the AST from the structural pass to avoid a second parse.
    poison_findings = analyze_template_poison_risk_from_analysis(analysis, artifact.chat_template)
    findings.extend(poison_findings)
    return findings


def _hash_artifact(
    path: Path,
    expected: str | None = None,
) -> tuple[Finding | None, dict[str, Any], str]:
    """Optionally hash the artifact and return a finding, observations, and digest."""
    result = hash_file(path, expected=expected)
    observations = {
        "hash_bytes_read": result.bytes_read,
        "hash_duration_seconds": result.duration_seconds,
        "hash_throughput_bytes_per_second": result.throughput_bytes_per_second,
    }
    return result.finding, observations, result.digest


def run_check(
    options: CheckOptions,
    *,
    command: list[str],
    progress: ProgressCallback | None = None,
) -> AuditReport:
    """Inspect local targets and return a policy-evaluated report."""
    start = time.monotonic()
    observations: dict[str, Any] = {}
    all_findings: list[Finding] = []
    targets: list[Target] = []
    artifacts: list[ArtifactFacts] = []
    runtimes: list[RuntimeFacts] = []
    bundle_info: BundleInfo | None = None

    # Load knowledge bundle
    try:
        bundle = load_bundle()
        bundle_info = bundle.info
        if progress:
            progress.on_bundle_loaded(bundle.info.bundle_version)
        if bundle.expired:
            all_findings.append(
                Finding(
                    id="cbr.bundle.expired",
                    head="loading",
                    check="knowledge_bundle",
                    status=Status.UNCHECKED,
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    summary=(
                        "The embedded knowledge bundle has expired;"
                        " advisory coverage is undetermined."
                    ),
                    evidence={
                        "bundle_version": bundle.info.bundle_version,
                        "expires_at": bundle.info.expires_at,
                    },
                )
            )
    except BundleError as exc:
        bundle = None
        all_findings.append(
            Finding(
                id="cbr.bundle.error",
                head="loading",
                check="knowledge_bundle",
                status=Status.ERROR,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                summary=f"Knowledge bundle could not be loaded: {exc}",
                evidence={"error": str(exc)},
            )
        )

    # Discover targets
    discovery = discover_targets(options.targets)
    targets = list(discovery.targets)
    if discovery.limit_reached:
        all_findings.append(
            Finding(
                id="cbr.discovery.limit_reached",
                head="loading",
                check="target_discovery",
                status=Status.UNCHECKED,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                summary="Directory discovery reached a limit; inventory may be incomplete.",
                evidence={
                    "candidates_examined": discovery.candidates_examined,
                    "skipped_symlinks": discovery.skipped_symlinks,
                },
            )
        )

    # Classify explicit runtime if provided
    runtime_target: Target | None = None
    if options.runtime is not None:
        runtime_target = classify_target(options.runtime)
        if runtime_target.kind is not TargetKind.LLAMA_CPP_RUNTIME:
            all_findings.append(
                Finding(
                    id="cbr.runtime.not_recognized",
                    head="loading",
                    check="runtime_identity",
                    status=Status.UNCHECKED,
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    summary="The explicit runtime path was not recognized as a llama.cpp binary.",
                    evidence={"path": str(options.runtime)},
                )
            )

    # Inspect GGUF artifacts
    gguf_targets = [t for t in targets if t.kind is TargetKind.GGUF]
    runtime_targets = [t for t in targets if t.kind is TargetKind.LLAMA_CPP_RUNTIME]

    if progress:
        progress.on_discovery_start(len(gguf_targets))

    artifact_facts: ArtifactFacts | None = None
    for target in gguf_targets:
        facts, findings = _inspect_artifact(target.path, DEFAULT_LIMITS)
        all_findings.extend(findings)
        if facts is not None:
            artifacts.append(facts)
            if artifact_facts is None:
                artifact_facts = facts
        if progress:
            progress.on_artifact_inspected(target.path, facts is not None)

    # Inspect runtime
    runtime_facts: RuntimeFacts | None = None
    runtime_path = options.runtime or (runtime_targets[0].path if runtime_targets else None)
    if runtime_path is not None:
        facts, findings = _inspect_runtime(
            runtime_path,
            version_override=options.runtime_version,
            allow_execution=options.allow_runtime_exec,
        )
        all_findings.extend(findings)
        runtime_facts = facts
        if facts is not None:
            runtimes.append(facts)
        if progress:
            progress.on_runtime_inspected(runtime_path, facts is not None)

    # Template analysis (per-artifact). Previously this only ran against
    # ``artifact_facts`` (the first successfully parsed GGUF); the other
    # GGUF files in the same directory were skipped, even when the attacker
    # hides the malicious template in a quantized variant (Pillar, 2025-07).
    for artifact in artifacts:
        all_findings.extend(_analyze_template(artifact))
        if progress:
            progress.on_template_analyzed(artifact.has_chat_template)

    # Hash if requested (per-artifact). Run BEFORE the companion file
    # inspection so the manifest-coherence check can compare the declared
    # SHA-256 in any companion manifest against the freshly computed
    # digest. Previously this block ran after ``inspect_companion_config``
    # and the manifest comparison always received ``available_digest=None``.
    if options.full_hash:
        for index, artifact in enumerate(artifacts):
            expected = options.expected_sha256 if index == 0 else None
            finding, hash_obs, digest = _hash_artifact(artifact.path, expected=expected)
            observations.update(hash_obs)
            if finding is not None:
                all_findings.append(finding)
            # Write the computed digest back so reports, manifest checks, and
            # subsequent consumers observe provenance from the full hash pass.
            object.__setattr__(artifact, "sha256", digest)
            if progress:
                progress.on_hash_complete(artifact.path, digest)

    # Companion file inspection (config.json, Modelfile, manifests, etc.)
    # Scan once per unique directory rather than per artifact so we do not
    # emit duplicate findings when several GGUF files share the same parent.
    inspected_dirs: set[Path] = set()
    for artifact in artifacts:
        artifact_dir = artifact.path.parent
        if artifact_dir in inspected_dirs or not artifact_dir.is_dir():
            continue
        inspected_dirs.add(artifact_dir)
        try:
            config_result = inspect_companion_config(
                artifact_dir,
                runtime="llama.cpp",
                artifact_name=artifact.name,
                available_digest=artifact.sha256,
                architecture=artifact.architecture,
                model_name=artifact.name,
            )
            all_findings.extend(config_result.findings)

            # Hugging Face UI Blindspot detection
            # (Pillar Security, 2025-07)
            if len(artifacts) > 1:
                from cancerbero.config import detect_template_mismatch_across_files

                mismatch_evidence = detect_template_mismatch_across_files(artifact_dir)
                for item in mismatch_evidence:
                    all_findings.append(
                        Finding(
                            id="cbr.config.template_mismatch",
                            head="loading",
                            check="template_mismatch_detection",
                            status=Status.SUSPICIOUS,
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            classification=Confidence.MEDIUM,
                            summary=item.detail,
                            evidence=item.value
                            if isinstance(item.value, dict)
                            else {"detail": str(item.value)},
                            action=(
                                "Do not load this model without verifying each GGUF file's "
                                "template individually. Attackers may hide malicious templates "
                                "in quantized variants while showing clean templates on "
                                "the repository page."
                            ),
                            references=[
                                "https://www.pillar.security/blog/llm-backdoors-at-the-inference-level-the-threat-of-poisoned-templates",
                            ],
                        )
                    )
        except (OSError, ValueError) as exc:
            all_findings.append(
                Finding(
                    id="cbr.config.inspection_error",
                    head="loading",
                    check="companion_config",
                    status=Status.ERROR,
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    classification=Confidence.HIGH,
                    summary=f"Companion file inspection failed: {exc}",
                    evidence={"error": str(exc)},
                )
            )

    # Advisory join (per-artifact). Previously this ran only against
    # ``artifact_facts``; sibling artifacts never had their versions compared
    # against the bundled rules.
    if runtime_facts is not None and bundle is not None:
        for artifact in artifacts:
            advisory_findings = evaluate_advisories(artifact, runtime_facts, bundle.rules)
            all_findings.extend(advisory_findings)
        if progress:
            progress.on_advisory_join(len(bundle.rules))
    elif runtime_facts is not None and bundle is None:
        all_findings.append(
            Finding(
                id="cbr.join.no_bundle",
                head="loading",
                check="runtime_advisory_join",
                status=Status.UNCHECKED,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                classification=Confidence.HIGH,
                summary=(
                    "Advisory join could not be performed"
                    " because the knowledge bundle is unavailable."
                ),
            )
        )

    # When NO runtime was supplied the advisory join cannot run. Emit a
    # single UNCHECKED ``runtime_advisory_join`` finding so the policy sees
    # explicit evidence for the check (and can downgrade the verdict to
    # ``CLEAN`` rather than ``UNDETERMINED`` per G3).
    if runtime_facts is None and not runtime_targets and options.runtime is None:
        all_findings.append(
            Finding(
                id="cbr.join.no_runtime",
                head="loading",
                check="runtime_advisory_join",
                status=Status.UNCHECKED,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                classification=Confidence.HIGH,
                summary=(
                    "Runtime advisory join was skipped because no llama.cpp "
                    "runtime was supplied. Re-run with --runtime <binary-or-dir> "
                    "to include runtime advisories in the verdict."
                ),
                references=[
                    "https://github.com/noguerol/cancerbero#runtime-join",
                ],
                mandatory=False,
            )
        )

    # If no targets found, add an error
    if not artifacts and not runtimes:
        all_findings.append(
            Finding(
                id="cbr.no_targets",
                head="loading",
                check="target_discovery",
                status=Status.ERROR,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                summary="No GGUF artifacts or llama.cpp runtimes were found.",
            )
        )

    # Runtime configuration security analysis (v0.5 Phase 5)
    if runtime_facts is not None:
        runtime_config_findings = _analyze_runtime_security(runtime_facts)
        all_findings.extend(runtime_config_findings)

    # Supply chain verification (v0.5 Phase 6) — per-artifact.
    for artifact in artifacts:
        supply_chain_findings = _analyze_supply_chain(artifact)
        all_findings.extend(supply_chain_findings)

    # Run optional delegates
    delegate_findings = _run_delegates(options, options.targets, progress)
    all_findings.extend(delegate_findings)

    # Evaluate verdict
    findings_tuple = tuple(all_findings)
    verdict, exit_code = evaluate_verdict(
        findings_tuple,
        runtime_in_scope=runtime_facts is not None or bool(runtime_targets),
    )

    # Generate hardening recommendations
    runtime_version = runtime_facts.version if runtime_facts else None
    has_network_access = any(
        "bind_all_interfaces" in f.id or "network_port" in f.id for f in findings_tuple
    )
    has_sandboxing_disabled = any("allow_spawn" in f.id for f in findings_tuple)
    hardening_recommendations = generate_hardening_recommendations(
        findings=findings_tuple,
        runtime_version=runtime_version,
        has_network_access=has_network_access,
        has_sandboxing_disabled=has_sandboxing_disabled,
    )

    duration = time.monotonic() - start
    observations["duration_seconds"] = round(duration, 3)

    return AuditReport(
        schema_version="1.0",
        cancerbero_version=__version__,
        command=command,
        targets=targets if targets else [Target(Path("."), TargetKind.UNKNOWN, "no_targets")],
        artifacts=artifacts,
        runtimes=runtimes,
        findings=findings_tuple,
        bundle=bundle_info,
        verdict=verdict,
        exit_code=exit_code,
        deterministic_options={
            "full_hash": options.full_hash,
            "expected_sha256": options.expected_sha256 is not None,
            "allow_runtime_exec": options.allow_runtime_exec,
        },
        observations=observations,
        hardening_recommendations=list(hardening_recommendations),
    )


def _analyze_runtime_security(runtime_facts: RuntimeFacts) -> list[Finding]:
    """Analyze runtime configuration for security issues."""
    findings: list[Finding] = []

    # Analyze runtime flags if available
    flags = runtime_facts.flags
    if flags:
        config_analysis = analyze_runtime_flags(list(flags))
        findings.extend(config_analysis.findings)

    return findings


def _analyze_supply_chain(artifact_facts: ArtifactFacts) -> list[Finding]:
    """Analyze supply chain risks for an artifact."""
    findings: list[Finding] = []

    # Analyze supply chain risks
    supply_chain_analysis = analyze_supply_chain(
        model_name=artifact_facts.name,
        model_path=artifact_facts.path,
        metadata=artifact_facts.metadata,
    )
    findings.extend(supply_chain_analysis.findings)

    return findings


def _run_delegates(
    options: CheckOptions,
    targets: tuple[Path, ...],
    progress: ProgressCallback | None = None,
) -> list[Finding]:
    """Run optional third-party delegates and return findings."""
    from cancerbero.delegates import (
        FicklingDelegate,
        ModelAuditDelegate,
        ModelScanDelegate,
        PickleScanDelegate,
    )
    from cancerbero.delegates.base import DelegateRunner

    findings: list[Finding] = []

    # Determine which delegates to run
    delegates_to_run: list[tuple[str, DelegateRunner]] = []
    if options.use_modelaudit or options.use_all_delegates:
        delegates_to_run.append(("modelaudit", ModelAuditDelegate()))
    if options.use_picklescan or options.use_all_delegates:
        delegates_to_run.append(("picklescan", PickleScanDelegate()))
    if options.use_fickling or options.use_all_delegates:
        delegates_to_run.append(("fickling", FicklingDelegate()))
    if options.use_modelscan or options.use_all_delegates:
        delegates_to_run.append(("modelscan", ModelScanDelegate()))

    if not delegates_to_run:
        return findings

    pickle_extensions = {".bin", ".pickle", ".pkl", ".pt", ".pth"}
    modelscan_extensions = pickle_extensions | {".h5", ".hdf5", ".keras", ".onnx", ".pb"}
    seen_finding_keys: set[tuple[str, str, str, str]] = set()

    for target_path in targets:
        if target_path.is_symlink() or not target_path.exists():
            continue
        target_extension = target_path.suffix.casefold()

        for delegate_name, delegate in delegates_to_run:
            supported = (
                delegate_name == "modelaudit"
                or target_path.is_dir()
                or (
                    delegate_name in {"picklescan", "fickling"}
                    and target_extension in pickle_extensions
                )
                or (delegate_name == "modelscan" and target_extension in modelscan_extensions)
            )
            if not supported:
                continue

            try:
                result = delegate.run(target_path)

                if not result.available:
                    findings.append(
                        Finding(
                            id=f"cbr.delegate.{delegate_name}.not_available",
                            head="loading",
                            check=f"delegate_{delegate_name}",
                            status=Status.UNCHECKED,
                            severity=Severity.INFO,
                            confidence=Confidence.HIGH,
                            summary=f"{delegate_name} is not installed. Install with: pip install {delegate_name}",
                            evidence={
                                "tool": delegate_name,
                                "error": result.error,
                            },
                            mandatory=False,
                        )
                    )
                elif not result.success:
                    findings.append(
                        Finding(
                            id=f"cbr.delegate.{delegate_name}.error",
                            head="loading",
                            check=f"delegate_{delegate_name}",
                            status=Status.ERROR,
                            severity=Severity.INFO,
                            confidence=Confidence.HIGH,
                            summary=f"{delegate_name} failed: {result.error}",
                            evidence={
                                "tool": delegate_name,
                                "version": result.version,
                                "error": result.error,
                                "duration_ms": result.duration_ms,
                            },
                            mandatory=False,
                        )
                    )
                else:
                    # Convert delegate findings to Cancerbero findings
                    for finding_index, finding in enumerate(result.findings):
                        severity_map = {
                            "critical": Severity.CRITICAL,
                            "high": Severity.HIGH,
                            "medium": Severity.MEDIUM,
                            "low": Severity.LOW,
                            "info": Severity.INFO,
                        }
                        severity = severity_map.get(
                            finding.get("severity", "info").lower(),
                            Severity.INFO,
                        )

                        # Only HIGH/CRITICAL delegate findings mark the artifact
                        # as suspicious. MEDIUM/LOW delegate findings are recorded
                        # as unchecked with INFO severity: they do not imply a
                        # suspicious artifact and, once down-graded, can never
                        # violate the Finding invariant that non-suspicious
                        # findings carry only INFO/LOW severity.
                        if severity in (Severity.HIGH, Severity.CRITICAL):
                            status = Status.SUSPICIOUS
                        else:
                            status = Status.UNCHECKED
                            severity = Severity.INFO

                        external_id = (
                            re.sub(
                                r"[^a-z0-9_.-]+",
                                "-",
                                str(finding.get("id", "unknown")).casefold(),
                            ).strip("-.")
                            or "unknown"
                        )
                        summary = str(finding.get("message", "Delegate finding"))[:2000]
                        location = str(finding.get("location") or finding.get("file") or "")[:2000]
                        dedup_key = (
                            str(target_path),
                            severity.value,
                            summary.casefold(),
                            location.casefold(),
                        )
                        if dedup_key in seen_finding_keys:
                            continue
                        seen_finding_keys.add(dedup_key)

                        findings.append(
                            Finding(
                                id=(f"cbr.delegate.{delegate_name}.{external_id}.{finding_index}"),
                                head="loading",
                                check=f"delegate_{delegate_name}",
                                status=status,
                                severity=severity,
                                confidence=Confidence.MEDIUM,
                                classification=Confidence.MEDIUM,
                                summary=summary,
                                evidence={
                                    "tool": delegate_name,
                                    "version": result.version,
                                    "finding": finding,
                                    "duration_ms": result.duration_ms,
                                    "telemetry_disabled": result.telemetry_disabled,
                                },
                                mandatory=severity in (Severity.HIGH, Severity.CRITICAL),
                            )
                        )

                    # Add success finding
                    findings.append(
                        Finding(
                            id=f"cbr.delegate.{delegate_name}.completed",
                            head="loading",
                            check=f"delegate_{delegate_name}",
                            status=Status.VERIFIED,
                            severity=Severity.INFO,
                            confidence=Confidence.HIGH,
                            summary=f"{delegate_name} completed successfully ({len(result.findings)} findings)",
                            evidence={
                                "tool": delegate_name,
                                "version": result.version,
                                "findings_count": len(result.findings),
                                "duration_ms": result.duration_ms,
                                "telemetry_disabled": result.telemetry_disabled,
                            },
                            mandatory=False,
                        )
                    )

            except Exception as exc:
                findings.append(
                    Finding(
                        id=f"cbr.delegate.{delegate_name}.exception",
                        head="loading",
                        check=f"delegate_{delegate_name}",
                        status=Status.ERROR,
                        severity=Severity.INFO,
                        confidence=Confidence.HIGH,
                        summary=f"{delegate_name} raised an exception: {exc}",
                        evidence={
                            "tool": delegate_name,
                            "error": str(exc),
                        },
                        mandatory=False,
                    )
                )

    return findings


__all__ = ["CheckOptions", "run_check"]
