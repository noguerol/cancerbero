"""Bounded inspection of files accompanying a local model artifact."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class ConfigLimits:
    max_depth: int = 4
    max_files: int = 256
    max_file_bytes: int = 2 * 1024 * 1024
    max_total_bytes: int = 8 * 1024 * 1024
    max_json_depth: int = 32
    max_evidence: int = 256

    def __post_init__(self) -> None:
        for name in (
            "max_depth",
            "max_files",
            "max_file_bytes",
            "max_total_bytes",
            "max_json_depth",
            "max_evidence",
        ):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")


@dataclass(frozen=True, slots=True)
class ConfigEvidence:
    """A configuration observation, not an automatic critical finding."""

    kind: str
    path: str
    detail: str
    value: Any = None
    trust_decision: bool = False
    severity: str = "info"
    runtime_relevance: str = "not_used"

    @property
    def relevant_to_llama_cpp(self) -> bool:
        return self.runtime_relevance in {"direct", "conditional"}


@dataclass(frozen=True, slots=True)
class ManifestDeclaration:
    path: str
    artifact: str
    sha256: str | None
    architecture: str | None
    name: str | None


@dataclass(frozen=True, slots=True)
class ConfigInspection:
    root: Path
    files_inspected: tuple[str, ...]
    evidence: tuple[ConfigEvidence, ...]
    errors: tuple[str, ...]
    bytes_read: int
    candidates_seen: int
    limit_reached: bool
    manifests: tuple[ManifestDeclaration, ...] = ()

    @property
    def trust_decisions(self) -> tuple[ConfigEvidence, ...]:
        return tuple(item for item in self.evidence if item.trust_decision)

    @property
    def findings(self):  # type annotation omitted to keep domain import lazy
        """Normalize inspection evidence and errors into domain Findings."""

        from cancerbero.domain import Confidence, Finding, Severity, Status

        findings: list[Finding] = []
        for index, item in enumerate(self.evidence):
            mismatch = item.kind.endswith("_mismatch")
            if mismatch:
                status = Status.SUSPICIOUS
            elif item.runtime_relevance == "not_used":
                status = Status.NOT_APPLICABLE
            elif item.kind.endswith("_match"):
                status = Status.VERIFIED
            elif item.severity == "high":
                # High-severity companion evidence (hardcoded credentials,
                # remote FROM URL, etc.) is always actionable; surface it as
                # SUSPICIOUS so the verdict policy can block.
                status = Status.SUSPICIOUS
            else:
                status = Status.UNCHECKED
            severity = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
                "info": Severity.INFO,
            }.get(item.severity, Severity.INFO)
            findings.append(
                Finding(
                    id=f"cbr.config.{item.kind}.{index}",
                    head="loading",
                    check="companion_config",
                    status=status,
                    severity=severity,
                    confidence=Confidence.HIGH,
                    classification=Confidence.HIGH,
                    summary=item.detail,
                    evidence={
                        "path": item.path,
                        "value": item.value,
                        "trust_decision": item.trust_decision,
                        "runtime_relevance": item.runtime_relevance,
                    },
                    # Companion signals are informational unless they are
                    # actually suspicious; absence of evidence is not a gap (H2).
                    mandatory=status is Status.SUSPICIOUS,
                )
            )
        for index, error in enumerate(self.errors):
            findings.append(
                Finding(
                    id=f"cbr.config.error.{index}",
                    head="loading",
                    check="companion_config",
                    status=Status.ERROR,
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    summary=error,
                    mandatory=False,
                )
            )
        if not findings:
            findings.append(
                Finding(
                    id="cbr.config.no_signals",
                    head="loading",
                    check="companion_config",
                    status=Status.CLEAN,
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    summary="No configured companion-file signals were found.",
                    mandatory=False,
                )
            )
        return tuple(findings)


DEFAULT_CONFIG_LIMITS = ConfigLimits()
_REMOTE_REFERENCE = re.compile(r"(?:https?://|hf://|huggingface\.co/)", re.IGNORECASE)
_FROM = re.compile(r"^\s*FROM\s+([^\s#]+)", re.IGNORECASE | re.MULTILINE)
_PINNED_SHA256 = re.compile(r"(?:@|:|\b)sha256[:=]?[0-9a-f]{64}\b", re.IGNORECASE)
_TEXT_SUFFIXES = frozenset(
    {".json", ".md", ".txt", ".yaml", ".yml", ".pem", ".key", ".cfg", ".ini", ".conf"}
)
_ADAPTER_SUFFIXES = frozenset({".json", ".safetensors", ".bin", ".gguf"})

# Rules File Backdoor detection patterns (Pillar Security, 2025-03)
# These detect malicious instructions in configuration/rules files
# that AI code editors and tools consume
_RULES_FILE_PATTERNS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    # Hidden instructions in markdown/html comments
    (
        re.compile(
            r"<!--.*(?:ignore|forget|disregard|override|bypass|system prompt|you are now|act as|pretend).*-->",
            re.IGNORECASE | re.DOTALL,
        ),
        "hidden_comment_instruction",
        "File contains hidden instructions in HTML comments that attempt to override AI behavior.",
    ),
    # Base64 encoded payloads that could hide instructions
    # Tightened: only match standalone runs not surrounded by quotes or
    # identifier characters, to avoid flagging URLs and prose words (H2).
    (
        re.compile("(?<![A-Za-z0-9+/_'\"`])[A-Za-z0-9+/]{50,}={0,2}(?![A-Za-z0-9+/_'\"`])"),
        "encoded_payload",
        "File contains long base64-like strings that may hide encoded malicious instructions.",
    ),
    # Direct prompt injection attempts
    (
        re.compile(
            r"(?:ignore|forget|disregard)\s+(?:all\s+)?(?:previous|above|prior)\s+(?:instructions|prompts|rules|context)",
            re.IGNORECASE,
        ),
        "direct_injection",
        "File contains direct prompt injection attempting to override previous instructions.",
    ),
    # System prompt override attempts
    (
        re.compile(
            r"(?:you are now|act as|pretend to be|your new role|system:\s*you are)", re.IGNORECASE
        ),
        "system_override",
        "File attempts to override the system prompt or change the AI's role.",
    ),
    # Data exfiltration instructions
    (
        re.compile(
            r"(?:send|post|upload|transmit|exfiltrate)\s+(?:all\s+)?(?:data|code|files|content|tokens|keys)\s+to",
            re.IGNORECASE,
        ),
        "exfiltration_instruction",
        "File contains instructions to exfiltrate data to an external location.",
    ),
    # Code execution instructions
    (
        re.compile(
            r"(?:execute|run|eval|exec|subprocess|os\.system|__import__)\s*\(", re.IGNORECASE
        ),
        "code_execution",
        "File contains instructions to execute code, which could be malicious.",
    ),
    # Credential harvesting
    (
        re.compile(
            r"(?:collect|harvest|extract|steal|send)\s+(?:all\s+)?(?:api[_-]?keys?|tokens?|passwords?|secrets?|credentials?)",
            re.IGNORECASE,
        ),
        "credential_harvest",
        "File contains instructions to collect or exfiltrate credentials.",
    ),
)

# High-risk patterns that should always be flagged
_HIGH_RISK_RULES_PATTERNS: frozenset[str] = frozenset(
    {
        "hidden_comment_instruction",
        "direct_injection",
        "system_override",
        "exfiltration_instruction",
        "code_execution",
        "credential_harvest",
    }
)

# Enhanced companion file security patterns (v0.5 Phase 2)
# Based on: JFrog findings, ReversingLabs, BeyondScale, CVE-2025-32444
_ENHANCED_COMPANION_PATTERNS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    # --- Hardcoded credentials (high-signal) ---
    (
        re.compile(
            r'(?:"api[_-]?key"|"apikey"|"access[_-]?key"|"secret[_-]?key"|"auth[_-]?token"|"bearer")\s*:\s*"[a-zA-Z0-9_\-]{20,}"',
            re.IGNORECASE,
        ),
        "hardcoded_api_key",
        "File contains hardcoded API keys or tokens. These should be stored in environment variables or secure vaults.",
    ),
    (
        re.compile(
            r"(?:AKIA[0-9A-Z]{16}|aws[_-]?access[_-]?key[_-]?id|aws[_-]?secret[_-]?access[_-]?key)",
            re.IGNORECASE,
        ),
        "hardcoded_aws_credentials",
        "File contains AWS credentials. These should be stored in environment variables or AWS credentials files.",
    ),
    (
        re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----"),
        "hardcoded_private_key",
        "File contains a private key. Private keys should never be stored in configuration files.",
    ),
    (
        re.compile(r'(?:"password"|"passwd"|"pwd")\s*:\s*"[^"]{8,}"', re.IGNORECASE),
        "hardcoded_password",
        "File contains a hardcoded password. Passwords should be stored in environment variables or secure vaults.",
    ),
    # --- Remote code execution in configs (high-signal) ---
    (
        re.compile(r'"trust[_-]?remote[_-]?code"\s*:\s*true', re.IGNORECASE),
        "trust_remote_code_enabled",
        "Configuration enables trust_remote_code, which allows executing code from remote repositories.",
    ),
    (
        re.compile(r'"auto[_-]?map"\s*:\s*\{', re.IGNORECASE),
        "auto_map_config",
        "Configuration contains auto_map which can load remote code automatically.",
    ),
    (
        re.compile(r"^FROM\s+https?://", re.IGNORECASE | re.MULTILINE),
        "remote_from_url",
        "Modelfile uses a remote URL in FROM statement, which downloads and executes code from the internet.",
    ),
    # --- Network exfiltration patterns (high-signal) ---
    (
        re.compile(r"https?://(?:discord|slack)\.com/api/webhooks/", re.IGNORECASE),
        "discord_slack_webhook",
        "File contains Discord or Slack webhook URLs that could be used for data exfiltration.",
    ),
    (
        re.compile(
            r'https?://[^\s"]+\?(?:data|token|key|secret|password|auth)=[^\s"]+', re.IGNORECASE
        ),
        "data_exfiltration_url",
        "File contains URLs with sensitive data parameters that could be used for exfiltration.",
    ),
)

# High-risk enhanced patterns
_HIGH_RISK_ENHANCED_COMPANION_PATTERNS: frozenset[str] = frozenset(
    {
        "hardcoded_api_key",
        "hardcoded_aws_credentials",
        "hardcoded_private_key",
        "hardcoded_password",
        "trust_remote_code_enabled",
        "remote_from_url",
        "discord_slack_webhook",
        "data_exfiltration_url",
    }
)

# Model card and documentation analysis patterns (v0.5 Phase 3)
# Based on: Hive Security, ReversingLabs, BeyondScale, CVE-2026-4372
_MODEL_CARD_PATTERNS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    # --- Known malicious patterns (high-signal only) ---
    # Credential harvesting in documentation
    (
        re.compile(
            r"(?:send|post|upload|transmit|exfiltrate|provide|submit|enter)\s+(?:your|all|the)\s+(?:api[_\s-]?key|token|password|secret|credential)",
            re.IGNORECASE,
        ),
        "credential_harvest_doc",
        "Documentation contains instructions to exfiltrate credentials. This is a known attack pattern.",
    ),
    # Links to suspicious shortened URLs
    (
        re.compile(r"https?://(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|rb\.gy)", re.IGNORECASE),
        "suspicious_shortened_url",
        "Documentation contains shortened URLs. Shortened URLs can hide malicious destinations.",
    ),
)

# High-risk model card patterns
_HIGH_RISK_MODEL_CARD_PATTERNS: frozenset[str] = frozenset(
    {
        "credential_harvest_doc",
        "suspicious_shortened_url",
    }
)


def analyze_model_card(
    text: str,
    relative: str,
    evidence: list[ConfigEvidence],
    limits: ConfigLimits,
) -> None:
    """Analyze model card documentation for suspicious patterns.

    This function checks for:
    - Suspicious claims (uncensored, perfect, bypass)
    - Missing critical information (license, training data)
    - Known malicious patterns (credential harvesting, untrusted code)
    """
    for pattern, kind, detail in _MODEL_CARD_PATTERNS:
        if len(evidence) >= limits.max_evidence:
            break
        match = pattern.search(text)
        if match:
            is_high_risk = kind in _HIGH_RISK_MODEL_CARD_PATTERNS
            _append_evidence(
                evidence,
                ConfigEvidence(
                    kind=f"model_card_{kind}",
                    path=relative,
                    detail=detail,
                    value=match.group(0)[:200],
                    trust_decision=True,
                    severity="high" if is_high_risk else "low",
                    runtime_relevance="not_used",
                ),
                limits,
            )


def inspect_companion_config(
    root: str | os.PathLike[str],
    *,
    runtime: str = "llama.cpp",
    limits: ConfigLimits = DEFAULT_CONFIG_LIMITS,
    artifact_name: str | None = None,
    available_digest: str | None = None,
    architecture: str | None = None,
    model_name: str | None = None,
) -> ConfigInspection:
    """Inspect a bounded set of companion files without executing any content.

    For ``llama.cpp``, Hugging Face remote-code settings and Ollama Modelfiles are
    recorded as trust decisions but marked as not used by direct GGUF loading.
    Adapter presence is conditionally relevant because llama.cpp loads one only
    when explicitly requested.
    """

    base = Path(root)
    if not base.is_dir():
        raise ValueError("root must be an existing directory")

    normalized_runtime = runtime.strip().lower()
    files: list[str] = []
    evidence: list[ConfigEvidence] = []
    errors: list[str] = []
    manifests: list[ManifestDeclaration] = []
    bytes_read = 0
    candidates_seen = 0
    limit_reached = False

    for path in _bounded_files(base, limits.max_depth):
        candidates_seen += 1
        if candidates_seen > limits.max_files:
            limit_reached = True
            break
        if not _is_companion(path):
            continue
        relative = path.relative_to(base).as_posix()
        files.append(relative)

        if path.suffix.lower() == ".py":
            _append_evidence(
                evidence,
                ConfigEvidence(
                    kind="python_code_present",
                    path=relative,
                    detail="Python code is present; mere presence does not mean it will execute.",
                    trust_decision=True,
                    severity="low",
                    runtime_relevance=(
                        "not_used" if normalized_runtime == "llama.cpp" else "conditional"
                    ),
                ),
                limits,
            )
            continue

        if _is_adapter(path):
            _append_evidence(
                evidence,
                ConfigEvidence(
                    kind="adapter_present",
                    path=relative,
                    detail=(
                        "An adapter companion is present and requires an explicit loading decision."
                    ),
                    trust_decision=True,
                    severity="low",
                    runtime_relevance="conditional",
                ),
                limits,
            )
            if path.suffix.lower() not in _TEXT_SUFFIXES:
                continue

        try:
            size = path.stat().st_size
        except OSError as exc:
            errors.append(f"Could not stat {relative}: {exc}")
            continue
        if size > limits.max_file_bytes:
            errors.append(
                f"Skipped {relative}: file exceeds the {limits.max_file_bytes}-byte limit."
            )
            limit_reached = True
            continue
        if bytes_read + size > limits.max_total_bytes:
            errors.append(
                f"Skipped {relative}: total inspection would exceed the "
                f"{limits.max_total_bytes}-byte limit."
            )
            limit_reached = True
            continue
        try:
            raw = path.read_bytes()
        except OSError as exc:
            errors.append(f"Could not read {relative}: {exc}")
            continue
        bytes_read += len(raw)

        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            errors.append(f"Could not decode {relative} as UTF-8: {exc}")
            continue

        if path.name.lower() == "modelfile":
            _inspect_modelfile(text, relative, normalized_runtime, evidence, limits)
            # Modelfile is plain text but its suffix is empty, so it falls
            # through the default branch below. Explicitly run the enhanced
            # companion patterns against the full body (api keys, AWS
            # credentials, exfiltration URLs, etc.).
            _inspect_rules_file_backdoor(text, relative, evidence, limits)
        if path.suffix.lower() == ".json":
            parsed_json = _inspect_json(
                text, relative, normalized_runtime, evidence, errors, limits
            )
            # Apply the enhanced companion patterns to JSON too. They are
            # written in JSON-shaped syntax precisely so the structural
            # decoder can also catch hardcoded credentials, exfiltration URLs,
            # trust_remote_code, and auto_map. The structural walker only
            # reports a small subset of those.
            _inspect_rules_file_backdoor(text, relative, evidence, limits)
            if _is_manifest(path) and parsed_json is not None:
                declaration = _parse_manifest_declaration(parsed_json, relative, errors)
                if declaration is not None:
                    manifests.append(declaration)
                    evidence.extend(
                        check_manifest_coherence(
                            declaration,
                            artifact_name=artifact_name,
                            available_digest=available_digest,
                            architecture=architecture,
                            model_name=model_name,
                        )[: max(0, limits.max_evidence - len(evidence))]
                    )
        else:
            parsed_json = None
        if _is_manifest(path) and path.suffix.lower() != ".json":
            _inspect_remote_references(text, relative, normalized_runtime, evidence, limits)

        # Rules File Backdoor detection (Pillar Security, 2025-03)
        # Files already classified as JSON are inspected structurally by
        # _inspect_json; re-scanning their raw text with the regexes would
        # double-report benign values (H2). Other text suffixes plus the
        # rules-file targets (``.cursorrules``, ``.github/copilot-instructions.md``)
        # are scanned via the regex set.
        if parsed_json is None and (
            path.suffix.lower() in _TEXT_SUFFIXES or _is_rules_file_target(path)
        ):
            _inspect_rules_file_backdoor(text, relative, evidence, limits)

        # Model card and documentation analysis (v0.5 Phase 3)
        if path.suffix.lower() == ".md" and (
            "readme" in path.name.lower()
            or "model_card" in path.name.lower()
            or "dataset_card" in path.name.lower()
        ):
            analyze_model_card(text, relative, evidence, limits)

    # Check for suspicious file types in the directory (supply chain)
    _check_suspicious_files(base, evidence, limits)

    if len(evidence) >= limits.max_evidence:
        limit_reached = True
        errors.append(f"Evidence was truncated at {limits.max_evidence} entries.")

    return ConfigInspection(
        root=base,
        files_inspected=tuple(sorted(files)),
        evidence=tuple(evidence),
        errors=tuple(errors),
        bytes_read=bytes_read,
        candidates_seen=min(candidates_seen, limits.max_files),
        limit_reached=limit_reached,
        manifests=tuple(manifests),
    )


def _check_suspicious_files(
    root: Path,
    evidence: list[ConfigEvidence],
    limits: ConfigLimits,
) -> None:
    """Check for suspicious file types in the directory."""
    suspicious_extensions = {".exe", ".bat", ".cmd", ".ps1", ".sh", ".vbs", ".wsf"}
    suspicious_patterns = [
        (re.compile(r"Q0_[KS]|Q0_0|Q1_[KS]", re.IGNORECASE), "impossible_quantization"),
    ]

    try:
        for entry in root.iterdir():
            if entry.is_file():
                # Check for suspicious extensions
                if entry.suffix.lower() in suspicious_extensions:
                    _append_evidence(
                        evidence,
                        ConfigEvidence(
                            kind="suspicious_file_type",
                            path=entry.name,
                            detail=f"Suspicious file type detected: {entry.suffix}",
                            value=entry.name,
                            severity="high",
                        ),
                        limits,
                    )
                # Check for suspicious patterns in filename
                for pattern, kind in suspicious_patterns:
                    if pattern.search(entry.name):
                        _append_evidence(
                            evidence,
                            ConfigEvidence(
                                kind=kind,
                                path=entry.name,
                                detail=f"Suspicious filename pattern detected: {entry.name}",
                                value=entry.name,
                                severity="high",
                            ),
                            limits,
                        )
    except OSError:
        pass


def _bounded_files(root: Path, max_depth: int) -> Iterator[Path]:
    pending: list[tuple[Path, int]] = [(root, 0)]
    while pending:
        directory, depth = pending.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name.lower())
        except OSError:
            continue
        directories: list[Path] = []
        for entry in entries:
            try:
                if entry.is_symlink():
                    continue
                if entry.is_file(follow_symlinks=False):
                    yield Path(entry.path)
                elif depth < max_depth and entry.is_dir(follow_symlinks=False):
                    directories.append(Path(entry.path))
            except OSError:
                continue
        pending.extend((item, depth + 1) for item in reversed(directories))


def _is_companion(path: Path) -> bool:
    name = path.name.lower()
    return (
        name in {"config.json", "tokenizer_config.json", "modelfile"}
        or name.startswith("readme")
        or "manifest" in name
        or path.suffix.lower() == ".py"
        or path.suffix.lower()
        in {".md", ".txt", ".yaml", ".yml", ".pem", ".key", ".cfg", ".ini", ".conf"}
        or _is_adapter(path)
        or _is_rules_file_target(path)
    )


def _is_rules_file_target(path: Path) -> bool:
    """Match the rules-file backdoor targets explicitly.

    ``.cursorrules`` has no suffix; ``.github/copilot-instructions.md``
    lives inside a dot-folder so a plain suffix check misses it.
    """
    name = path.name.lower()
    if name in {".cursorrules", "rules.md"}:
        return True
    posix = path.as_posix().lower()
    return posix == ".github/copilot-instructions.md" or posix.endswith(
        "/.github/copilot-instructions.md"
    )


def _is_adapter(path: Path) -> bool:
    name = path.name.lower()
    return "adapter" in name and path.suffix.lower() in _ADAPTER_SUFFIXES


def _is_manifest(path: Path) -> bool:
    return "manifest" in path.name.lower()


def _append_evidence(
    evidence: list[ConfigEvidence], item: ConfigEvidence, limits: ConfigLimits
) -> None:
    if len(evidence) < limits.max_evidence:
        evidence.append(item)


def _inspect_json(
    text: str,
    relative: str,
    runtime: str,
    evidence: list[ConfigEvidence],
    errors: list[str],
    limits: ConfigLimits,
) -> Any | None:
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        errors.append(f"Could not parse {relative} as JSON: {exc}")
        return None

    try:
        entries = tuple(_walk_json(value, max_depth=limits.max_json_depth))
    except ValueError as exc:
        errors.append(f"Could not fully inspect {relative}: {exc}")
        return None

    for json_path, key, item in entries:
        relevance = "not_used" if runtime == "llama.cpp" else "conditional"
        if key == "auto_map" and bool(item):
            _append_evidence(
                evidence,
                ConfigEvidence(
                    kind="auto_map",
                    path=relative,
                    detail=f"{json_path} delegates model classes to custom code.",
                    value=item,
                    trust_decision=True,
                    severity="low",
                    runtime_relevance=relevance,
                ),
                limits,
            )
        elif key == "trust_remote_code" and item is True:
            _append_evidence(
                evidence,
                ConfigEvidence(
                    kind="trust_remote_code",
                    path=relative,
                    detail=f"{json_path} opts into remote code for runtimes that honor it.",
                    value=True,
                    trust_decision=True,
                    severity="low",
                    runtime_relevance=relevance,
                ),
                limits,
            )
        if isinstance(item, str) and _REMOTE_REFERENCE.search(item):
            pinned = bool(_PINNED_SHA256.search(item))
            _append_evidence(
                evidence,
                ConfigEvidence(
                    kind="remote_reference_pinned" if pinned else "remote_reference_unpinned",
                    path=relative,
                    detail=(
                        f"{json_path} contains a remote reference"
                        + (" pinned by SHA-256." if pinned else " without a SHA-256 pin.")
                    ),
                    value=item,
                    trust_decision=True,
                    severity="info" if pinned else "low",
                    runtime_relevance=relevance,
                ),
                limits,
            )
    return value


def _walk_json(
    value: Any, *, max_depth: int, path: str = "$", depth: int = 0
) -> Iterator[tuple[str, str | None, Any]]:
    if depth > max_depth:
        raise ValueError(f"JSON nesting exceeds the {max_depth}-level limit")
    if isinstance(value, dict):
        for key in sorted(value, key=str):
            item = value[key]
            item_path = f"{path}.{key}"
            yield item_path, str(key), item
            yield from _walk_json(item, max_depth=max_depth, path=item_path, depth=depth + 1)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            item_path = f"{path}[{index}]"
            yield item_path, None, item
            yield from _walk_json(item, max_depth=max_depth, path=item_path, depth=depth + 1)


def _inspect_modelfile(
    text: str,
    relative: str,
    runtime: str,
    evidence: list[ConfigEvidence],
    limits: ConfigLimits,
) -> None:
    relevance = "not_used" if runtime == "llama.cpp" else "conditional"
    for match in _FROM.finditer(text):
        reference = match.group(1).strip("\"'")
        if _is_local_from(reference):
            continue
        pinned = bool(_PINNED_SHA256.search(reference))
        _append_evidence(
            evidence,
            ConfigEvidence(
                kind="modelfile_from_pinned" if pinned else "modelfile_from_unpinned",
                path=relative,
                detail=(
                    "Modelfile FROM selects a non-local source"
                    + (" pinned by SHA-256." if pinned else " without a SHA-256 pin.")
                ),
                value=reference,
                trust_decision=True,
                severity="info" if pinned else "low",
                runtime_relevance=relevance,
            ),
            limits,
        )


def _is_local_from(reference: str) -> bool:
    return reference.startswith(("./", "../", "/", "file://"))


def _inspect_remote_references(
    text: str,
    relative: str,
    runtime: str,
    evidence: list[ConfigEvidence],
    limits: ConfigLimits,
) -> None:
    relevance = "not_used" if runtime == "llama.cpp" else "conditional"
    for match in _REMOTE_REFERENCE.finditer(text):
        end = text.find("\n", match.start())
        snippet = text[match.start() : end if end >= 0 else len(text)].strip(" \"',")[:512]
        pinned = bool(_PINNED_SHA256.search(snippet))
        _append_evidence(
            evidence,
            ConfigEvidence(
                kind="remote_reference_pinned" if pinned else "remote_reference_unpinned",
                path=relative,
                detail=(
                    "Manifest contains a remote reference"
                    + (" pinned by SHA-256." if pinned else " without a SHA-256 pin.")
                ),
                value=snippet,
                trust_decision=True,
                severity="info" if pinned else "low",
                runtime_relevance=relevance,
            ),
            limits,
        )


def _parse_manifest_declaration(
    data: dict[str, Any], relative: str, errors: list[str]
) -> ManifestDeclaration | None:
    """Extract a manifest declaration from a JSON file if it looks like one."""
    artifact = data.get("artifact") or data.get("model") or data.get("file")
    if not isinstance(artifact, str):
        return None
    return ManifestDeclaration(
        path=relative,
        artifact=artifact,
        sha256=data.get("sha256") if isinstance(data.get("sha256"), str) else None,
        architecture=data.get("architecture")
        if isinstance(data.get("architecture"), str)
        else None,
        name=data.get("name") if isinstance(data.get("name"), str) else None,
    )


def check_manifest_coherence(
    declaration: ManifestDeclaration,
    *,
    artifact_name: str | None = None,
    available_digest: str | None = None,
    architecture: str | None = None,
    model_name: str | None = None,
) -> tuple[ConfigEvidence, ...]:
    """Compare a manifest declaration against observed artifact facts."""
    evidence: list[ConfigEvidence] = []
    if declaration.sha256 and available_digest:
        match = declaration.sha256.lower() == available_digest.lower()
        evidence.append(
            ConfigEvidence(
                kind="digest_match" if match else "digest_mismatch",
                path=declaration.path,
                detail=(
                    "Manifest digest matches the artifact."
                    if match
                    else "Manifest digest does not match the artifact."
                ),
                value={"declared": declaration.sha256, "actual": available_digest},
                severity="info" if match else "low",
                # A manifest digest comparison is always directly applicable
                # to the inspected artifact, regardless of which runtime
                # consumes the model.
                runtime_relevance="direct",
            )
        )
    if declaration.architecture and architecture:
        match = declaration.architecture == architecture
        evidence.append(
            ConfigEvidence(
                kind="architecture_match" if match else "architecture_mismatch",
                path=declaration.path,
                detail=(
                    "Manifest architecture matches the artifact."
                    if match
                    else "Manifest architecture does not match the artifact."
                ),
                value={"declared": declaration.architecture, "actual": architecture},
                severity="info" if match else "low",
            )
        )
    if declaration.name and model_name:
        match = declaration.name == model_name
        evidence.append(
            ConfigEvidence(
                kind="name_match" if match else "name_mismatch",
                path=declaration.path,
                detail=(
                    "Manifest name matches the artifact."
                    if match
                    else "Manifest name does not match the artifact."
                ),
                value={"declared": declaration.name, "actual": model_name},
                severity="info" if match else "low",
            )
        )
    return tuple(evidence)


def _inspect_rules_file_backdoor(
    text: str,
    relative: str,
    evidence: list[ConfigEvidence],
    limits: ConfigLimits,
) -> None:
    """Detect Rules File Backdoor patterns (Pillar Security, 2025-03).

    This attack vector uses malicious instructions in configuration/rules files
    that AI code editors and tools consume, turning them into attack vectors.

    Also includes enhanced security patterns for v0.5:
    - Pickle deserialization risks (JFrog, ReversingLabs)
    - MCP server configuration risks (arXiv 2603.21642)
    - Hardcoded credentials
    - Remote code execution in configs
    - Network exfiltration patterns
    - Tokenizer manipulation
    """
    # Check original Rules File Backdoor patterns
    for pattern, kind, detail in _RULES_FILE_PATTERNS:
        if len(evidence) >= limits.max_evidence:
            break
        match = pattern.search(text)
        if match:
            is_high_risk = kind in _HIGH_RISK_RULES_PATTERNS
            _append_evidence(
                evidence,
                ConfigEvidence(
                    kind=f"rules_backdoor_{kind}",
                    path=relative,
                    detail=detail,
                    value=match.group(0)[:200],
                    trust_decision=True,
                    severity="high" if is_high_risk else "low",
                    runtime_relevance="conditional",
                ),
                limits,
            )
            break  # Only report first match per file

    # Check enhanced companion security patterns (v0.5)
    for pattern, kind, detail in _ENHANCED_COMPANION_PATTERNS:
        if len(evidence) >= limits.max_evidence:
            break
        match = pattern.search(text)
        if match:
            is_high_risk = kind in _HIGH_RISK_ENHANCED_COMPANION_PATTERNS
            _append_evidence(
                evidence,
                ConfigEvidence(
                    kind=f"companion_security_{kind}",
                    path=relative,
                    detail=detail,
                    value=match.group(0)[:200],
                    trust_decision=True,
                    severity="high" if is_high_risk else "low",
                    runtime_relevance="conditional",
                ),
                limits,
            )


def detect_template_mismatch_across_files(
    root: str | os.PathLike[str],
    *,
    limits: ConfigLimits = DEFAULT_CONFIG_LIMITS,
) -> list[ConfigEvidence]:
    """Detect Hugging Face UI Blindspot: different templates across GGUF files.

    Pillar Security (2025-07) discovered that attackers can place a clean template
    in the first GGUF file while hiding malicious templates in subsequent files.
    This function compares templates across GGUF files in the same directory.
    """
    from cancerbero.gguf.inspector import inspect_gguf
    from cancerbero.gguf.limits import DEFAULT_LIMITS as GGUF_LIMITS

    base = Path(root)
    if not base.is_dir():
        return []

    gguf_files: list[Path] = []
    for path in _bounded_files(base, limits.max_depth):
        if path.suffix.lower() == ".gguf":
            gguf_files.append(path)
        if len(gguf_files) >= 10:  # Limit comparison to 10 files
            break

    if len(gguf_files) < 2:
        return []

    templates: dict[str, str] = {}  # path -> template
    for gguf_path in gguf_files:
        try:
            facts, _ = inspect_gguf(gguf_path, limits=GGUF_LIMITS)
            if facts.chat_template:
                templates[str(gguf_path.relative_to(base))] = facts.chat_template
        except Exception:
            continue

    if len(templates) < 2:
        return []

    # Compare templates across files
    evidence: list[ConfigEvidence] = []
    template_values = list(templates.values())
    first_template = template_values[0]

    for path_str, template in templates.items():
        if template != first_template:
            evidence.append(
                ConfigEvidence(
                    kind="template_mismatch_across_files",
                    path=path_str,
                    detail=(
                        "Different chat template found across GGUF files in the same directory. "
                        "This is a known attack vector (Pillar Security, 2025-07) where "
                        "attackers hide malicious templates in quantized variants."
                    ),
                    value={
                        "file": path_str,
                        "template_length": len(template),
                        "first_file_template_length": len(first_template),
                    },
                    trust_decision=True,
                    severity="high",
                    runtime_relevance="direct",
                )
            )

    return evidence


# Descriptive aliases for callers that inspect directories rather than one config.
inspect_companion_files = inspect_companion_config
inspect_config = inspect_companion_config
