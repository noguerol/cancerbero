"""Convert a validated GGUF document into domain-level artifact facts."""

from __future__ import annotations

import re
from pathlib import Path

from cancerbero.domain import ArtifactFacts, Confidence, Finding, Severity, Status, TensorDescriptor
from cancerbero.gguf.limits import DEFAULT_LIMITS, ParserLimits
from cancerbero.gguf.reader import GgufDocument, read_gguf

# Patterns that might indicate suspicious metadata.
# ``URL in metadata`` is suppressed on a small allowlist of well-known
# benign GGUF keys (``general.source.url``, ``general.license.link`` ...)
# because every modern model carries those fields and emitting a finding
# per model drowned legitimate reports (blue finding from the external
# audit).
_SUSPICIOUS_PATTERNS = [
    (re.compile(r"https?://", re.IGNORECASE), "URL in metadata"),
    (re.compile(r"eval\s*\(", re.IGNORECASE), "eval() call in metadata"),
    (re.compile(r"exec\s*\(", re.IGNORECASE), "exec() call in metadata"),
    (re.compile(r"os\.system", re.IGNORECASE), "os.system call in metadata"),
    (re.compile(r"subprocess", re.IGNORECASE), "subprocess reference in metadata"),
    (re.compile(r"__import__", re.IGNORECASE), "__import__ in metadata"),
    (re.compile(r"socket\.", re.IGNORECASE), "socket reference in metadata"),
]
_URL_ALLOWLIST_KEYS = frozenset(
    {
        "general.source.url",
        "general.url",
        "general.license.link",
        "general.homepage",
        "general.repository",
        "general.documentation",
        "general.base_model.repo",
    }
)


def _check_metadata_safety(doc: GgufDocument) -> list[Finding]:
    """Check for suspicious patterns in metadata values."""
    from cancerbero.domain import Confidence, Severity, Status

    findings: list[Finding] = []
    for key, value in doc.metadata.items():
        if not isinstance(value, str):
            continue
        for pattern, description in _SUSPICIOUS_PATTERNS:
            # Suppress the noisy ``URL in metadata`` finding on the small
            # allowlist of benign provenance keys.
            if pattern.pattern == r"https?://" and key.lower() in _URL_ALLOWLIST_KEYS:
                continue
            if pattern.search(value):
                findings.append(
                    Finding(
                        id=f"cbr.gguf.metadata_pattern.{key}",
                        head="loading",
                        check="gguf_metadata_safety",
                        status=Status.UNCHECKED,
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        summary=(f"Metadata key '{key}' contains {description.lower()}"),
                        evidence={
                            "key": key,
                            "pattern": description,
                            "value_preview": value[:200],
                        },
                        mandatory=False,
                    )
                )
                break  # Only report first match per key
    return findings


def inspect_gguf(
    path: str | Path,
    *,
    limits: ParserLimits = DEFAULT_LIMITS,
) -> tuple[ArtifactFacts, list[Finding]]:
    """Read and validate a GGUF file, returning domain facts without tensor bytes.

    Returns a tuple of (ArtifactFacts, list[Finding]) where findings include
    any structural warnings or suspicious metadata patterns detected.
    """

    doc: GgufDocument = read_gguf(path, limits)
    findings: list[Finding] = []

    # Record successful GGUF parsing as a core check result
    findings.append(
        Finding(
            id="cbr.gguf.parsed",
            head="loading",
            check="gguf_structure",
            status=Status.CLEAN,
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            summary="GGUF file parsed successfully.",
            evidence={
                "version": doc.version,
                "tensor_count": doc.tensor_count,
                "metadata_count": doc.metadata_count,
            },
            mandatory=False,
        )
    )

    # Check for suspicious metadata patterns
    findings.extend(_check_metadata_safety(doc))

    # Quantization integrity findings that COULD have been emitted here are
    # all provably dead: the reader raises ``GgufTypeError`` for unknown
    # tensor types, ``GgufRangeError`` for misaligned offsets, and
    # ``GgufValidationError`` for zero-sized dimensions. By the time we
    # reach this point every tensor descriptor already passed those checks.
    # The previous ``_check_quantization_integrity`` and zero-dimension
    # loops therefore produced no findings against real GGUF files; their
    # tests passed only because they constructed ``GgufDocument`` objects
    # in memory, bypassing the reader. See docs/decisions for the rationale.

    tensors = [
        TensorDescriptor(
            name=t.name,
            dimensions=t.dimensions,
            ggml_type=t.ggml_type,
            offset=t.offset,
            byte_size=t.byte_size,
        )
        for t in doc.tensors
    ]

    facts = ArtifactFacts(
        path=doc.path,
        file_size=doc.file_size,
        gguf_version=doc.version,
        tensor_count=doc.tensor_count,
        metadata_count=doc.metadata_count,
        metadata_end=doc.metadata_end,
        tensor_data_offset=doc.tensor_data_offset,
        alignment=doc.alignment,
        architecture=doc.metadata.get("general.architecture"),
        name=doc.metadata.get("general.name"),
        file_type=doc.metadata.get("general.file_type"),
        quantization_version=doc.metadata.get("general.quantization_version"),
        chat_template=doc.metadata.get("tokenizer.chat_template"),
        metadata=doc.metadata,
        tensors=tensors,
        bytes_read=doc.bytes_read,
        omitted_metadata_keys=doc.omitted_metadata_keys,
    )

    # Surface coverage gaps so the operator knows metadata was inspected
    # incompletely. We emit one finding per omitted key with a stable id
    # (no counters, no per-instance variation) so deduplication and
    # --explain continue to work.
    if doc.omitted_metadata_keys:
        findings.append(
            Finding(
                id="cbr.gguf.metadata_omitted",
                head="loading",
                check="gguf_structure",
                status=Status.UNCHECKED,
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                summary=(
                    f"Parser retained {doc.metadata_count - len(doc.omitted_metadata_keys)}"
                    f" of {doc.metadata_count} metadata keys; {len(doc.omitted_metadata_keys)}"
                    " key(s) were skipped because the retained-metadata budget"
                    f" ({doc.metadata_end} bytes analysed, {len(doc.omitted_metadata_keys)}"
                    " omitted). Re-run with stricter limits or trust the model source."
                ),
                evidence={
                    "omitted_keys": list(doc.omitted_metadata_keys),
                    "retained_count": doc.metadata_count - len(doc.omitted_metadata_keys),
                    "metadata_count": doc.metadata_count,
                },
                mandatory=False,
            )
        )

    return facts, findings


__all__ = ["inspect_gguf"]
