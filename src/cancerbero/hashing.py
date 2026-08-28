"""Separate, streamed SHA-256 calculation for complete artifact files."""

from __future__ import annotations

import hashlib
import hmac
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

_SHA256_HEX_LENGTH = 64
DEFAULT_CHUNK_SIZE = 1024 * 1024


@dataclass(frozen=True, slots=True)
class HashResult:
    """Result and measured I/O cost of one complete streaming hash pass.

    ``matches`` is ``None`` when no expected digest was supplied. Throughput is
    reported in bytes per second and is zero if the injected clock has no elapsed
    resolution.
    """

    path: Path
    digest: str
    expected_digest: str | None
    matches: bool | None
    bytes_read: int
    duration_seconds: float
    throughput_bytes_per_second: float
    algorithm: str = "sha256"

    @property
    def sha256(self) -> str:
        return self.digest

    @property
    def finding(self):  # type annotation omitted to keep domain import lazy
        """Return the provenance Finding represented by this result."""

        from cancerbero.domain import Confidence, Finding, Severity, Status

        evidence = {
            "algorithm": self.algorithm,
            "digest": self.digest,
            "expected_digest": self.expected_digest,
            "bytes_read": self.bytes_read,
        }
        if self.expected_digest is None:
            return Finding(
                id="cbr.identity.digest_absent",
                head="provenance",
                check="sha256",
                status=Status.UNCHECKED,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                summary="SHA-256 was calculated, but no expected digest was supplied.",
                evidence=evidence,
                mandatory=False,
            )
        if self.matches:
            return Finding(
                id="cbr.identity.digest_match",
                head="provenance",
                check="sha256",
                status=Status.VERIFIED,
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                summary="SHA-256 matches the expected digest.",
                evidence=evidence,
            )
        return Finding(
            id="cbr.identity.digest_mismatch",
            head="provenance",
            check="sha256",
            status=Status.SUSPICIOUS,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            summary="SHA-256 does not match the expected digest.",
            evidence=evidence,
            action="Do not load the artifact; obtain it again from a trusted source.",
        )


def validate_expected_sha256(expected: str) -> str:
    """Validate and normalize an expected SHA-256 digest.

    Exactly 64 ASCII hexadecimal characters are accepted. Leading or trailing
    whitespace is rejected rather than silently changing the declared digest.
    """

    if not isinstance(expected, str):
        raise TypeError("expected SHA-256 digest must be a string")
    if len(expected) != _SHA256_HEX_LENGTH or any(
        character not in "0123456789abcdefABCDEF" for character in expected
    ):
        raise ValueError("expected SHA-256 digest must contain exactly 64 hexadecimal characters")
    return expected.lower()


def hash_file(
    path: str | os.PathLike[str],
    expected: str | None = None,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    clock: Callable[[], float] = time.perf_counter,
) -> HashResult:
    """Stream a complete file through SHA-256 in a phase separate from metadata.

    Expected digest comparison uses :func:`hmac.compare_digest`. The function
    reports the full bytes read, elapsed duration, and measured throughput.
    """

    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    normalized_expected = validate_expected_sha256(expected) if expected is not None else None
    file_path = Path(path)
    digest = hashlib.sha256()
    bytes_read = 0
    buffer = bytearray(chunk_size)
    view = memoryview(buffer)

    started = clock()
    with file_path.open("rb", buffering=0) as stream:
        while True:
            count = stream.readinto(buffer)
            if not count:
                break
            digest.update(view[:count])
            bytes_read += count
    duration = max(0.0, clock() - started)
    actual = digest.hexdigest()
    matches = (
        hmac.compare_digest(actual, normalized_expected)
        if normalized_expected is not None
        else None
    )
    throughput = bytes_read / duration if duration > 0.0 else 0.0
    return HashResult(
        path=file_path,
        digest=actual,
        expected_digest=normalized_expected,
        matches=matches,
        bytes_read=bytes_read,
        duration_seconds=duration,
        throughput_bytes_per_second=throughput,
    )


stream_sha256 = hash_file
