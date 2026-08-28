"""Static-first inspection of explicitly selected llama.cpp runtimes."""

from __future__ import annotations

import os
import re
import stat
import subprocess
import tempfile
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from cancerbero.discovery import is_known_llama_cpp_name
from cancerbero.domain import Confidence, RuntimeFacts
from cancerbero.gguf.limits import DEFAULT_LIMITS, ParserLimits

_MAX_IDENTITY_FILE_BYTES = 64 * 1024
_MAX_STATIC_BINARY_BYTES = 4 * 1024 * 1024
_MAX_PE_HEADER_OFFSET = 1024 * 1024
_NEARBY_LEVELS = 4

_IDENTITY_FILENAMES = (
    "build-info.json",
    "build-info.txt",
    "build_info.json",
    "build_info.txt",
    "llama-build-info.txt",
    "llama-version.txt",
    "version.txt",
    "build.txt",
    "CMakeCache.txt",
)

_BUILD_PATTERNS = (
    re.compile(r"(?i)\b(?:llama[_ .-]*)?build(?:[_ .-]*(?:number|no))?\s*[:= -]\s*b?(\d+)\b"),
    re.compile(r"(?i)\bversion\s*[:= -]\s*b(\d+)\b"),
    re.compile(r"(?im)^\s*b(\d+)\s*$"),
    re.compile(r"(?im)\bversion\s*[:= -]\s*(\d+)\s*(?:\(|$)"),
)
_VERSION_PATTERNS = (
    re.compile(
        r"(?i)\b(?:llama(?:\.cpp)?[_ .-]*)?version"
        r"\s*[:= -]\s*v?"
        r"([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-+][0-9A-Za-z.-]+)?)"
    ),
    re.compile(
        r"(?i)\bllama(?:\.cpp)?[/ _-]v?([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-+][0-9A-Za-z.-]+)?)"
    ),
)
_COMMIT_PATTERNS = (
    re.compile(r"(?i)\b(?:git[_ .-]*)?(?:commit|revision|rev)\s*[:= -]\s*([0-9a-f]{7,40})\b"),
    re.compile(r"(?i)\b(?:build|version)\s*[:= -]\s*\d+\s*\(([0-9a-f]{7,40})\)"),
)
_FLAGS_LINE = re.compile(r"(?im)^\s*flags?\s*[:=]\s*(.+?)\s*$")
_OVERRIDE_BUILD = re.compile(r"(?i)^\s*(?:build\s*[:= -]?\s*)?b?(\d+)\s*$")
_OVERRIDE_COMMIT = re.compile(r"(?i)^\s*(?:commit\s*[:= -]?\s*)?([0-9a-f]{7,40})\s*$")
_OVERRIDE_VERSION = re.compile(
    r"(?i)^\s*(?:version\s*[:= -]?\s*)?v?"
    r"([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-+][0-9A-Za-z.-]+)?)\s*$"
)

_MACH_O_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf",
    b"\xbf\xba\xfe\xca",
}


class RuntimeInspectionError(ValueError):
    """Raised when runtime inspection cannot be performed safely."""


@dataclass(frozen=True, slots=True)
class _Identity:
    version: str | None = None
    build: int | None = None
    commit: str | None = None

    @property
    def identified(self) -> bool:
        return self.version is not None or self.build is not None or self.commit is not None


def _read_bounded(path: Path, maximum: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        return b""
    try:
        with path.open("rb") as stream:
            return stream.read(maximum)
    except OSError:
        return b""


def detect_executable_format(path: str | os.PathLike[str]) -> str | None:
    """Identify ELF, PE, or Mach-O from bounded header reads."""

    candidate = Path(path)
    header = _read_bounded(candidate, 64)
    if header.startswith(b"\x7fELF"):
        return "ELF"
    if header[:4] in _MACH_O_MAGICS:
        return "Mach-O"
    if not header.startswith(b"MZ"):
        return None

    # Validate PE\0\0 when the DOS header supplies a bounded offset. Tiny test
    # fixtures and some wrappers only expose MZ, which is still recognizably PE.
    if len(header) >= 64:
        pe_offset = int.from_bytes(header[60:64], "little")
        if pe_offset <= _MAX_PE_HEADER_OFFSET:
            try:
                with candidate.open("rb") as stream:
                    stream.seek(pe_offset)
                    if stream.read(4) == b"PE\x00\x00":
                        return "PE"
            except OSError:
                return None
    return "PE"


def _parse_identity(text: str, *, override: bool = False) -> _Identity:
    stripped = text.strip()
    if not stripped:
        return _Identity()

    if override:
        match = _OVERRIDE_BUILD.fullmatch(stripped)
        if match:
            return _Identity(build=int(match.group(1)))
        match = _OVERRIDE_VERSION.fullmatch(stripped)
        if match:
            return _Identity(version=match.group(1))
        match = _OVERRIDE_COMMIT.fullmatch(stripped)
        if match:
            return _Identity(commit=match.group(1).lower())

    build: int | None = None
    version: str | None = None
    commit: str | None = None
    for pattern in _BUILD_PATTERNS:
        match = pattern.search(stripped)
        if match:
            build = int(match.group(1))
            break
    for pattern in _VERSION_PATTERNS:
        match = pattern.search(stripped)
        if match:
            version = match.group(1)
            break
    for pattern in _COMMIT_PATTERNS:
        match = pattern.search(stripped)
        if match:
            commit = match.group(1).lower()
            break
    return _Identity(version=version, build=build, commit=commit)


def _parse_override(value: str | int) -> _Identity:
    identity = _parse_identity(str(value), override=True)
    if not identity.identified:
        # Explicit input is retained as an opaque version rather than guessed
        # into the build, tag, or commit namespace.
        identity = _Identity(version=str(value).strip())
    return identity


def _nearby_directories(binary: Path) -> tuple[Path, ...]:
    directories: list[Path] = []
    current = binary.parent
    for _ in range(_NEARBY_LEVELS + 1):
        if current in directories:
            break
        directories.append(current)
        if current.parent == current:
            break
        current = current.parent
    return tuple(directories)


def _nearby_texts(binary: Path) -> Iterator[tuple[str, str]]:
    """Yield ``(filename, decoded text)`` pairs for nearby build-info files."""

    for directory in _nearby_directories(binary):
        for filename in _IDENTITY_FILENAMES:
            candidate = directory / filename
            data = _read_bounded(candidate, _MAX_IDENTITY_FILE_BYTES)
            if data:
                yield filename, data.decode("utf-8", errors="replace")


def _flags_from_text(text: str) -> tuple[str, ...]:
    """Extract a whitespace-separated flags line from a build-info file."""

    match = _FLAGS_LINE.search(text)
    if not match:
        return ()
    return tuple(match.group(1).split())


def _flags_from_nearby_files(binary: Path) -> tuple[str, ...]:
    """Infer runtime command-line flags from nearby build-info files.

    Structured JSON build-info may carry a ``flags`` list; text build-info
    may carry a ``flags:`` line. Only string tokens are accepted, and only
    from bounded nearby files, so this is a conservative inference.
    """

    import json as _json

    for filename, text in _nearby_texts(binary):
        if filename.endswith(".json"):
            try:
                obj = _json.loads(text)
                if isinstance(obj, dict):
                    raw = obj.get("flags")
                    if isinstance(raw, list) and all(isinstance(item, str) for item in raw):
                        return tuple(raw)
            except (ValueError, _json.JSONDecodeError):
                pass
        flags = _flags_from_text(text)
        if flags:
            return flags
    return ()


def _identity_from_nearby_files(binary: Path) -> _Identity:
    import json as _json

    for filename, text in _nearby_texts(binary):
        # Try JSON first for structured build-info files
        if filename.endswith(".json"):
            try:
                obj = _json.loads(text)
                if isinstance(obj, dict):
                    build = obj.get("build")
                    commit = obj.get("commit")
                    version = obj.get("version")
                    if (
                        isinstance(build, int)
                        or isinstance(commit, str)
                        or isinstance(version, str)
                    ):
                        return _Identity(
                            version=str(version) if isinstance(version, str) else None,
                            build=build if isinstance(build, int) else None,
                            commit=commit.lower() if isinstance(commit, str) else None,
                        )
            except (ValueError, _json.JSONDecodeError):
                pass
        identity = _parse_identity(text)
        if identity.identified:
            return identity
    return _Identity()


def _resolve_git_directory(dot_git: Path) -> Path | None:
    if dot_git.is_symlink():
        return None
    if dot_git.is_dir():
        return dot_git
    data = _read_bounded(dot_git, 4096).decode("utf-8", errors="replace").strip()
    if not data.lower().startswith("gitdir:"):
        return None
    location = Path(data.split(":", 1)[1].strip())
    if not location.is_absolute():
        location = dot_git.parent / location
    try:
        resolved = location.resolve(strict=True)
    except OSError:
        return None
    return resolved if resolved.is_dir() else None


def _commit_from_git_directory(git_directory: Path) -> str | None:
    head = _read_bounded(git_directory / "HEAD", 4096).decode("ascii", errors="ignore").strip()
    if re.fullmatch(r"[0-9a-fA-F]{40}", head):
        return head.lower()
    if not head.startswith("ref:"):
        return None

    reference = head.split(":", 1)[1].strip()
    if reference.startswith("/") or ".." in Path(reference).parts:
        return None
    value = _read_bounded(git_directory / reference, 4096).decode("ascii", errors="ignore").strip()
    if re.fullmatch(r"[0-9a-fA-F]{40}", value):
        return value.lower()

    packed = _read_bounded(git_directory / "packed-refs", _MAX_IDENTITY_FILE_BYTES)
    for line in packed.decode("ascii", errors="ignore").splitlines():
        if line.startswith(("#", "^")):
            continue
        fields = line.split(" ", 1)
        if (
            len(fields) == 2
            and fields[1] == reference
            and re.fullmatch(r"[0-9a-fA-F]{40}", fields[0])
        ):
            return fields[0].lower()
    return None


def _identity_from_git(binary: Path) -> _Identity:
    for directory in _nearby_directories(binary):
        git_directory = _resolve_git_directory(directory / ".git")
        if git_directory is None:
            continue
        commit = _commit_from_git_directory(git_directory)
        if commit is not None:
            return _Identity(commit=commit)
    return _Identity()


def _identity_from_static_binary(binary: Path) -> _Identity:
    data = _read_bounded(binary, _MAX_STATIC_BINARY_BYTES)
    if not data:
        return _Identity()
    # NULs and control bytes delimit compiled strings. The parser only accepts
    # labelled values, avoiding arbitrary numeric constants in executable code.
    text = re.sub(r"[^\x20-\x7e]+", "\n", data.decode("latin-1", errors="ignore"))
    return _parse_identity(text)


def _minimal_environment() -> dict[str, str]:
    environment = {"LANG": "C", "LC_ALL": "C"}
    if os.name == "nt":
        for name in ("SYSTEMROOT", "WINDIR"):
            if name in os.environ:
                environment[name] = os.environ[name]
    return environment


def _run_version(binary: Path, limits: ParserLimits) -> str:
    """Run one explicitly authorized runtime with a bounded combined stream."""

    output = bytearray()
    output_limit_reached = threading.Event()
    reader_error: list[BaseException] = []

    with tempfile.TemporaryDirectory(prefix="cancerbero-runtime-") as temporary_cwd:
        try:
            process = subprocess.Popen(  # noqa: S603 - explicit opt-in, no shell
                [os.fspath(binary), "--version"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=temporary_cwd,
                env=_minimal_environment(),
            )
        except OSError as error:
            raise RuntimeInspectionError(f"Cannot execute runtime {binary}: {error}") from error

        assert process.stdout is not None

        def read_output() -> None:
            try:
                while True:
                    chunk = process.stdout.read(8192)
                    if not chunk:
                        break
                    remaining = limits.max_subprocess_output_bytes - len(output)
                    if remaining <= 0:
                        output_limit_reached.set()
                        process.kill()
                        break
                    output.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        output_limit_reached.set()
                        process.kill()
                        break
            except BaseException as error:  # pragma: no cover - defensive pipe failure
                reader_error.append(error)
                process.kill()

        reader = threading.Thread(target=read_output, name="cancerbero-runtime-output", daemon=True)
        reader.start()
        try:
            process.wait(timeout=limits.subprocess_timeout_seconds)
        except subprocess.TimeoutExpired as error:
            process.kill()
            process.wait()
            reader.join(timeout=1.0)
            process.stdout.close()
            raise RuntimeInspectionError(
                "Runtime version command timed out after "
                f"{limits.subprocess_timeout_seconds:g} seconds"
            ) from error
        reader.join(timeout=1.0)
        process.stdout.close()

    if reader_error:
        raise RuntimeInspectionError(f"Cannot capture runtime version output: {reader_error[0]}")
    if output_limit_reached.is_set():
        raise RuntimeInspectionError(
            "Runtime version output exceeded the combined "
            f"{limits.max_subprocess_output_bytes} byte limit"
        )
    return output.decode("utf-8", errors="replace")


def _component_name(path: Path) -> str:
    name = path.name
    if name.casefold().endswith(".exe"):
        name = name[:-4]
    return name if is_known_llama_cpp_name(name) else "unknown"


def inspect_runtime(
    path: str | os.PathLike[str],
    *,
    version_override: str | int | None = None,
    allow_execution: bool = False,
    limits: ParserLimits = DEFAULT_LIMITS,
) -> RuntimeFacts:
    """Inspect an explicitly supplied runtime, preferring non-executing sources.

    Identity source order is: explicit override, nearby build/version files,
    nearby Git metadata, bounded binary strings, and finally ``--version`` when
    ``allow_execution`` is true. Passing a discovered path without that opt-in
    can therefore never execute it.
    """

    original = Path(path)
    if not original.exists():
        raise RuntimeInspectionError(f"Runtime does not exist: {original}")
    try:
        binary = original.resolve(strict=True)
    except OSError as error:
        raise RuntimeInspectionError(f"Cannot resolve runtime {original}: {error}") from error
    if not binary.is_file():
        raise RuntimeInspectionError(f"Runtime is not a regular file: {original}")

    try:
        file_stat = binary.stat()
    except OSError as error:
        raise RuntimeInspectionError(f"Cannot stat runtime {original}: {error}") from error

    facts = RuntimeFacts(
        path=original,
        component=_component_name(original),
        executable_format=detect_executable_format(binary),
        writable_by_group=bool(file_stat.st_mode & stat.S_IWGRP),
        writable_by_others=bool(file_stat.st_mode & stat.S_IWOTH),
        flags=_flags_from_nearby_files(binary),
    )

    identity = _Identity()
    if version_override is not None:
        identity = _parse_override(version_override)
        facts.detection_method = "explicit_override"
        facts.confidence = Confidence.HIGH
    else:
        identity = _identity_from_nearby_files(binary)
        if identity.identified:
            facts.detection_method = "nearby_build_file"
            facts.confidence = Confidence.HIGH
        else:
            identity = _identity_from_git(binary)
            if identity.identified:
                facts.detection_method = "git_metadata"
                facts.confidence = Confidence.MEDIUM
            else:
                identity = _identity_from_static_binary(binary)
                if identity.identified:
                    facts.detection_method = "static_binary_strings"
                    facts.confidence = Confidence.LOW
                elif allow_execution:
                    facts.executed = True
                    output = _run_version(binary, limits)
                    identity = _parse_identity(output)
                    if identity.identified:
                        facts.detection_method = "version_command"
                        facts.confidence = Confidence.MEDIUM

    facts.version = identity.version
    facts.build = identity.build
    facts.commit = identity.commit
    return facts
