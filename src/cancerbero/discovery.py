"""Bounded, non-executing discovery of GGUF and llama.cpp targets."""

from __future__ import annotations

import os
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from cancerbero.domain import Target, TargetKind
from cancerbero.gguf.limits import DEFAULT_LIMITS, ParserLimits

GGUF_MAGIC = b"GGUF"

# Deliberately explicit: generic legacy names such as ``main`` and ``server``
# are too ambiguous to classify safely from a filename alone.
LLAMA_CPP_RUNTIME_NAMES = frozenset(
    {
        "llama-cli",
        "llama-server",
        "llama-run",
        "llama-simple",
        "llama-batched",
        "llama-embedding",
        "llama-perplexity",
        "llama-llava-cli",
        "llama-gemma3-cli",
        "llama-minicpmv-cli",
        "llama-qwen2vl-cli",
    }
)

IGNORED_DIRECTORY_NAMES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".cache",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "cache",
        "caches",
        "env",
        "node_modules",
        "venv",
    }
)


@dataclass(frozen=True, slots=True)
class DiscoveryResult:
    """A deterministic inventory plus information about incomplete discovery."""

    targets: tuple[Target, ...]
    candidates_examined: int
    limit_reached: bool = False
    skipped_symlinks: int = 0
    skipped_directories: int = 0

    @property
    def complete(self) -> bool:
        return not self.limit_reached


def _portable_name(path: Path) -> str:
    name = path.name.casefold()
    return name[:-4] if name.endswith(".exe") else name


def is_known_llama_cpp_name(path: str | os.PathLike[str]) -> bool:
    """Return whether *path* has an unambiguous supported llama.cpp name."""

    return _portable_name(Path(path)) in LLAMA_CPP_RUNTIME_NAMES


def has_gguf_magic(path: str | os.PathLike[str]) -> bool:
    """Read only the magic of a regular, non-symlink file."""

    candidate = Path(path)
    try:
        if candidate.is_symlink() or not candidate.is_file():
            return False
        with candidate.open("rb") as stream:
            return stream.read(len(GGUF_MAGIC)) == GGUF_MAGIC
    except OSError:
        return False


def classify_target(path: str | os.PathLike[str]) -> Target:
    """Classify one explicit path without executing it or following symlinks."""

    candidate = Path(path)
    if candidate.is_symlink():
        return Target(candidate, TargetKind.UNKNOWN, "symlink_not_followed")
    if not candidate.exists():
        return Target(candidate, TargetKind.UNKNOWN, "path_not_found")
    if candidate.is_dir():
        return Target(candidate, TargetKind.DIRECTORY, "directory")
    if not candidate.is_file():
        return Target(candidate, TargetKind.UNKNOWN, "not_a_regular_file")
    if has_gguf_magic(candidate):
        return Target(candidate, TargetKind.GGUF, "gguf_magic")
    if is_known_llama_cpp_name(candidate):
        return Target(candidate, TargetKind.LLAMA_CPP_RUNTIME, "llama_cpp_filename")
    return Target(candidate, TargetKind.UNKNOWN, "unrecognized_file")


def discover_target(
    path: str | os.PathLike[str],
    *,
    limits: ParserLimits = DEFAULT_LIMITS,
) -> Target:
    """Classify one explicit target.

    ``limits`` is accepted for a uniform integration signature. Direct target
    classification performs only constant-size reads; directories are not
    expanded here. Use :func:`discover_targets` to inventory directories and
    receive an explicit completeness signal.
    """

    del limits
    return classify_target(path)


def discover_directory(
    path: str | os.PathLike[str],
    *,
    limits: ParserLimits = DEFAULT_LIMITS,
) -> DiscoveryResult:
    """Inventory a directory within hard depth and candidate-count limits.

    Directory entries are sorted for reproducibility. Symlinks are counted and
    skipped regardless of whether they point to files or directories. Every
    regular file consumes one candidate slot because extensionless GGUF files
    must still be detected by magic.
    """

    root = Path(path)
    if root.is_symlink():
        raise ValueError(f"Directory target must not be a symlink: {root}")
    if not root.exists():
        raise ValueError(f"Directory target does not exist: {root}")
    if not root.is_dir():
        raise ValueError(f"Directory target is not a directory: {root}")

    targets: list[Target] = []
    candidates_examined = 0
    skipped_symlinks = 0
    skipped_directories = 0
    limit_reached = False

    # Depth zero is the supplied directory. Files immediately inside it are
    # always inspected; children are entered only while below the depth limit.
    pending: list[tuple[Path, int]] = [(root, 0)]
    while pending and not limit_reached:
        directory, depth = pending.pop()
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name.casefold())
        except OSError as error:
            raise OSError(f"Cannot scan directory {directory}: {error}") from error

        child_directories: list[Path] = []
        for entry in entries:
            entry_path = Path(entry.path)
            try:
                if entry.is_symlink():
                    skipped_symlinks += 1
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if entry.name.casefold() in IGNORED_DIRECTORY_NAMES:
                        skipped_directories += 1
                    elif depth >= limits.max_directory_depth:
                        skipped_directories += 1
                        limit_reached = True
                    else:
                        child_directories.append(entry_path)
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue
            except OSError:
                # A concurrently replaced entry is not followed or guessed.
                continue

            if candidates_examined >= limits.max_directory_candidates:
                limit_reached = True
                break
            candidates_examined += 1
            target = classify_target(entry_path)
            if target.kind in {TargetKind.GGUF, TargetKind.LLAMA_CPP_RUNTIME}:
                targets.append(target)

        # Stack is LIFO; reverse insertion preserves ascending traversal order.
        pending.extend((child, depth + 1) for child in reversed(child_directories))

    targets.sort(key=lambda target: os.fspath(target.path).casefold())
    return DiscoveryResult(
        targets=tuple(targets),
        candidates_examined=candidates_examined,
        limit_reached=limit_reached,
        skipped_symlinks=skipped_symlinks,
        skipped_directories=skipped_directories,
    )


def discover_targets(
    paths: Iterable[str | os.PathLike[str]],
    *,
    limits: ParserLimits = DEFAULT_LIMITS,
) -> DiscoveryResult:
    """Discover explicit files and expand explicit directories."""

    targets: list[Target] = []
    candidates_examined = 0
    skipped_symlinks = 0
    skipped_directories = 0
    limit_reached = False

    for raw_path in paths:
        target = classify_target(raw_path)
        if target.kind is TargetKind.DIRECTORY:
            result = discover_directory(target.path, limits=limits)
            targets.extend(result.targets)
            candidates_examined += result.candidates_examined
            skipped_symlinks += result.skipped_symlinks
            skipped_directories += result.skipped_directories
            limit_reached = limit_reached or result.limit_reached
        else:
            targets.append(target)

    targets.sort(key=lambda item: os.fspath(item.path).casefold())
    return DiscoveryResult(
        targets=tuple(targets),
        candidates_examined=candidates_examined,
        limit_reached=limit_reached,
        skipped_symlinks=skipped_symlinks,
        skipped_directories=skipped_directories,
    )
