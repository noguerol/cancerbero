"""Canonical JSON serialization and explicit report output."""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from pathlib import Path

from cancerbero.domain import AuditReport


def canonical_json(report: AuditReport, *, include_observations: bool = False) -> str:
    """Serialize stable report data with deterministic key and list ordering."""
    data = report.to_dict() if include_observations else report.deterministic_dict()
    return json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def write_json_report(
    report: AuditReport,
    destination: str | Path,
    *,
    include_observations: bool = False,
) -> None:
    """Write JSON to stdout or atomically replace an explicitly requested path."""
    content = canonical_json(report, include_observations=include_observations)
    if str(destination) == "-":
        print(content, end="")
        return

    path = Path(destination).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)
        raise
