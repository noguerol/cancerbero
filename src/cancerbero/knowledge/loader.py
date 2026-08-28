"""Offline loader for embedded or explicitly supplied knowledge bundles."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path
from typing import Any

from cancerbero.domain import BundleInfo
from cancerbero.knowledge.schema import (
    BundleError,
    BundleSchemaError,
    KnowledgeBundle,
    parse_advisories,
    parse_manifest,
    parse_timestamp,
)

MAX_MANIFEST_BYTES = 64 * 1024
MAX_ADVISORIES_BYTES = 2 * 1024 * 1024


class BundleIntegrityError(BundleError):
    """Canonical bundle content does not match its declared SHA-256."""


class BundleIOError(BundleError):
    """Bundle files could not be read safely."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BundleSchemaError(f"JSON object contains duplicate key {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise BundleSchemaError(f"non-finite JSON number {value!r} is not allowed")


def decode_json(raw: bytes, *, source: str) -> Any:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise BundleSchemaError(f"{source}: must be UTF-8") from error
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as error:
        raise BundleSchemaError(
            f"{source}: invalid JSON at line {error.lineno}, column {error.colno}"
        ) from error


def canonical_json_bytes(value: Any) -> bytes:
    """Encode JSON using the single representation used for bundle digests."""
    try:
        rendered = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as error:
        raise BundleSchemaError("bundle content is not canonical JSON data") from error
    return rendered.encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _read_path(path: Path, *, limit: int, label: str) -> bytes:
    try:
        size = path.stat().st_size
        if size > limit:
            raise BundleIOError(f"{label}: exceeds {limit} byte limit")
        raw = path.read_bytes()
    except BundleIOError:
        raise
    except OSError as error:
        raise BundleIOError(f"{label}: cannot read {path}: {error}") from error
    if len(raw) > limit:
        raise BundleIOError(f"{label}: exceeds {limit} byte limit")
    return raw


def _read_resource(name: str, *, limit: int) -> bytes:
    resource = resources.files("cancerbero.knowledge").joinpath("bundled", name)
    try:
        raw = resource.read_bytes()
    except OSError as error:
        raise BundleIOError(f"embedded {name}: cannot be read: {error}") from error
    if len(raw) > limit:
        raise BundleIOError(f"embedded {name}: exceeds {limit} byte limit")
    return raw


def _normalise_now(now: datetime | None) -> datetime:
    instant = now or datetime.now(timezone.utc)
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    return instant.astimezone(timezone.utc)


def load_bundle(path: Path | None = None, *, now: datetime | None = None) -> KnowledgeBundle:
    """Load and verify a bundle without network access.

    ``path`` may name a bundle directory or its ``manifest.json``. Corruption is
    never converted into findings: :class:`BundleError` is raised so the CLI can
    report operational exit code 3. Expiry is exposed through ``bundle.expired``
    and is not corruption.
    """
    if path is None:
        manifest_raw = _read_resource("manifest.json", limit=MAX_MANIFEST_BYTES)
        source = "embedded"
    else:
        supplied = Path(path)
        manifest_path = supplied / "manifest.json" if supplied.is_dir() else supplied
        if manifest_path.name != "manifest.json":
            raise BundleIOError("bundle path must be a directory or manifest.json")
        manifest_raw = _read_path(manifest_path, limit=MAX_MANIFEST_BYTES, label="bundle manifest")
        source = str(manifest_path.parent.resolve())

    manifest_data = decode_json(manifest_raw, source="manifest.json")
    manifest = parse_manifest(manifest_data)

    if path is None:
        advisories_raw = _read_resource(manifest.advisories_path, limit=MAX_ADVISORIES_BYTES)
    else:
        supplied = Path(path)
        directory = supplied if supplied.is_dir() else supplied.parent
        advisories_raw = _read_path(
            directory / manifest.advisories_path,
            limit=MAX_ADVISORIES_BYTES,
            label="bundle advisories",
        )

    advisories_data = decode_json(advisories_raw, source=manifest.advisories_path)
    actual_digest = canonical_sha256(advisories_data)
    if not hmac.compare_digest(actual_digest, manifest.advisories_sha256):
        raise BundleIntegrityError("advisories.json canonical SHA-256 does not match manifest")
    rules = parse_advisories(advisories_data, manifest=manifest)
    instant = _normalise_now(now)
    expired = instant >= parse_timestamp(manifest.expires_at, "manifest.expires_at")
    info = BundleInfo(
        schema_version=manifest.schema_version,
        bundle_version=manifest.bundle_version,
        published_at=manifest.published_at,
        expires_at=manifest.expires_at,
        digest_sha256=actual_digest,
        source=source,
        integrity="canonical_sha256_verified",
    )
    return KnowledgeBundle(info=info, advisories=rules, expired=expired)


__all__ = [
    "BundleError",
    "BundleIOError",
    "BundleIntegrityError",
    "BundleSchemaError",
    "KnowledgeBundle",
    "canonical_json_bytes",
    "canonical_sha256",
    "decode_json",
    "load_bundle",
]
