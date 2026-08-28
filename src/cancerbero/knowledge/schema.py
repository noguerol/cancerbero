"""Strict, non-executable schema for Cancerbero knowledge bundles."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any
from urllib.parse import urlparse

from cancerbero.domain import AdvisoryRule, BundleInfo, Confidence, Severity

SCHEMA_VERSION = "1.0"
_BUILD_OPERATORS = frozenset({"gt", "gte", "lt", "lte"})
_PREDICATE_OPERATORS = frozenset({"equals", "present"})
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_VERSION_RE = re.compile(r"[0-9]+(?:\.[0-9]+)*\Z")


class BundleError(ValueError):
    """Base class for bundle corruption and validation failures exposed to callers."""


class BundleSchemaError(BundleError):
    """The bundle is well-formed JSON but does not satisfy the closed schema."""


@dataclass(frozen=True, slots=True)
class BundleManifest:
    schema_version: str
    bundle_version: str
    published_at: str
    expires_at: str
    advisories_path: str
    advisories_sha256: str
    advisory_count: int


@dataclass(frozen=True, slots=True)
class KnowledgeBundle:
    """Validated bundle plus integrity and expiry metadata."""

    info: BundleInfo
    advisories: tuple[AdvisoryRule, ...]
    expired: bool

    @property
    def rules(self) -> tuple[AdvisoryRule, ...]:
        """Alias used by the applicability engine's public integration contract."""
        return self.advisories

    def is_expired(self, at: datetime | None = None) -> bool:
        if at is None:
            return self.expired
        instant = _normalise_instant(at, "at")
        return instant >= parse_timestamp(self.info.expires_at, "expires_at")


def _fail(location: str, message: str) -> None:
    raise BundleSchemaError(f"{location}: {message}")


def _mapping(value: object, location: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        _fail(location, "must be an object")
    return value


def _closed_keys(value: Mapping[str, Any], required: set[str], location: str) -> None:
    actual = set(value)
    missing = sorted(required - actual)
    unknown = sorted(actual - required)
    if missing:
        _fail(location, f"missing fields: {', '.join(missing)}")
    if unknown:
        _fail(location, f"unknown fields: {', '.join(unknown)}")


def _string(value: object, location: str, *, nonempty: bool = True) -> str:
    if not isinstance(value, str) or (nonempty and not value):
        _fail(location, "must be a non-empty string" if nonempty else "must be a string")
    return value


def _integer(value: object, location: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        _fail(location, f"must be an integer >= {minimum}")
    return value


def _version(value: object, location: str) -> str:
    result = _string(value, location)
    if not _VERSION_RE.fullmatch(result):
        _fail(location, "must be a dotted numeric version")
    return result


def _normalise_instant(value: datetime, location: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        _fail(location, "must be timezone-aware")
    return value.astimezone(timezone.utc)


def parse_timestamp(value: object, location: str) -> datetime:
    text = _string(value, location)
    if not text.endswith("Z"):
        _fail(location, "must be an RFC 3339 UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as error:
        raise BundleSchemaError(f"{location}: invalid timestamp") from error
    return _normalise_instant(parsed, location)


def _calendar_date(value: object, location: str) -> str:
    text = _string(value, location)
    try:
        parsed = date.fromisoformat(text)
    except ValueError as error:
        raise BundleSchemaError(f"{location}: invalid ISO date") from error
    if parsed.isoformat() != text:
        _fail(location, "must use YYYY-MM-DD format")
    return text


def _https_url(value: object, location: str) -> str:
    text = _string(value, location)
    parsed = urlparse(text)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        _fail(location, "must be an absolute HTTPS URL without credentials")
    return text


def parse_manifest(data: object) -> BundleManifest:
    root = _mapping(data, "manifest")
    _closed_keys(
        root,
        {
            "schema_version",
            "bundle_version",
            "published_at",
            "expires_at",
            "advisories",
        },
        "manifest",
    )
    schema_version = _version(root["schema_version"], "manifest.schema_version")
    if schema_version != SCHEMA_VERSION:
        _fail("manifest.schema_version", f"unsupported schema {schema_version!r}")
    bundle_version = _version(root["bundle_version"], "manifest.bundle_version")
    published_at = _string(root["published_at"], "manifest.published_at")
    expires_at = _string(root["expires_at"], "manifest.expires_at")
    published = parse_timestamp(published_at, "manifest.published_at")
    expires = parse_timestamp(expires_at, "manifest.expires_at")
    if expires <= published:
        _fail("manifest.expires_at", "must be later than published_at")

    advisories = _mapping(root["advisories"], "manifest.advisories")
    _closed_keys(advisories, {"path", "sha256", "count"}, "manifest.advisories")
    path = _string(advisories["path"], "manifest.advisories.path")
    if path != "advisories.json":
        _fail("manifest.advisories.path", "must be exactly 'advisories.json'")
    digest = _string(advisories["sha256"], "manifest.advisories.sha256")
    if not _SHA256_RE.fullmatch(digest):
        _fail("manifest.advisories.sha256", "must be a lowercase SHA-256 hex digest")

    return BundleManifest(
        schema_version=schema_version,
        bundle_version=bundle_version,
        published_at=published_at,
        expires_at=expires_at,
        advisories_path=path,
        advisories_sha256=digest,
        advisory_count=_integer(advisories["count"], "manifest.advisories.count"),
    )


def _parse_build_range(
    value: object, location: str, *, scheme: str = "llama_cpp_build"
) -> dict[str, int | str]:
    constraints = _mapping(value, location)
    keys = set(constraints)
    if not keys or not keys <= _BUILD_OPERATORS:
        _fail(location, "must contain only explicit gt/gte/lt/lte build constraints")
    if "gt" in keys and "gte" in keys:
        _fail(location, "cannot contain both gt and gte")
    if "lt" in keys and "lte" in keys:
        _fail(location, "cannot contain both lt and lte")
    if scheme == "llama_cpp_build":
        result: dict[str, int | str] = {
            key: _integer(constraints[key], f"{location}.{key}") for key in constraints
        }
    else:
        # For semver and other string-based schemes
        result = {key: _string(constraints[key], f"{location}.{key}") for key in constraints}
    return result


def _integer_interval(constraints: Mapping[str, int]) -> tuple[int, int | None]:
    lower = constraints.get("gte", 0)
    if "gt" in constraints:
        lower = constraints["gt"] + 1
    upper: int | None = constraints.get("lte")
    if "lt" in constraints:
        upper = constraints["lt"] - 1
    return lower, upper


def _ranges_overlap(left: Mapping[str, int], right: Mapping[str, int]) -> bool:
    left_low, left_high = _integer_interval(left)
    right_low, right_high = _integer_interval(right)
    low = max(left_low, right_low)
    if left_high is None:
        high = right_high
    elif right_high is None:
        high = left_high
    else:
        high = min(left_high, right_high)
    return high is None or low <= high


def _parse_predicate(value: object, location: str) -> dict[str, Any]:
    predicate = _mapping(value, location)
    operator = _string(predicate.get("operator"), f"{location}.operator")
    if operator not in _PREDICATE_OPERATORS:
        _fail(f"{location}.operator", "must be 'present' or 'equals'")
    expected = {"field", "operator"} if operator == "present" else {"field", "operator", "value"}
    _closed_keys(predicate, expected, location)
    field = _string(predicate["field"], f"{location}.field")
    if not all(part.isidentifier() and not part.startswith("_") for part in field.split(".")):
        _fail(f"{location}.field", "must be a public dotted identifier")
    result: dict[str, Any] = {"field": field, "operator": operator}
    if operator == "equals":
        comparison = predicate["value"]
        if comparison is not None and type(comparison) not in {str, int, bool}:
            _fail(f"{location}.value", "must be a string, integer, boolean, or null")
        result["value"] = comparison
    return result


def _parse_rule(value: object, location: str) -> AdvisoryRule:
    rule = _mapping(value, location)
    required = {
        "id",
        "title",
        "source",
        "component",
        "version_scheme",
        "affected",
        "fixed",
        "artifact_predicates",
        "severity",
        "confidence",
        "explanation",
        "action",
        "published",
        "reviewed",
        "verified_by",
        "fixed_inferred",
    }
    _closed_keys(rule, required, location)
    version_scheme = _string(rule["version_scheme"], f"{location}.version_scheme")
    affected = _parse_build_range(rule["affected"], f"{location}.affected", scheme=version_scheme)
    fixed = _parse_build_range(rule["fixed"], f"{location}.fixed", scheme=version_scheme)
    if version_scheme == "llama_cpp_build" and _ranges_overlap(affected, fixed):
        _fail(location, "affected and fixed build ranges overlap")

    predicates_value = rule["artifact_predicates"]
    if not isinstance(predicates_value, list) or not predicates_value:
        _fail(f"{location}.artifact_predicates", "must be a non-empty array")
    predicates = tuple(
        _parse_predicate(item, f"{location}.artifact_predicates[{index}]")
        for index, item in enumerate(predicates_value)
    )

    version_scheme = _string(rule["version_scheme"], f"{location}.version_scheme")
    if version_scheme not in {"llama_cpp_build", "semver"}:
        _fail(f"{location}.version_scheme", "must be 'llama_cpp_build' or 'semver'")
    try:
        severity = Severity(_string(rule["severity"], f"{location}.severity"))
        confidence = Confidence(_string(rule["confidence"], f"{location}.confidence"))
    except ValueError as error:
        raise BundleSchemaError(f"{location}: invalid severity or confidence") from error

    return AdvisoryRule(
        id=_string(rule["id"], f"{location}.id"),
        title=_string(rule["title"], f"{location}.title"),
        source=_https_url(rule["source"], f"{location}.source"),
        component=_string(rule["component"], f"{location}.component"),
        version_scheme=version_scheme,
        affected=affected,
        fixed=fixed,
        artifact_predicates=predicates,
        severity=severity,
        confidence=confidence,
        explanation=_string(rule["explanation"], f"{location}.explanation"),
        action=_string(rule["action"], f"{location}.action"),
        published=_calendar_date(rule["published"], f"{location}.published"),
        reviewed=_calendar_date(rule["reviewed"], f"{location}.reviewed"),
    )


def parse_advisories(data: object, *, manifest: BundleManifest) -> tuple[AdvisoryRule, ...]:
    root = _mapping(data, "advisories")
    _closed_keys(root, {"schema_version", "bundle_version", "advisories"}, "advisories")
    if _version(root["schema_version"], "advisories.schema_version") != manifest.schema_version:
        _fail("advisories.schema_version", "does not match manifest")
    if _version(root["bundle_version"], "advisories.bundle_version") != manifest.bundle_version:
        _fail("advisories.bundle_version", "does not match manifest")
    values = root["advisories"]
    if not isinstance(values, list):
        _fail("advisories.advisories", "must be an array")
    rules = tuple(
        _parse_rule(item, f"advisories.advisories[{index}]") for index, item in enumerate(values)
    )
    if len(rules) != manifest.advisory_count:
        _fail("advisories.advisories", "count does not match manifest")
    ids = [rule.id for rule in rules]
    if len(set(ids)) != len(ids):
        _fail("advisories.advisories", "advisory ids must be unique")
    if ids != sorted(ids):
        _fail("advisories.advisories", "advisories must be sorted by id")
    return rules


__all__ = [
    "BundleError",
    "BundleManifest",
    "BundleSchemaError",
    "KnowledgeBundle",
    "SCHEMA_VERSION",
    "parse_advisories",
    "parse_manifest",
    "parse_timestamp",
]
