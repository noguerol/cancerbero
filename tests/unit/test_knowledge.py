"""Tests for knowledge bundle loading and schema validation."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from cancerbero.knowledge.loader import (
    BundleIntegrityError,
    canonical_sha256,
    load_bundle,
)
from cancerbero.knowledge.schema import BundleSchemaError, KnowledgeBundle, parse_manifest


class TestEmbeddedBundle:
    def test_load_embedded_bundle(self) -> None:
        bundle = load_bundle()
        assert isinstance(bundle, KnowledgeBundle)
        assert bundle.info.schema_version == "1.0"
        assert len(bundle.rules) > 0
        assert bundle.info.integrity == "canonical_sha256_verified"

    def test_bundle_not_expired_by_default(self) -> None:
        bundle = load_bundle()
        assert bundle.expired is False

    def test_bundle_expired_in_future(self) -> None:
        future = datetime(2099, 1, 1, tzinfo=timezone.utc)
        bundle = load_bundle(now=future)
        assert bundle.expired is True

    def test_bundle_rules_have_required_fields(self) -> None:
        bundle = load_bundle()
        valid_components = {"llama.cpp", "llama-cpp-python", "sglang", "ollama"}
        valid_schemes = {"llama_cpp_build", "semver"}
        for rule in bundle.rules:
            assert (
                rule.id.startswith("CVE-")
                or rule.id.startswith("GGUF-")
                or rule.id.startswith("GHSA-")
            )
            assert rule.source.startswith("https://")
            assert rule.component in valid_components
            assert rule.version_scheme in valid_schemes
            assert len(rule.artifact_predicates) > 0


class TestManifestValidation:
    def test_valid_manifest(self) -> None:
        data = {
            "schema_version": "1.0",
            "bundle_version": "2026.08.27",
            "published_at": "2026-08-27T00:00:00Z",
            "expires_at": "2027-08-27T00:00:00Z",
            "advisories": {
                "path": "advisories.json",
                "sha256": "a" * 64,
                "count": 0,
            },
        }
        manifest = parse_manifest(data)
        assert manifest.schema_version == "1.0"

    def test_unknown_schema_version_rejected(self) -> None:
        data = {
            "schema_version": "99.0",
            "bundle_version": "2026.08.27",
            "published_at": "2026-08-27T00:00:00Z",
            "expires_at": "2027-08-27T00:00:00Z",
            "advisories": {"path": "advisories.json", "sha256": "a" * 64, "count": 0},
        }
        with pytest.raises(BundleSchemaError, match="unsupported"):
            parse_manifest(data)

    def test_missing_field_rejected(self) -> None:
        with pytest.raises(BundleSchemaError, match="missing"):
            parse_manifest({"schema_version": "1.0"})


class TestIntegrityVerification:
    def test_corrupted_advisories_raises(self, tmp_path: Path) -> None:
        manifest_dir = tmp_path / "bundle"
        manifest_dir.mkdir()
        manifest_data = {
            "schema_version": "1.0",
            "bundle_version": "2026.08.27",
            "published_at": "2026-08-27T00:00:00Z",
            "expires_at": "2027-08-27T00:00:00Z",
            "advisories": {
                "path": "advisories.json",
                "sha256": "a" * 64,  # wrong digest
                "count": 0,
            },
        }
        (manifest_dir / "manifest.json").write_text(json.dumps(manifest_data))
        (manifest_dir / "advisories.json").write_text(
            json.dumps({"schema_version": "1.0", "bundle_version": "2026.08.27", "advisories": []})
        )
        with pytest.raises(BundleIntegrityError):
            load_bundle(manifest_dir)


class TestCanonicalDigest:
    def test_deterministic(self) -> None:
        data = {"key": "value", "number": 42}
        assert canonical_sha256(data) == canonical_sha256(data)

    def test_order_independent(self) -> None:
        assert canonical_sha256({"b": 2, "a": 1}) == canonical_sha256({"a": 1, "b": 2})
