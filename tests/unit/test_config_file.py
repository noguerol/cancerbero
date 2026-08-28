"""Tests for configuration file loading (YAML/JSON)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from cancerbero.config_file import ConfigFileError, load_config


class TestLoadConfig:
    def test_missing_config_returns_defaults(self, tmp_path: Path) -> None:
        config = load_config(tmp_path / "nope.yaml")
        assert config.full_hash is False
        assert config.runtime is None

    def test_yaml_config_applies_values(self, tmp_path: Path) -> None:
        path = tmp_path / "cancerbero.yaml"
        path.write_text("runtime: ./llama-cli\nfull_hash: true\nformat: json\n", encoding="utf-8")
        config = load_config(path)
        assert config.runtime == Path("llama-cli")
        assert config.full_hash is True
        assert config.format == "json"

    def test_json_config_applies_values(self, tmp_path: Path) -> None:
        path = tmp_path / "cancerbero.json"
        path.write_text('{"runtime": "./llama-cli", "full_hash": true}', encoding="utf-8")
        config = load_config(path)
        assert config.runtime == Path("llama-cli")
        assert config.full_hash is True

    def test_malformed_yaml_raises_config_error(self, tmp_path: Path) -> None:
        path = tmp_path / "cancerbero.yaml"
        path.write_text("runtime: [unclosed", encoding="utf-8")
        with pytest.raises(ConfigFileError, match="invalid YAML"):
            load_config(path)

    def test_missing_pyyaml_json_fallback(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "cancerbero.json"
        path.write_text('{"full_hash": true}', encoding="utf-8")
        monkeypatch.setitem(sys.modules, "yaml", None)
        config = load_config(path)
        assert config.full_hash is True

    def test_missing_pyyaml_yaml_content_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "cancerbero.yaml"
        path.write_text("runtime: ./llama-cli\n", encoding="utf-8")
        monkeypatch.setitem(sys.modules, "yaml", None)
        with pytest.raises(ConfigFileError, match="install PyYAML or convert to JSON"):
            load_config(path)

    def test_missing_pyyaml_non_config_returns_defaults(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "cancerbero.yaml"
        path.write_text("not a config at all\n", encoding="utf-8")
        monkeypatch.setitem(sys.modules, "yaml", None)
        config = load_config(path)
        assert config.full_hash is False
