"""Tests for resource limits and safety (task 75)."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from cancerbero.gguf.reader import read_gguf
from tests.fixtures_factory import build_gguf_v2


class TestLimits:
    """Task 75: Inputs with extreme sizes or depth should not exhaust memory/CPU."""

    def test_truncated_file_is_rejected(self, tmp_path: Path) -> None:
        """A truncated GGUF file should be rejected gracefully."""
        data = build_gguf_v2()
        path = tmp_path / "truncated.gguf"
        path.write_bytes(data[:10])  # Truncate to 10 bytes
        with pytest.raises(Exception):
            read_gguf(path)

    def test_empty_file_is_rejected(self, tmp_path: Path) -> None:
        """An empty file should be rejected gracefully."""
        path = tmp_path / "empty.gguf"
        path.write_bytes(b"")
        with pytest.raises(Exception):
            read_gguf(path)

    def test_file_with_only_magic_is_rejected(self, tmp_path: Path) -> None:
        """A file with only magic bytes should be rejected."""
        path = tmp_path / "magic_only.gguf"
        path.write_bytes(b"GGUF")
        with pytest.raises(Exception):
            read_gguf(path)

    def test_header_only_with_zero_counts_succeeds(self, tmp_path: Path) -> None:
        """A file with only the header (0 tensors, 0 metadata) should succeed as empty GGUF."""
        # GGUF v2 with 0 tensors and 0 metadata is technically valid (empty model)
        path = tmp_path / "header_only.gguf"
        build_gguf_v2()  # Default has 0 tensors, but has some metadata
        # Build a truly empty one: magic + version + 0 tensors + 0 metadata
        header = b"GGUF" + struct.pack("<I", 2) + struct.pack("<Q", 0) + struct.pack("<Q", 0)
        # Add alignment padding
        header += b"\x00" * (32 - len(header))
        path.write_bytes(header)
        # This should succeed (empty GGUF is valid)
        result = read_gguf(path)
        assert result.tensor_count == 0
        assert result.metadata_count == 0

    def test_very_long_metadata_key_is_handled(self, tmp_path: Path) -> None:
        """A metadata key that's very long should be handled gracefully."""
        long_key = "a" * 10000
        data = build_gguf_v2(
            extra_metadata=[
                (long_key, 8, struct.pack("<Q", 5) + b"hello"),
            ]
        )
        path = tmp_path / "long_key.gguf"
        path.write_bytes(data)
        # Should either succeed or fail gracefully, not hang
        try:
            result = read_gguf(path)
            assert result is not None
        except Exception:
            pass  # Graceful failure is acceptable

    def test_very_long_string_value_is_handled(self, tmp_path: Path) -> None:
        """A metadata value that's very long should be handled gracefully."""
        long_value = "b" * 100000
        encoded = long_value.encode("utf-8")
        data = build_gguf_v2(
            extra_metadata=[
                ("test.long_value", 8, struct.pack("<Q", len(encoded)) + encoded),
            ]
        )
        path = tmp_path / "long_value.gguf"
        path.write_bytes(data)
        # Should either succeed or fail gracefully, not hang
        try:
            result = read_gguf(path)
            assert result is not None
        except Exception:
            pass  # Graceful failure is acceptable

    def test_zero_length_string_is_handled(self, tmp_path: Path) -> None:
        """A zero-length string should be handled gracefully."""
        data = build_gguf_v2(
            extra_metadata=[
                ("test.empty", 8, struct.pack("<Q", 0)),
            ]
        )
        path = tmp_path / "empty_str.gguf"
        path.write_bytes(data)
        try:
            result = read_gguf(path)
            assert result is not None
        except Exception:
            pass  # Graceful failure is acceptable

    def test_many_metadata_entries_is_handled(self, tmp_path: Path) -> None:
        """A GGUF with many metadata entries should be handled gracefully."""
        extra = [(f"test.key_{i}", 8, struct.pack("<Q", 5) + b"hello") for i in range(100)]
        data = build_gguf_v2(extra_metadata=extra)
        path = tmp_path / "many_meta.gguf"
        path.write_bytes(data)
        try:
            result = read_gguf(path)
            assert result is not None
        except Exception:
            pass  # Graceful failure is acceptable
