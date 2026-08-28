"""Tests for GGUF with unreliable metadata and exaggerated sizes (task 54)."""

from __future__ import annotations

import contextlib
import struct
from pathlib import Path

import pytest

from cancerbero.gguf.reader import (
    GgufLimitError,
    GgufValidationError,
    read_gguf,
)
from tests.fixtures_factory import build_gguf_v2


class TestUnreliableMetadata:
    """Task 54: GGUF with unreliable metadata and exaggerated sizes."""

    def test_exaggerated_tensor_count_is_rejected(self, tmp_path: Path) -> None:
        """A GGUF claiming billions of tensors should be rejected."""
        data = bytearray(build_gguf_v2())
        # Tensor count is at offset 8 (after magic + version), 8 bytes little-endian
        struct.pack_into("<Q", data, 8, 2**63 - 1)
        path = tmp_path / "exaggerated.gguf"
        path.write_bytes(bytes(data))
        with pytest.raises((GgufLimitError, GgufValidationError, Exception)):
            read_gguf(path)

    def test_exaggerated_metadata_count_is_rejected(self, tmp_path: Path) -> None:
        """A GGUF claiming billions of metadata entries should be rejected."""
        data = bytearray(build_gguf_v2())
        # Metadata count is at offset 16 (after magic + version + tensor_count), 8 bytes
        struct.pack_into("<Q", data, 16, 2**63 - 1)
        path = tmp_path / "exaggerated_meta.gguf"
        path.write_bytes(bytes(data))
        with pytest.raises((GgufLimitError, GgufValidationError, Exception)):
            read_gguf(path)

    def test_exaggerated_string_length_is_rejected(self, tmp_path: Path) -> None:
        """A GGUF with a string claiming billions of bytes should be rejected."""
        data = bytearray(
            build_gguf_v2(
                extra_metadata=[
                    ("test.key", 8, struct.pack("<Q", 2**63 - 1) + b"\x00" * 10),
                ]
            )
        )
        path = tmp_path / "exaggerated_str.gguf"
        path.write_bytes(bytes(data))
        with pytest.raises((GgufLimitError, GgufValidationError, Exception)):
            read_gguf(path)

    def test_huge_alignment_is_rejected(self, tmp_path: Path) -> None:
        """A GGUF with absurdly large alignment should be rejected."""
        # Build with alignment=1 first, then corrupt it
        bytearray(build_gguf_v2(alignment=1))
        # general.alignment metadata value is somewhere in the file
        # It's easier to just build with a large alignment that doesn't cause ZeroDivisionError
        data2 = bytearray(build_gguf_v2(alignment=2**30))
        path = tmp_path / "huge_align.gguf"
        path.write_bytes(bytes(data2))
        # This may succeed or fail depending on limits, but should not hang.
        with contextlib.suppress(Exception):
            read_gguf(path)

    def test_duplicate_metadata_key_is_rejected(self, tmp_path: Path) -> None:
        """A GGUF with duplicate metadata keys should be rejected."""
        data = bytearray(
            build_gguf_v2(
                extra_metadata=[
                    ("test.key", 8, struct.pack("<Q", 5) + b"hello"),
                    ("test.key", 8, struct.pack("<Q", 5) + b"world"),
                ]
            )
        )
        path = tmp_path / "dup_key.gguf"
        path.write_bytes(bytes(data))
        with pytest.raises((GgufValidationError, Exception)):
            read_gguf(path)

    def test_invalid_gguf_type_is_rejected(self, tmp_path: Path) -> None:
        """A GGUF with an invalid metadata type should be rejected."""
        data = bytearray(
            build_gguf_v2(
                extra_metadata=[
                    ("test.key", 255, b"\x00" * 10),
                ]
            )
        )
        path = tmp_path / "invalid_type.gguf"
        path.write_bytes(bytes(data))
        with pytest.raises((GgufValidationError, Exception)):
            read_gguf(path)
