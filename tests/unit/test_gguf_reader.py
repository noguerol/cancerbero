"""Tests for the defensive GGUF parser."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from cancerbero.gguf.inspector import inspect_gguf
from cancerbero.gguf.limits import ParserLimits
from cancerbero.gguf.reader import (
    GgufDuplicateError,
    GgufIoError,
    GgufLimitError,
    GgufMagicError,
    GgufTruncatedError,
    GgufTypeError,
    GgufValidationError,
    GgufVersionError,
    read_gguf,
)
from tests.fixtures_factory import build_gguf_v2, write_gguf


class TestValidGguf:
    def test_minimal_valid_v2(self, tmp_path: Path) -> None:
        path = write_gguf(tmp_path / "ok.gguf")
        doc = read_gguf(path)
        assert doc.version == 2
        assert doc.endian == "little"
        assert doc.tensor_count == 0
        assert doc.metadata_count == 3
        assert doc.metadata["general.architecture"] == "llama"
        assert doc.metadata["general.name"] == "test-model"
        assert doc.alignment == 32
        assert doc.bytes_read > 0

    def test_chat_template_extracted(self, tmp_path: Path) -> None:
        template = "{{ bos_token }}{% for m in messages %}{{ m.content }}{% endfor %}"
        path = write_gguf(tmp_path / "tpl.gguf", chat_template=template)
        doc = read_gguf(path)
        assert doc.metadata["tokenizer.chat_template"] == template

    def test_inspect_gguf_returns_artifact_facts(self, tmp_path: Path) -> None:
        path = write_gguf(tmp_path / "facts.gguf", architecture="mistral", name="my-model")
        facts, findings = inspect_gguf(path)
        assert facts.architecture == "mistral"
        assert facts.name == "my-model"
        assert facts.gguf_version == 2
        assert facts.has_chat_template is False

    def test_bytes_read_is_tracked(self, tmp_path: Path) -> None:
        path = write_gguf(tmp_path / "tracked.gguf")
        doc = read_gguf(path)
        assert doc.bytes_read == path.stat().st_size


class TestMagicValidation:
    def test_bad_magic_raises(self, tmp_path: Path) -> None:
        path = write_gguf(tmp_path / "bad.gguf", bad_magic=True)
        with pytest.raises(GgufMagicError):
            read_gguf(path)

    def test_empty_file_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "empty.gguf"
        path.write_bytes(b"")
        with pytest.raises(GgufTruncatedError):
            read_gguf(path)

    def test_truncated_magic_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "trunc.gguf"
        path.write_bytes(b"GG")
        with pytest.raises(GgufTruncatedError):
            read_gguf(path)


class TestVersionValidation:
    def test_v1_rejected(self, tmp_path: Path) -> None:
        path = write_gguf(tmp_path / "v1.gguf", bad_version=1)
        with pytest.raises(GgufVersionError):
            read_gguf(path)

    def test_v4_rejected(self, tmp_path: Path) -> None:
        path = write_gguf(tmp_path / "v4.gguf", bad_version=4)
        with pytest.raises(GgufVersionError):
            read_gguf(path)


class TestTruncation:
    def test_truncated_metadata_count(self, tmp_path: Path) -> None:
        path = write_gguf(tmp_path / "trunc.gguf", truncate_at=12)
        with pytest.raises(GgufTruncatedError):
            read_gguf(path)

    def test_truncated_metadata_key(self, tmp_path: Path) -> None:
        path = write_gguf(tmp_path / "trunc.gguf", truncate_at=20)
        with pytest.raises(GgufTruncatedError):
            read_gguf(path)


class TestLimits:
    def test_zero_kv_limit_rejected(self) -> None:
        with pytest.raises(ValueError, match="max_kv_count"):
            ParserLimits(max_kv_count=0)

    def test_metadata_budget_enforced(self, tmp_path: Path) -> None:
        limits = ParserLimits(max_metadata_bytes=32)
        path = write_gguf(tmp_path / "big.gguf")
        with pytest.raises(GgufLimitError, match="budget"):
            read_gguf(path, limits=limits)

    def test_string_limit_enforced(self, tmp_path: Path) -> None:
        limits = ParserLimits(max_string_bytes=4)
        path = write_gguf(tmp_path / "long.gguf", name="a-very-long-name")
        with pytest.raises(GgufLimitError, match="length"):
            read_gguf(path, limits=limits)


class TestAlignment:
    def test_alignment_must_be_power_of_two(self, tmp_path: Path) -> None:
        # Build a minimal GGUF manually with alignment=12
        def _str(s: str) -> bytes:
            enc = s.encode("utf-8")
            return struct.pack("<Q", len(enc)) + enc

        parts = [b"GGUF", struct.pack("<I", 2)]  # magic, version 2
        parts.append(struct.pack("<Q", 0))  # tensor count
        parts.append(struct.pack("<Q", 3))  # metadata count
        # general.architecture
        parts.append(_str("general.architecture"))
        parts.append(struct.pack("<I", 8))  # STRING type
        parts.append(_str("llama"))
        # general.name
        parts.append(_str("general.name"))
        parts.append(struct.pack("<I", 8))
        parts.append(_str("test"))
        # general.alignment = 12 (not power of two)
        parts.append(_str("general.alignment"))
        parts.append(struct.pack("<I", 4))  # UINT32 type
        parts.append(struct.pack("<I", 12))
        data = b"".join(parts)
        path = tmp_path / "align.gguf"
        path.write_bytes(data)
        with pytest.raises(GgufValidationError, match="alignment"):
            read_gguf(path)


class TestDuplicateKeys:
    def test_duplicate_metadata_key_raises(self, tmp_path: Path) -> None:
        data = build_gguf_v2(
            extra_metadata=[("general.architecture", 8, struct.pack("<Q", 4) + b"test")]
        )
        path = tmp_path / "dup.gguf"
        path.write_bytes(data)
        with pytest.raises(GgufDuplicateError):
            read_gguf(path)


class TestIoErrors:
    def test_nonexistent_file_raises_io_error(self, tmp_path: Path) -> None:
        with pytest.raises(GgufIoError):
            read_gguf(tmp_path / "nonexistent.gguf")

    def test_directory_raises_io_error(self, tmp_path: Path) -> None:
        with pytest.raises(GgufIoError):
            read_gguf(tmp_path)


class TestQuantizationTypes:
    """Known GGML tensor types must never be flagged as unknown.

    The known-type set is the canonical GGML_TYPE_SIZES table in the reader;
    the inspector must not keep a second, drifting copy.
    """

    def _write_gguf_with_tensor(self, tmp_path: Path, ggml_type: int) -> Path:
        from tests.fixtures_factory import build_gguf_v2

        if ggml_type == 12:  # Q4_K: 256 elements, 144-byte block
            dims, block_bytes = (256, 1), 144
        elif ggml_type == 42:  # Q2_0: 64 elements, 18-byte block
            dims, block_bytes = (64, 1), 18
        else:
            raise AssertionError(f"no fixture dimensions for type {ggml_type}")
        data = build_gguf_v2(tensors=[("tok_embd.weight", dims, ggml_type, 0)])
        path = tmp_path / f"type-{ggml_type}.gguf"
        # Append the encoded tensor block so range validation passes; the
        # reader never reads these bytes.
        path.write_bytes(data + b"\x00" * block_bytes)
        return path

    def test_q4_k_type_id_12_produces_no_unknown_quant_type(self, tmp_path: Path) -> None:
        path = self._write_gguf_with_tensor(tmp_path, ggml_type=12)
        facts, findings = inspect_gguf(path)
        assert facts.tensors[0].ggml_type == 12
        assert facts.tensors[0].byte_size == 144
        assert [f for f in findings if f.id == "cbr.gguf.unknown_quant_type"] == []

    def test_canonical_table_recognizes_types_missing_from_old_copy(self, tmp_path: Path) -> None:
        # Type 42 (Q2_0) is canonical in GGML_TYPE_SIZES but was absent from
        # the inspector's historical hardcoded table; it must not be flagged.
        path = self._write_gguf_with_tensor(tmp_path, ggml_type=42)
        facts, findings = inspect_gguf(path)
        assert facts.tensors[0].ggml_type == 42
        assert [f for f in findings if f.id == "cbr.gguf.unknown_quant_type"] == []

    def test_unknown_type_rejected_by_reader_before_inspection(self, tmp_path: Path) -> None:
        # Type id 4 is a hole in the canonical GGML_TYPE_SIZES table; the
        # reader rejects it, so the inspector never sees an unknown type id
        # from a parsed document.
        from tests.fixtures_factory import build_gguf_v2

        data = build_gguf_v2(tensors=[("t", (32, 1), 4, 0)])
        path = tmp_path / "type-4.gguf"
        path.write_bytes(data + b"\x00" * 18)
        with pytest.raises(GgufTypeError, match="Unknown or unsupported GGML tensor type"):
            read_gguf(path)
