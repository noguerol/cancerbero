"""Synthetic GGUF fixture builder for tests."""

from __future__ import annotations

import struct
from pathlib import Path


def _gguf_string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return struct.pack("<Q", len(encoded)) + encoded


def _gguf_metadata(key: str, value_type: int, value: bytes) -> bytes:
    return _gguf_string(key) + struct.pack("<I", value_type) + value


def _gguf_string_value(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return struct.pack("<Q", len(encoded)) + encoded


def build_gguf_v2(
    *,
    architecture: str = "llama",
    name: str = "test-model",
    chat_template: str | None = None,
    tensor_count: int = 0,
    tensors: list[tuple[str, tuple[int, ...], int, int]] | None = None,
    extra_metadata: list[tuple[str, int, bytes]] | None = None,
    alignment: int = 32,
    truncate_at: int | None = None,
    bad_magic: bool = False,
    bad_version: int | None = None,
) -> bytes:
    """Build a minimal GGUF v2 file.

    tensors: list of (name, dimensions, ggml_type, relative_offset)
    """
    if tensors is None:
        tensors = []

    parts: list[bytes] = []

    # Magic
    parts.append(b"GGUF" if not bad_magic else b"XXXX")
    # Version
    version = bad_version if bad_version is not None else 2
    parts.append(struct.pack("<I", version))
    # Tensor count
    parts.append(struct.pack("<Q", len(tensors)))
    # Metadata count
    metadata_items: list[bytes] = []
    metadata_items.append(
        _gguf_metadata("general.architecture", 8, _gguf_string_value(architecture))
    )
    metadata_items.append(_gguf_metadata("general.name", 8, _gguf_string_value(name)))
    metadata_items.append(_gguf_metadata("general.alignment", 4, struct.pack("<I", alignment)))
    if chat_template is not None:
        metadata_items.append(
            _gguf_metadata("tokenizer.chat_template", 8, _gguf_string_value(chat_template))
        )
    if extra_metadata:
        for key, vtype, val in extra_metadata:
            metadata_items.append(_gguf_metadata(key, vtype, val))

    parts.append(struct.pack("<Q", len(metadata_items)))
    parts.extend(metadata_items)

    # Tensor descriptors
    for tname, dims, ggml_type, offset in tensors:
        parts.append(_gguf_string(tname))
        parts.append(struct.pack("<I", len(dims)))
        for dim in dims:
            parts.append(struct.pack("<Q", dim))
        parts.append(struct.pack("<I", ggml_type))
        parts.append(struct.pack("<Q", offset))

    result = b"".join(parts)
    # Add alignment padding after tensor descriptors
    padding_needed = (alignment - (len(result) % alignment)) % alignment
    result += b"\x00" * padding_needed
    if truncate_at is not None:
        result = result[:truncate_at]
    return result


def write_gguf(path: Path, **kwargs) -> Path:
    """Write a synthetic GGUF fixture to disk."""
    path.write_bytes(build_gguf_v2(**kwargs))
    return path
