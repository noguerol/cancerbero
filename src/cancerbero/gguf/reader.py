"""Bounded, sequential GGUF v2/v3 reader that never reads tensor data."""

from __future__ import annotations

import codecs
import os
import re
import stat
import struct
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Any, BinaryIO

from cancerbero.gguf.limits import DEFAULT_LIMITS, ParserLimits

GGUF_MAGIC = b"GGUF"
DEFAULT_ALIGNMENT = 32
UINT64_MAX = (1 << 64) - 1


class GgufError(Exception):
    """Base class for errors caused while inspecting a GGUF file."""


class GgufIoError(GgufError):
    """The input could not be opened or read as a regular file."""


class GgufMagicError(GgufError):
    """The file does not have the GGUF byte-level magic."""


class GgufVersionError(GgufError):
    """The GGUF version or its byte order is unsupported."""


class GgufTruncatedError(GgufError):
    """The file ends before a declared structure is complete."""


class GgufLimitError(GgufError):
    """A configured parser limit was exceeded."""


class GgufTypeError(GgufError):
    """A metadata or tensor type is not explicitly supported."""


class GgufDuplicateError(GgufError):
    """A metadata key or tensor name is duplicated."""


class GgufValidationError(GgufError):
    """A GGUF structure violates a format invariant."""


class GgufRangeError(GgufValidationError):
    """A tensor range is invalid, out of bounds, or overlapping."""


class GgufValueType(IntEnum):
    UINT8 = 0
    INT8 = 1
    UINT16 = 2
    INT16 = 3
    UINT32 = 4
    INT32 = 5
    FLOAT32 = 6
    BOOL = 7
    STRING = 8
    ARRAY = 9
    UINT64 = 10
    INT64 = 11
    FLOAT64 = 12


# GGML type id -> (block elements, encoded block bytes). This is intentionally
# explicit. Removed ids 4, 5, 31-33, and 36-38 are holes and are not inferred.
# The table follows current ggml's public ggml_type and quant block definitions.
GGML_TYPE_SIZES: dict[int, tuple[int, int]] = {
    0: (1, 4),  # F32
    1: (1, 2),  # F16
    2: (32, 18),  # Q4_0
    3: (32, 20),  # Q4_1
    6: (32, 22),  # Q5_0
    7: (32, 24),  # Q5_1
    8: (32, 34),  # Q8_0
    9: (32, 40),  # Q8_1
    10: (256, 84),  # Q2_K
    11: (256, 110),  # Q3_K
    12: (256, 144),  # Q4_K
    13: (256, 176),  # Q5_K
    14: (256, 210),  # Q6_K
    15: (256, 292),  # Q8_K
    16: (256, 66),  # IQ2_XXS
    17: (256, 74),  # IQ2_XS
    18: (256, 98),  # IQ3_XXS
    19: (256, 50),  # IQ1_S
    20: (32, 18),  # IQ4_NL
    21: (256, 110),  # IQ3_S
    22: (256, 82),  # IQ2_S
    23: (256, 136),  # IQ4_XS
    24: (1, 1),  # I8
    25: (1, 2),  # I16
    26: (1, 4),  # I32
    27: (1, 8),  # I64
    28: (1, 8),  # F64
    29: (256, 56),  # IQ1_M
    30: (1, 2),  # BF16
    34: (256, 54),  # TQ1_0
    35: (256, 66),  # TQ2_0
    39: (32, 17),  # MXFP4
    40: (64, 36),  # NVFP4
    41: (128, 18),  # Q1_0
    42: (64, 18),  # Q2_0
    # ROCmFP4/ROCmFPX experimental types (AMD ROCm forks)
    100: (32, 18),  # Q4_0_ROCMFP4 (dual UE4M3 scales)
    101: (32, 17),  # Q4_0_ROCMFP4_FAST (single UE4M3 scale)
    102: (32, 26),  # Q6_0_ROCMFPX / TURBO3_0 (fork-dependent)
    103: (32, 33),  # Q8_0_ROCMFPX / TURBO4_0 (fork-dependent)
    104: (32, 14),  # Q3_0_ROCMFPX
    105: (32, 14),  # TURBO3_0 (ROCmFPX fork)
    106: (32, 18),  # TURBO4_0 (ROCmFPX fork)
    107: (32, 10),  # Q2_0_ROCMFPX
    108: (32, 17),  # Q4_0_ROCMI4
}

_SCALAR_FORMATS: dict[GgufValueType, str] = {
    GgufValueType.UINT8: "B",
    GgufValueType.INT8: "b",
    GgufValueType.UINT16: "H",
    GgufValueType.INT16: "h",
    GgufValueType.UINT32: "I",
    GgufValueType.INT32: "i",
    GgufValueType.FLOAT32: "f",
    GgufValueType.UINT64: "Q",
    GgufValueType.INT64: "q",
    GgufValueType.FLOAT64: "d",
}

_STANDARD_METADATA_TYPES = {
    "general.alignment": GgufValueType.UINT32,
    "general.architecture": GgufValueType.STRING,
    "general.file_type": GgufValueType.UINT32,
    "general.name": GgufValueType.STRING,
    "general.quantization_version": GgufValueType.UINT32,
    "tokenizer.chat_template": GgufValueType.STRING,
}
_ESSENTIAL_METADATA = frozenset(_STANDARD_METADATA_TYPES)
_KEY_PATTERN = re.compile(r"[a-z0-9]+(?:[_-][a-z0-9]+)*(?:\.[a-z0-9]+(?:[_-][a-z0-9]+)*)*")
_OMITTED = object()


@dataclass(frozen=True, slots=True)
class GgufTensor:
    """A validated tensor descriptor; no tensor bytes are retained or read."""

    name: str
    dimensions: tuple[int, ...]
    ggml_type: int
    offset: int
    byte_size: int


@dataclass(frozen=True, slots=True)
class GgufDocument:
    path: Path
    file_size: int
    version: int
    endian: str
    tensor_count: int
    metadata_count: int
    metadata: dict[str, Any]
    metadata_types: dict[str, GgufValueType]
    omitted_metadata_keys: tuple[str, ...]
    metadata_end: int
    tensor_data_offset: int
    alignment: int
    tensors: tuple[GgufTensor, ...]
    bytes_read: int


@dataclass(frozen=True, slots=True)
class _RawTensor:
    name: str
    dimensions: tuple[int, ...]
    ggml_type: int
    offset: int
    byte_size: int


class GgufReader:
    """Read and validate only GGUF metadata and tensor descriptors."""

    def __init__(
        self,
        path: str | Path,
        limits: ParserLimits = DEFAULT_LIMITS,
    ) -> None:
        self.path = Path(path)
        self.limits = limits
        self._stream: BinaryIO | None = None
        self._file_size = 0
        self._offset = 0
        self._bytes_read = 0
        self._endian = "<"
        self._metadata_start = 0
        self._metadata_end_limit = 0
        self._retained_bytes = 0
        self._array_elements = 0

    def read(self) -> GgufDocument:
        try:
            with self.path.open("rb", buffering=0) as stream:
                file_stat = os.fstat(stream.fileno())
                if not stat.S_ISREG(file_stat.st_mode):
                    raise GgufIoError(f"GGUF input is not a regular file: {self.path}")
                self._stream = stream
                self._file_size = file_stat.st_size
                return self._read_document()
        except GgufError:
            raise
        except OSError as exc:
            raise GgufIoError(f"Could not read GGUF file {self.path}: {exc}") from exc
        finally:
            self._stream = None

    def _read_document(self) -> GgufDocument:
        magic = self._read_exact(4, "GGUF magic")
        if magic != GGUF_MAGIC:
            raise GgufMagicError("Invalid GGUF magic; expected byte sequence 'GGUF'")

        raw_version = self._read_exact(4, "GGUF version")
        version, endian = self._decode_version(raw_version)
        self._endian = endian

        tensor_count = self._read_integer("Q", "tensor count")
        metadata_count = self._read_integer("Q", "metadata count")
        self._check_count("metadata key-value count", metadata_count, self.limits.max_kv_count)
        self._check_count("tensor count", tensor_count, self.limits.max_tensor_count)

        self._metadata_start = self._offset
        self._metadata_end_limit = self._metadata_start + self.limits.max_metadata_bytes
        metadata: dict[str, Any] = {}
        metadata_types: dict[str, GgufValueType] = {}
        omitted: list[str] = []
        seen_keys: set[str] = set()

        for index in range(metadata_count):
            key = self._read_string(
                self.limits.max_key_bytes,
                f"metadata key {index}",
                metadata=True,
                retain=True,
            )
            assert isinstance(key, str)
            self._validate_key(key, index)
            if key in seen_keys:
                raise GgufDuplicateError(f"Duplicate metadata key {key!r}")
            seen_keys.add(key)

            raw_type = self._read_integer("I", f"metadata type for {key!r}", metadata=True)
            value_type = self._value_type(raw_type, f"metadata key {key!r}")
            expected_type = _STANDARD_METADATA_TYPES.get(key)
            if expected_type is not None and value_type is not expected_type:
                raise GgufValidationError(
                    f"Metadata key {key!r} must have type {expected_type.name}, "
                    f"not {value_type.name}"
                )
            metadata_types[key] = value_type
            value = self._read_value(
                value_type,
                depth=0,
                retain=True,
                context=f"metadata value for {key!r}",
                string_limit=(
                    self.limits.max_template_bytes
                    if key == "tokenizer.chat_template"
                    else self.limits.max_string_bytes
                ),
                essential=key in _ESSENTIAL_METADATA,
            )
            if value is _OMITTED:
                omitted.append(key)
            else:
                metadata[key] = value

        metadata_end = self._offset
        alignment = metadata.get("general.alignment", DEFAULT_ALIGNMENT)
        if not isinstance(alignment, int):
            raise GgufValidationError("Metadata key 'general.alignment' is not an integer")
        self._validate_alignment(alignment)

        # Every descriptor needs at least one dimension and 32 encoded bytes.
        self._ensure_can_consume(
            self._checked_multiply(tensor_count, 32, "minimum tensor descriptor bytes"),
            "tensor descriptors",
        )
        raw_tensors: list[_RawTensor] = []
        seen_tensor_names: set[str] = set()
        for index in range(tensor_count):
            tensor = self._read_tensor(index, alignment)
            if tensor.name in seen_tensor_names:
                raise GgufDuplicateError(f"Duplicate tensor name {tensor.name!r}")
            seen_tensor_names.add(tensor.name)
            raw_tensors.append(tensor)

        descriptor_end = self._offset
        tensor_data_offset = self._align(descriptor_end, alignment)
        padding_size = tensor_data_offset - descriptor_end
        if padding_size:
            if descriptor_end + padding_size > self._file_size:
                # File ends before aligned tensor data start. This is valid
                # when there are no tensors; the data block is simply absent.
                if tensor_count > 0:
                    raise GgufTruncatedError(
                        f"Truncated alignment padding before tensor data at byte {descriptor_end}"
                    )
                tensor_data_offset = descriptor_end
            else:
                self._read_exact(padding_size, "tensor data alignment padding")

        tensors = self._validate_tensor_ranges(raw_tensors, tensor_data_offset)
        return GgufDocument(
            path=self.path,
            file_size=self._file_size,
            version=version,
            endian="little" if endian == "<" else "big",
            tensor_count=tensor_count,
            metadata_count=metadata_count,
            metadata=metadata,
            metadata_types=metadata_types,
            omitted_metadata_keys=tuple(omitted),
            metadata_end=metadata_end,
            tensor_data_offset=tensor_data_offset,
            alignment=alignment,
            tensors=tuple(tensors),
            bytes_read=self._bytes_read,
        )

    @staticmethod
    def _decode_version(raw: bytes) -> tuple[int, str]:
        little = struct.unpack("<I", raw)[0]
        big = struct.unpack(">I", raw)[0]
        if little in {2, 3}:
            return little, "<"
        if big == 3:
            return 3, ">"
        if big == 2:
            raise GgufVersionError("Big-endian GGUF is supported only for version 3")
        displayed = big if raw[:2] == b"\x00\x00" else little
        raise GgufVersionError(f"Unsupported GGUF version {displayed}; expected version 2 or 3")

    def _read_tensor(self, index: int, alignment: int) -> _RawTensor:
        name = self._read_string(
            self.limits.max_tensor_name_bytes,
            f"tensor name {index}",
            metadata=False,
            retain=True,
        )
        assert isinstance(name, str)
        dimension_count = self._read_integer("I", f"dimension count for tensor {name!r}")
        if dimension_count == 0:
            raise GgufValidationError(f"Tensor {name!r} has no dimensions")
        self._check_count("tensor dimension count", dimension_count, self.limits.max_dimensions)
        self._ensure_can_consume(
            self._checked_multiply(dimension_count, 8, "tensor dimensions"),
            f"dimensions for tensor {name!r}",
        )
        dimensions = tuple(
            self._read_integer("Q", f"dimension {axis} for tensor {name!r}")
            for axis in range(dimension_count)
        )
        if any(dimension == 0 for dimension in dimensions):
            raise GgufValidationError(f"Tensor {name!r} has a zero-sized dimension")

        ggml_type = self._read_integer("I", f"GGML type for tensor {name!r}")
        if ggml_type not in GGML_TYPE_SIZES:
            raise GgufTypeError(
                f"Unknown or unsupported GGML tensor type id {ggml_type} for tensor {name!r}"
            )
        relative_offset = self._read_integer("Q", f"data offset for tensor {name!r}")
        if relative_offset % alignment:
            raise GgufRangeError(
                f"Tensor {name!r} offset {relative_offset} is not aligned to {alignment} bytes"
            )
        byte_size = self._tensor_byte_size(name, dimensions, ggml_type)
        return _RawTensor(name, dimensions, ggml_type, relative_offset, byte_size)

    def _tensor_byte_size(self, name: str, dimensions: tuple[int, ...], ggml_type: int) -> int:
        block_size, type_size = GGML_TYPE_SIZES[ggml_type]
        if dimensions[0] % block_size:
            raise GgufValidationError(
                f"Tensor {name!r} first dimension {dimensions[0]} is not a multiple "
                f"of GGML type {ggml_type} block size {block_size}"
            )
        blocks_per_row = dimensions[0] // block_size
        row_count = self._checked_product(dimensions[1:], f"row count for tensor {name!r}")
        block_count = self._checked_multiply(
            blocks_per_row, row_count, f"block count for tensor {name!r}"
        )
        return self._checked_multiply(block_count, type_size, f"byte size for tensor {name!r}")

    def _validate_tensor_ranges(
        self,
        raw_tensors: list[_RawTensor],
        tensor_data_offset: int,
    ) -> list[GgufTensor]:
        if tensor_data_offset > self._file_size:
            raise GgufTruncatedError(
                f"Tensor data begins at byte {tensor_data_offset},"
                f" beyond file size {self._file_size}"
            )
        ranges: list[tuple[int, int, str]] = []
        tensors: list[GgufTensor] = []
        for tensor in raw_tensors:
            absolute_start = tensor_data_offset + tensor.offset
            absolute_end = absolute_start + tensor.byte_size
            if absolute_start > UINT64_MAX or absolute_end > UINT64_MAX:
                raise GgufRangeError(f"Tensor {tensor.name!r} range overflows a 64-bit offset")
            if absolute_start < tensor_data_offset or absolute_end > self._file_size:
                raise GgufRangeError(
                    f"Tensor {tensor.name!r} byte range [{absolute_start}, {absolute_end}) "
                    f"is outside file size {self._file_size}"
                )
            ranges.append((absolute_start, absolute_end, tensor.name))
            tensors.append(
                GgufTensor(
                    name=tensor.name,
                    dimensions=tensor.dimensions,
                    ggml_type=tensor.ggml_type,
                    offset=tensor.offset,
                    byte_size=tensor.byte_size,
                )
            )

        ranges.sort(key=lambda item: (item[0], item[1], item[2]))
        for previous, current in zip(ranges, ranges[1:], strict=False):
            if current[0] < previous[1]:
                raise GgufRangeError(
                    f"Tensor ranges overlap: {previous[2]!r} [{previous[0]}, {previous[1]}) "
                    f"and {current[2]!r} [{current[0]}, {current[1]})"
                )
        return tensors

    def _read_value(
        self,
        value_type: GgufValueType,
        *,
        depth: int,
        retain: bool,
        context: str,
        string_limit: int,
        essential: bool = False,
    ) -> Any:
        if value_type in _SCALAR_FORMATS:
            fmt = _SCALAR_FORMATS[value_type]
            size = struct.calcsize(fmt)
            value = self._read_integer(fmt, context, metadata=True)
            if retain and self._reserve_retained(size, essential=essential, context=context):
                return value
            return _OMITTED

        if value_type is GgufValueType.BOOL:
            raw = self._read_integer("B", context, metadata=True)
            if raw not in {0, 1}:
                raise GgufValidationError(
                    f"Invalid boolean value {raw} in {context}; expected 0 or 1"
                )
            if retain and self._reserve_retained(1, essential=essential, context=context):
                return bool(raw)
            return _OMITTED

        if value_type is GgufValueType.STRING:
            return self._read_string(
                string_limit,
                context,
                metadata=True,
                retain=retain,
                charge_retention=True,
                essential=essential,
            )

        if value_type is not GgufValueType.ARRAY:
            raise GgufTypeError(f"Unsupported metadata value type {value_type!r} in {context}")

        array_depth = depth + 1
        if array_depth > self.limits.max_array_depth:
            raise GgufLimitError(
                f"Metadata array depth {array_depth} exceeds limit {self.limits.max_array_depth}"
            )
        raw_element_type = self._read_integer(
            "I", f"array element type in {context}", metadata=True
        )
        element_type = self._value_type(raw_element_type, f"array element type in {context}")
        count = self._read_integer("Q", f"array length in {context}", metadata=True)
        self._check_count("metadata array element count", count, self.limits.max_array_elements)
        if self._array_elements + count > self.limits.max_array_elements:
            raise GgufLimitError(
                "Cumulative metadata array element count exceeds limit "
                f"{self.limits.max_array_elements}"
            )
        self._array_elements += count

        minimum_item_size = self._minimum_value_size(element_type)
        minimum_bytes = self._checked_multiply(count, minimum_item_size, "minimum array bytes")
        self._ensure_can_consume(minimum_bytes, context, metadata=True)

        keep_array = retain and self._reserve_retained(
            self._checked_multiply(count, 8, "retained array references"),
            essential=essential,
            context=context,
        )
        values: list[Any] | None = [] if keep_array else None
        complete = keep_array
        for index in range(count):
            value = self._read_value(
                element_type,
                depth=array_depth,
                retain=keep_array,
                context=f"{context}, array element {index}",
                string_limit=self.limits.max_string_bytes,
                essential=essential,
            )
            if value is _OMITTED:
                complete = False
            elif values is not None:
                values.append(value)
        return values if complete and values is not None else _OMITTED

    @staticmethod
    def _minimum_value_size(value_type: GgufValueType) -> int:
        if value_type in _SCALAR_FORMATS:
            return struct.calcsize(_SCALAR_FORMATS[value_type])
        if value_type is GgufValueType.BOOL:
            return 1
        if value_type is GgufValueType.STRING:
            return 8
        if value_type is GgufValueType.ARRAY:
            return 12
        raise GgufTypeError(f"Unsupported metadata value type {value_type!r}")

    def _read_string(
        self,
        maximum: int,
        context: str,
        *,
        metadata: bool,
        retain: bool,
        charge_retention: bool = False,
        essential: bool = False,
    ) -> str | object:
        length = self._read_integer("Q", f"length of {context}", metadata=metadata)
        if length > maximum:
            raise GgufLimitError(f"{context.capitalize()} length {length} exceeds limit {maximum}")
        self._ensure_can_consume(length, context, metadata=metadata)

        keep = retain
        if charge_retention:
            keep = retain and self._reserve_retained(
                length,
                essential=essential,
                context=context,
            )
        if keep:
            raw = self._read_exact(length, context, metadata=metadata)
            try:
                return raw.decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise GgufValidationError(
                    f"Invalid UTF-8 in {context} at byte {exc.start}"
                ) from exc

        decoder = codecs.getincrementaldecoder("utf-8")("strict")
        remaining = length
        try:
            while remaining:
                chunk_size = min(remaining, 64 * 1024)
                decoder.decode(
                    self._read_exact(chunk_size, context, metadata=metadata),
                    final=chunk_size == remaining,
                )
                remaining -= chunk_size
            if length == 0:
                decoder.decode(b"", final=True)
        except UnicodeDecodeError as exc:
            raise GgufValidationError(f"Invalid UTF-8 in {context} at byte {exc.start}") from exc
        return _OMITTED

    def _read_integer(self, fmt: str, context: str, *, metadata: bool = False) -> int | float:
        full_format = self._endian + fmt
        size = struct.calcsize(full_format)
        return struct.unpack(full_format, self._read_exact(size, context, metadata=metadata))[0]

    def _read_exact(self, size: int, context: str, *, metadata: bool = False) -> bytes:
        self._ensure_can_consume(size, context, metadata=metadata)
        if size == 0:
            return b""
        assert self._stream is not None
        data = self._stream.read(size)
        self._bytes_read += len(data)
        self._offset += len(data)
        if len(data) != size:
            raise GgufTruncatedError(
                f"Truncated GGUF while reading {context} at byte {self._offset - len(data)}; "
                f"needed {size} bytes, found {len(data)}"
            )
        return data

    def _ensure_can_consume(self, size: int, context: str, *, metadata: bool = False) -> None:
        if size < 0:
            raise GgufValidationError(f"Negative byte count while reading {context}")
        end = self._offset + size
        if metadata and end > self._metadata_end_limit:
            used = self._offset - self._metadata_start
            raise GgufLimitError(
                f"Metadata byte budget {self.limits.max_metadata_bytes} would be exceeded "
                f"after {used} bytes while reading {context}"
            )
        if end > self._file_size:
            raise GgufTruncatedError(
                f"Truncated GGUF while reading {context} at byte {self._offset}; "
                f"needed {size} bytes with {self._file_size - self._offset} available"
            )

    def _reserve_retained(self, size: int, *, essential: bool, context: str) -> bool:
        if self._retained_bytes + size <= self.limits.max_retained_metadata_bytes:
            self._retained_bytes += size
            return True
        if essential:
            raise GgufLimitError(
                f"Retained metadata budget {self.limits.max_retained_metadata_bytes} "
                f"would be exceeded while retaining {context}"
            )
        return False

    @staticmethod
    def _value_type(raw: int | float, context: str) -> GgufValueType:
        try:
            return GgufValueType(int(raw))
        except ValueError as exc:
            raise GgufTypeError(f"Unknown GGUF metadata type id {raw} in {context}") from exc

    @staticmethod
    def _check_count(label: str, value: int | float, maximum: int) -> None:
        count = int(value)
        if count > maximum:
            raise GgufLimitError(f"{label.capitalize()} {count} exceeds limit {maximum}")

    @staticmethod
    def _checked_multiply(left: int, right: int, context: str) -> int:
        result = left * right
        if result > UINT64_MAX:
            raise GgufValidationError(f"64-bit multiplication overflow in {context}")
        return result

    def _checked_product(self, values: tuple[int, ...], context: str) -> int:
        result = 1
        for value in values:
            result = self._checked_multiply(result, value, context)
        return result

    @staticmethod
    def _align(offset: int, alignment: int) -> int:
        return offset + (-offset % alignment)

    @staticmethod
    def _validate_alignment(alignment: int) -> None:
        if alignment < 8 or alignment & (alignment - 1):
            raise GgufValidationError(
                f"Invalid GGUF alignment {alignment}; expected a power of two of at least 8"
            )

    @staticmethod
    def _validate_key(key: str, index: int) -> None:
        try:
            key.encode("ascii", errors="strict")
        except UnicodeEncodeError as exc:
            raise GgufValidationError(
                f"Metadata key {index} must contain ASCII characters only"
            ) from exc
        if not _KEY_PATTERN.fullmatch(key):
            raise GgufValidationError(f"Metadata key {key!r} contains invalid characters")


def read_gguf(path: str | Path, limits: ParserLimits = DEFAULT_LIMITS) -> GgufDocument:
    """Read a GGUF file without mapping or reading any tensor bytes."""

    return GgufReader(path, limits).read()


__all__ = [
    "DEFAULT_ALIGNMENT",
    "GGML_TYPE_SIZES",
    "GgufDocument",
    "GgufDuplicateError",
    "GgufError",
    "GgufIoError",
    "GgufLimitError",
    "GgufMagicError",
    "GgufRangeError",
    "GgufReader",
    "GgufTensor",
    "GgufTruncatedError",
    "GgufTypeError",
    "GgufValidationError",
    "GgufValueType",
    "GgufVersionError",
    "read_gguf",
]
