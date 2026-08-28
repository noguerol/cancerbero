#!/usr/bin/env python3
"""Coverage-guided harness for the bounded GGUF parser.

Install ``atheris`` separately and run:
    python fuzz/fuzz_gguf.py tests/corpus/gguf -max_len=1048576

The production package does not depend on the fuzzer.
"""

from __future__ import annotations

import os
import sys
import tempfile

import atheris

with atheris.instrument_imports():
    from cancerbero.gguf.inspector import GgufError, inspect_gguf
    from cancerbero.gguf.limits import ParserLimits

FUZZ_LIMITS = ParserLimits(
    max_metadata_bytes=1 << 20,
    max_retained_metadata_bytes=1 << 18,
    max_string_bytes=1 << 16,
    max_template_bytes=1 << 14,
    max_array_elements=4096,
    max_array_depth=4,
    max_kv_count=512,
    max_tensor_count=512,
    max_dimensions=4,
    max_tensor_name_bytes=256,
    max_key_bytes=256,
    max_directory_depth=2,
    max_directory_candidates=16,
    subprocess_timeout_seconds=1.0,
    max_subprocess_output_bytes=4096,
)


def fuzz_one_input(data: bytes) -> None:
    descriptor, name = tempfile.mkstemp(suffix=".gguf")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
        try:
            inspect_gguf(name, limits=FUZZ_LIMITS)
        except (GgufError, OSError, UnicodeError, ValueError):
            pass
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass


def main() -> None:
    atheris.Setup(sys.argv, fuzz_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
