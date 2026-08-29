# Decision Record 0003 — Quantization Integrity Scope

**Date:** 2026-08-28
**Status:** Accepted

## Context

v0.5 introduced three "quantization integrity" findings
(`cbr.gguf.unknown_quant_type`, `cbr.gguf.tensor_misalignment`,
`cbr.gguf.zero_dimension`). The findings existed in the inspector but
could never be produced against a real GGUF file: the GGUF reader in
`cancerbero.gguf.reader` rejects every condition those findings
targeted with a typed exception (`GgufTypeError`, `GgufRangeError`,
`GgufValidationError`) before `inspect_gguf` ever sees the document.

The unit tests for those findings constructed `GgufDocument` objects in
memory and bypassed the reader, producing a green test suite that gave
false confidence.

## Decision

Remove the three dead quantization integrity checks. Surface any
parser-rejected condition as an `error` finding on `gguf_structure`
instead.

## Consequences

- The CHANGELOG entry "Quantization Integrity: Tensor misalignment
  detection" no longer reflects the actual behaviour and has been
  rewritten.
- Operators lose three never-emitted `suspicious` findings. They gain a
  stronger guarantee: any GGUF file that violates tensor invariants
  fails the core check with `status=error` and the verdict becomes
  `UNDETERMINED` (exit 2).
- The unit tests in `tests/unit/test_quantization_integrity.py` now
  assert that the reader, not the inspector, raises the typed
  exceptions for unknown types, misaligned offsets, and zero-sized
  dimensions. The old "spy the inspector" tests were deleted.

## Alternatives considered

- **Move the checks into the reader and emit typed findings there.**
  Rejected: the reader must be exception-driven to keep its surface
  small and its invariants clear. Mixing finding emission into the
  reader would couple the parser to the report schema.
- **Make the reader tolerant (no exception, return UNCHECKED tensors)
  and let the inspector decide.** Rejected: a tolerant reader is more
  expensive to reason about and removes the typed exception signal
  that callers already use for defensive programming.
- **Reintroduce the checks behind a `--paranoid` flag once we have a
  corpus of malformed GGUF files.** Accepted as future work; see
  `docs/decisions/0002-deferred-features-v0.1.md`.