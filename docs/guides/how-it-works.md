# How Cancerbero Works

This document explains Cancerbero's architecture, inspection pipeline, and design decisions.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    CANCERBERO CLI                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   Target     │  │   GGUF       │  │   Runtime    │     │
│  │   Discovery  │  │   Parser     │  │   Inspector  │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│         │                │                  │               │
│         ▼                ▼                  ▼               │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              Inspection Pipeline                      │  │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐   │  │
│  │  │Artifact │ │Template │ │Companion│ │Advisory │   │  │
│  │  │ Facts   │ │Analysis │ │  Files  │ │  Join   │   │  │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘   │  │
│  └──────────────────────────────────────────────────────┘  │
│                           │                                 │
│                           ▼                                 │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              Knowledge Bundle                         │  │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐               │  │
│  │  │Advisory │ │Template │ │Runtime  │               │  │
│  │  │Database │ │References│ │  Info   │               │  │
│  │  └─────────┘ └─────────┘ └─────────┘               │  │
│  └──────────────────────────────────────────────────────┘  │
│                           │                                 │
│                           ▼                                 │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              Verdict Policy                    │  │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐               │  │
│  │  │ Core    │ │Finding  │ │Verdict  │               │  │
│  │  │ Checks  │ │Analysis │ │Decision │               │  │
│  │  └─────────┘ └─────────┘ └─────────┘               │  │
│  └──────────────────────────────────────────────────────┘  │
│                           │                                 │
│                           ▼                                 │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              Report Generator                         │  │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐   │  │
│  │  │Terminal │ │  JSON   │ │Markdown │ │  SARIF  │   │  │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘   │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Inspection Pipeline

### : Target Discovery

Cancerbero discovers targets by:

1. **File magic**: Reads first 4 bytes to detect GGUF format
2. **Filename matching**: Recognizes known llama.cpp binary names
3. **Directory traversal**: Bounded depth-first search with limits

**Safety measures**:
- No symlink following
- Bounded depth (default: 4 levels)
- Bounded candidates (default: 256 files)
- Ignores `.git`, `.venv`, `node_modules`, etc.

### : GGUF Parsing

The GGUF parser reads only metadata, never tensor data:

1. **Header validation**: Magic bytes, version, endianness
2. **Metadata extraction**: Key-value pairs with type validation
3. **Tensor descriptors**: Names, dimensions, types, offsets
4. **Alignment verification**: Data block alignment
5. **Range validation**: No overlaps, no out-of-bounds

**Safety measures**:
- Conservative limits on all allocations
- No mmap of tensor data
- Checked arithmetic for all calculations
- Streaming validation before full parsing

### : Template Analysis

Chat templates are analyzed statically:

1. **AST parsing**: Jinja2 template → Abstract Syntax Tree
2. **Pattern detection**: Risky constructs (calls, imports, etc.)
3. **Poison detection**: Attack-specific patterns
4. **Reference comparison**: Against known templates (when available)

**Safety measures**:
- Never renders templates
- Bounded AST node count
- Bounded template size
- No code execution

### : Companion File Inspection

Files in the model directory are inspected:

1. **File discovery**: Bounded traversal of companion files
2. **Content analysis**: Pattern matching for suspicious content
3. **Trust decisions**: auto_map, trust_remote_code, remote references
4. **Rules File Backdoor**: Detection of malicious instructions
5. **Enhanced security**: Pickle, MCP, credentials, exfiltration

**Safety measures**:
- Bounded file count and size
- No code execution
- Pattern matching only

### : Advisory Join

Artifact properties are crossed with runtime identity:

1. **Runtime identification**: Build number, version, commit
2. **Advisory matching**: Version ranges, artifact predicates
3. **Applicability determination**: affected, fixed, unknown, not_applicable

**Safety measures**:
- Conservative version comparison
- Honest unknown states
- No inference of safety

### : Verdict Decision ()

The verdict policy requires positive evidence from core checks:

1. **Core check evaluation**: gguf_structure, chat_template_static, runtime_advisory_join
2. **Finding analysis**: Status, confidence, severity
3. **Verdict decision**: SUITABLE, NOT SUITABLE, or UNDETERMINED

**Core checks**:
- `gguf_structure` — GGUF parsed successfully
- `chat_template_static` — Template analyzed (present or absent)
- `runtime_advisory_join` — Runtime version identified and checked

**Verdict logic**:
- All core checks pass, no suspicious findings → SUITABLE
- High-confidence suspicious finding → NOT SUITABLE
- Medium-confidence suspicious finding → UNDETERMINED
- Missing core check → UNDETERMINED
- Error condition → UNDETERMINED

### : Report Generation

Findings are compiled into reports:

1. **Verdict calculation**: Based on finding statuses
2. **Coverage summary**: What was and wasn't checked
3. **Format rendering**: Terminal, JSON, Markdown, SARIF

## Design Decisions

### Why No ML Frameworks?

Cancerbero deliberately avoids ML frameworks because:

1. **Security**: ML frameworks have large attack surfaces
2. **Size**: Keeps installation small and fast
3. **Reliability**: Fewer dependencies = fewer failure modes
4. **Focus**: Cancerbero inspects metadata, not model behavior

### Why Static Analysis Only?

Cancerbero uses static analysis (no model execution) because:

1. **Safety**: Executing untrusted models is risky
2. **Speed**: Static analysis is fast
3. **Determinism**: Same input → same output
4. **Scope**: Cancerbero checks what's verifiable without execution

### Why No Safety Seals?

Cancerbero doesn't provide binary "safe/unsafe" verdicts because:

1. **Honesty**: Absence of evidence ≠ evidence of absence
2. **Context**: What's risky depends on the deployment
3. **Actionability**: Specific findings are more useful than scores
4. **Trust**: Users should understand what was checked

### Why Core Checks?

Cancerbero requires positive evidence from core checks because:

1. **Honesty**: "SUITABLE on no evidence" is misleading
2. **Friction**: Requiring runtime version is deliberate friction
3. **Trust**: Users should provide evidence for definitive verdicts
4. **Safety**: Missing checks should not produce positive verdicts

### Why Embedded Bundle?

The knowledge bundle is embedded in the package because:

1. **Offline**: Works without network access
2. **Integrity**: Signed with the package
3. **Simplicity**: No separate update mechanism
4. **Trust**: Users trust the package, not external sources

## Performance Characteristics

### Metadata-Only Inspection

| File Size | Time | Bytes Read | Percentage |
|-----------|------|------------|------------|
| 1 GB | < 1s | ~10 MB | ~1% |
| 10 GB | < 2s | ~15 MB | ~0.15% |
| 50 GB | < 5s | ~20 MB | ~0.04% |

### Hash Calculation

| File Size | Time | Throughput |
|-----------|------|------------|
| 1 GB | ~2s | ~500 MB/s |
| 10 GB | ~20s | ~500 MB/s |
| 50 GB | ~100s | ~500 MB/s |

### Memory Usage

| Operation | Peak Memory |
|-----------|-------------|
| Metadata inspection | < 100 MB |
| Hash calculation | < 50 MB |
| Template analysis | < 50 MB |
| Full check | < 200 MB |

## Security Considerations

### What Cancerbero Trusts

1. **The package itself**: Embedded bundle, code
2. **Local filesystem**: File contents, metadata
3. **Python runtime**: Standard library, Jinja2

### What Cancerbero Doesn't Trust

1. **GGUF files**: Treated as untrusted input
2. **Companion files**: Scanned for malicious patterns
3. **Runtime binaries**: Not executed by default
4. **External bundles**: Not supported in 0.1.0

### Attack Surface

Cancerbero's attack surface is minimal:

1. **GGUF parser**: Bounded, validated, no tensor data
2. **Template parser**: AST only, no rendering
3. **File reading**: Bounded, no code execution
4. **No network**: No outbound connections
5. **No execution**: No model or binary execution

## Limitations

### What Cancerbero Can Detect

- Known runtime vulnerabilities (via advisory join)
- Suspicious template patterns (via static analysis)
- Malicious companion files (via pattern matching)
- Template mismatches across files
- Structural GGUF issues
- Pickle deserialization risks
- MCP server configuration risks
- Hardcoded credentials
- Remote code execution configurations
- Network exfiltration patterns

### What Cancerbero Cannot Detect

- Backdoors in model weights
- Novel, unknown vulnerabilities
- Behavior that only manifests during execution
- Sophisticated obfuscation that evades pattern matching
- Zero-day exploits

## Future Directions

### Planned Improvements

1. **More advisories**: Additional CVEs and security bulletins
2. **More runtimes**: Ollama, llama-cpp-python, vLLM, SGLang
3. **External bundles**: Signed, updatable knowledge bundles
4. **Template references**: Exact references for more model families
5. **Performance**: Faster parsing, parallel processing

### Research Areas

1. **Weight analysis**: Statistical detection of backdoors (cancerbero-lab)
2. **Behavioral testing**: Differential analysis with reference models
3. **Provenance verification**: Cryptographic signing and verification
4. **Continuous monitoring**: Runtime behavior tracking
