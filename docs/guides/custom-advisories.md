# Custom Advisory Rules

This guide explains how Cancerbero's advisory system works and how to extend it with custom rules.

## Advisory System Overview

Cancerbero includes an embedded knowledge bundle of security advisories for llama.cpp and related components. These advisories are used to cross-reference artifact properties with runtime vulnerabilities.

### How It Works

1. **Artifact Properties**: Cancerbero extracts properties from GGUF files (format, template, dimensions, etc.)
2. **Runtime Identity**: Cancerbero identifies the llama.cpp build/version
3. **Advisory Rules**: Cancerbero matches properties and runtime against known advisories
4. **Findings**: Cancerbero generates findings based on matches

### Advisory Structure

Each advisory contains:

```json
{
  "id": "CVE-2026-27940",
  "title": "GHSA-3p4r-fq3f-q74v: heap buffer overflow in GGUF mem_size calculation",
  "source": "https://github.com/ggml-org/llama.cpp/security/advisories/GHSA-3p4r-fq3f-q74v",
  "component": "llama.cpp",
  "version_scheme": "llama_cpp_build",
  "affected": {"lte": 8145},
  "fixed": {"gte": 8146},
  "artifact_predicates": [
    {"field": "format", "operator": "present"},
    {"field": "format", "operator": "equals", "value": "gguf"}
  ],
  "severity": "high",
  "confidence": "high",
  "explanation": "This llama.cpp build is exposed to a vulnerable GGUF loader path.",
  "action": "Do not load the artifact with this runtime; update llama.cpp to build b8146 or later.",
  "published": "2026-03-12",
  "reviewed": "2026-08-28"
}
```

### Fields Explained

| Field | Description |
|-------|-------------|
| `id` | Unique identifier (CVE, GHSA, or custom) |
| `title` | Human-readable title |
| `source` | URL to primary source |
| `component` | Affected component (llama.cpp, llama-cpp-python, etc.) |
| `version_scheme` | Version numbering scheme |
| `affected` | Version range that is affected |
| `fixed` | Version range that is fixed |
| `artifact_predicates` | Conditions on artifact properties |
| `severity` | Severity level |
| `confidence` | Confidence level |
| `explanation` | Detailed explanation |
| `action` | Recommended action |
| `published` | Publication date |
| `reviewed` | Last review date |

## Version Schemes

### llama_cpp_build

For llama.cpp build numbers (e.g., b8146):

```json
{
  "version_scheme": "llama_cpp_build",
  "affected": {"lte": 8145},
  "fixed": {"gte": 8146}
}
```

Operators:
- `gt`: greater than
- `gte`: greater than or equal
- `lt`: less than
- `lte`: less than or equal

### semver

For semantic versions (e.g., 0.2.72):

```json
{
  "version_scheme": "semver",
  "affected": {"gte": "0.2.30", "lte": "0.2.71"},
  "fixed": {"gte": "0.2.72"}
}
```

## Artifact Predicates

Predicates define conditions on artifact properties:

### present

Check if a field exists:

```json
{"field": "format", "operator": "present"}
```

### equals

Check if a field equals a value:

```json
{"field": "format", "operator": "equals", "value": "gguf"}
```

### Available Fields

| Field | Description | Example |
|-------|-------------|---------|
| `format` | File format | "gguf" |
| `architecture` | Model architecture | "llama", "qwen35" |
| `name` | Model name | "Qwen3.6-27B" |
| `has_chat_template` | Whether template exists | true/false |
| `file_type` | Quantization type | 30 |
| `gguf_version` | GGUF version | 2, 3 |

## Built-in Advisories

Cancerbero includes these advisories:

| ID | Component | Severity | Description |
|----|-----------|----------|-------------|
| CVE-2024-32878 | llama.cpp | HIGH | Uninitialized variable in GGUF loader |
| CVE-2024-34359 | llama-cpp-python | CRITICAL | Template injection |
| CVE-2026-27940 | llama.cpp | HIGH | Heap buffer overflow in mem_size |
| CVE-2026-33298 | llama.cpp | HIGH | Heap buffer overflow in tensor parsing |
| CVE-2026-5760 | SGLang | HIGH | Template injection in /v1/rerank |
| GGUF-2026-05-001 | llama.cpp | HIGH | Multiple GGUF parser vulnerabilities |
| GGUF-STRUCT-001 | llama.cpp | MEDIUM | Zero-sized tensor dimensions |

## Extending the Advisory Bundle

### Current Limitations

In 0.1.0, the advisory bundle is embedded in the package and cannot be extended without modifying the source code. Future versions may support:

- External signed bundle updates
- Community-contributed advisories
- Custom rule files

### Workaround: Custom Checks

For now, you can implement custom checks by:

1. **Using companion file inspection**: Cancerbero already scans companion files for suspicious patterns
2. **Post-processing JSON output**: Parse Cancerbero's JSON output and add custom checks
3. **Contributing to the bundle**: Submit pull requests to add advisories

### Example: Post-Processing

```python
import json
import subprocess

# Run Cancerbero
result = subprocess.run(
    ["cancerbero", "check", "./model.gguf", "--json", "-"],
    capture_output=True,
    text=True
)

report = json.loads(result.stdout)

# Add custom check
custom_finding = {
    "id": "custom.my-check",
    "head": "loading",
    "check": "custom_check",
    "status": "unchecked",
    "severity": "info",
    "confidence": "high",
    "summary": "Custom check for my organization",
    "evidence": {},
    "action": None,
    "references": [],
    "mandatory": False
}

report["findings"].append(custom_finding)

# Save modified report
with open("custom-report.json", "w") as f:
    json.dump(report, f, indent=2)
```

## Advisory Sources

### Primary Sources

Cancerbero uses these primary sources for advisories:

1. **GitHub Security Advisories**: https://github.com/ggml-org/llama.cpp/security/advisories
2. **NIST NVD**: https://nvd.nist.gov/
3. **oss-security**: https://seclists.org/oss-sec/
4. **Vendor advisories**: Direct from component maintainers

### Verification

All advisories are verified against primary sources before inclusion. Each advisory includes:

- Source URL
- Publication date
- Last review date
- Version boundaries from official sources

## Best Practices

### 1. Keep Cancerbero Updated

Advisories are updated with new Cancerbero releases. Update regularly:

```bash
pip install --upgrade cancerbero
```

### 2. Verify Advisory Applicability

Not all advisories apply to all configurations:

- **Component-specific**: llama.cpp advisories don't apply to llama-cpp-python
- **Version-specific**: Check if your version is actually affected
- **Configuration-specific**: Some advisories require specific artifact properties

### 3. Review Actions

Each advisory includes a recommended action. Review and follow these actions:

- **Update runtime**: Install a fixed version
- **Isolate artifact**: Don't load in production
- **Replace artifact**: Obtain from trusted source
- **Review configuration**: Check trust decisions

### 4. Document Exceptions

If you accept a risk, document it:

```yaml
# risk-acceptance.yaml
advisory: CVE-2026-27940
runtime: llama-cli build 5000
reason: Development environment only, not production
accepted_by: security-team
date: 2026-08-28
review_date: 2026-09-28
```

## Troubleshooting

### Issue: Advisory not detected

**Cause**: Runtime build unknown or advisory doesn't apply.

**Solution**:
1. Provide runtime version: `--runtime-version b8146`
2. Check advisory applicability
3. Verify artifact has required properties

### Issue: False positive

**Cause**: Advisory applies but risk is acceptable.

**Solution**:
1. Document risk acceptance
2. Consider updating runtime
3. Review advisory details

### Issue: Advisory outdated

**Cause**: Cancerbero version is old.

**Solution**: Update Cancerbero to get latest advisories.

## Future Plans

### External Bundle Updates

Future versions may support:

- Signed external bundle updates
- Community-contributed advisories
- Automatic updates from trusted sources

### Custom Rule Files

Future versions may support:

- Custom rule files in YAML/JSON
- Organization-specific advisories
- Integration with vulnerability databases

### Real-Time Updates

Future versions may support:

- Real-time advisory updates
- Integration with security feeds
- Automated vulnerability scanning

## References

- [GitHub Security Advisories](https://github.com/ggml-org/llama.cpp/security/advisories)
- [NIST NVD](https://nvd.nist.gov/)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Cancerbero Security Documentation](../security/threat-model.md)
