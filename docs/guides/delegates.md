# Third-Party Tool Delegates

Cancerbero integrates with specialized third-party security tools to extend its detection capabilities. Each delegate is **optional** — Cancerbero works without them, reporting `unchecked` for delegate-specific checks.

## Available Delegates

### ModelAudit

**Developer:** Promptfoo  
**Focus:** Broad format scanning (42+ formats)  
**Install:** `pip install modelaudit`  
**Docs:** https://github.com/promptfoo/modelaudit

ModelAudit scans model files in 42+ formats for security issues, including:
- Pickle deserialization risks
- Malicious code patterns
- Structural vulnerabilities
- CVE detection

**Usage:**
```bash
cancerbero check ./model.gguf --modelaudit
```

### PickleScan

**Developer:** Hugging Face  
**Focus:** Pickle bytecode analysis  
**Install:** `pip install picklescan`  
**Docs:** https://github.com/mmaitre314/picklescan

PickleScan analyzes pickle bytecode for malicious imports.

**Note:** Has known bypass CVEs (CVE-2025-1716, JFrog zero-days). Use fickling for more rigorous analysis.

**Usage:**
```bash
cancerbero check ./model.gguf --picklescan
```

### Fickling

**Developer:** Trail of Bits  
**Focus:** Allowlist-based pickle scanning  
**Install:** `pip install fickling`  
**Docs:** https://github.com/trailofbits/fickling  
**Blog:** https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/

Fickling uses an allowlist approach rather than blocklists, making it more rigorous than picklescan.

**Usage:**
```bash
cancerbero check ./model.gguf --fickling
```

### ModelScan

**Developer:** Protect AI  
**Focus:** Multi-framework model scanning  
**Install:** `pip install modelscan`  
**Docs:** https://github.com/protectai/modelscan

ModelScan scans PyTorch, TensorFlow SavedModel, and Keras H5 models for security issues.

**Usage:**
```bash
cancerbero check ./model.gguf --modelscan
```

## Using Delegates

### Single Delegate

```bash
# Run ModelAudit only
cancerbero check ./model.gguf --modelaudit
```

### Multiple Delegates

```bash
# Run multiple delegates
cancerbero check ./model.gguf --modelaudit --fickling
```

### All Available Delegates

```bash
# Run all installed delegates
cancerbero check ./model.gguf --all-delegates
```

### In CI/CD

```yaml
# GitHub Actions
- name: Check model with all delegates
  run: |
    pip install modelaudit fickling picklescan modelscan
    cancerbero check ./models/ --all-delegates --no-interactive
```

## Delegate Behavior

### When Tool Is Installed

If the delegate tool is installed, Cancerbero:
1. Runs the tool on the target file
2. Parses the output
3. Converts findings to Cancerbero format
4. Includes findings in the report

### When Tool Is Not Installed

If the delegate tool is not installed, Cancerbero:
1. Reports `unchecked` for that delegate
2. Includes installation instructions in the finding
3. Does not block the verdict

### Telemetry

All delegates disable telemetry when running external tools:
- `PROMPTFOO_DISABLE_TELEMETRY=1`
- `NO_ANALYTICS=1`
- `DO_NOT_TRACK=1`

## Delegate Findings

Delegate findings are included in the report with:
- **id:** `cbr.delegate.<tool>.<finding_id>`
- **check:** `delegate_<tool>`
- **status:** Based on severity (HIGH/CRITICAL → SUSPICIOUS, else UNCHECKED)
- **evidence:** Tool name, version, finding details, duration

## Recommended Installation

### Minimal (No Delegates)

```bash
pip install cancerbero
```

### Standard (ModelAudit)

```bash
pip install cancerbero modelaudit
```

### Comprehensive (All Delegates)

```bash
pip install cancerbero modelaudit fickling picklescan modelscan
```

### In pyproject.toml

```toml
[project.optional-dependencies]
delegates = [
    "modelaudit>=0.1.0",
    "fickling>=0.1.0",
    "picklescan>=0.1.0",
    "modelscan>=0.1.0",
]
```

## Comparison

| Tool | Approach | Strengths | Weaknesses |
|------|----------|-----------|------------|
| **ModelAudit** | Blocklist | 42+ formats, JSON/SARIF | May miss novel attacks |
| **picklescan** | Blocklist | Widely used | Has bypass CVEs |
| **fickling** | Allowlist | More rigorous than blocklist | Limited format support |
| **ModelScan** | Blocklist | Multi-framework | May miss novel attacks |

## References

- [ModelAudit Documentation](https://github.com/promptfoo/modelaudit)
- [PickleScan Documentation](https://github.com/mmaitre314/picklescan)
- [Fickling Blog](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [ModelScan Documentation](https://github.com/protectai/modelscan)
