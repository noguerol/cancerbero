# Batch Processing Guide

Cancerbero supports efficient batch processing of multiple models. This guide covers best practices for checking large numbers of models.

## Basic Batch Processing

### Check a Directory

```bash
cancerbero check ./models/
```

Cancerbero will:
1. Scan the directory recursively
2. Find all GGUF files
3. Inspect each file
4. Show combined results

### Check Multiple Paths

```bash
cancerbero check ./model1.gguf ./model2.gguf ./model3.gguf
```

### Check with Glob Patterns

```bash
cancerbero check ./models/*.gguf
```

## Performance Optimization

### Use Summary Mode

For quick checks, use `--summary-only`:

```bash
cancerbero check ./models/ --summary-only --no-interactive
```

This shows only the verdict line, which is faster for large directories.

### Disable Unnecessary Features

```bash
# Skip banner and interactive prompts
cancerbero check ./models/ --no-banner --no-interactive

# Skip color for faster output
cancerbero check ./models/ --no-color
```

### Parallel Processing

For very large batches, consider parallel processing:

```bash
# GNU Parallel
find ./models -name "*.gguf" | parallel -j 4 cancerbero check {} --no-interactive --summary-only

# xargs
find ./models -name "*.gguf" | xargs -P 4 -I {} cancerbero check {} --no-interactive --summary-only
```

## Output Management

### JSON Reports for Each Model

```bash
# Generate individual reports
for model in ./models/*.gguf; do
    name=$(basename "$model" .gguf)
    cancerbero check "$model" --no-interactive --json "reports/${name}.json"
done
```

### Combined Report

```bash
# Check all models and generate single report
cancerbero check ./models/ --no-interactive --json all-models.json
```

### SARIF for GitHub

```bash
# Generate SARIF for all models
cancerbero check ./models/ --no-interactive --format sarif > results.sarif
```

## Filtering Results

### Check Only Specific Models

```bash
# Check only Qwen models
cancerbero check ./models/qwen*.gguf --no-interactive

# Check only large models
find ./models -name "*.gguf" -size +1G -exec cancerbero check {} --no-interactive \;
```

### Filter by Verdict

```bash
# Find models with issues
for model in ./models/*.gguf; do
    result=$(cancerbero check "$model" --summary-only --no-interactive 2>&1)
    if echo "$result" | grep -q "NOT SUITABLE"; then
        echo "ISSUE: $model"
    fi
done
```

## CI/CD Integration

### GitHub Actions Matrix

```yaml
name: Batch Model Check

on:
  push:
    paths:
      - 'models/**'

jobs:
  check:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        model:
          - models/llama-3.1-8b.gguf
          - models/qwen3.6-27b.gguf
          - models/gemma-4-31b.gguf
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      
      - name: Install Cancerbero
        run: pip install cancerbero
      
      - name: Check ${{ matrix.model }}
        run: |
          cancerbero check ${{ matrix.model }} \
            --no-interactive \
            --no-banner \
            --json report-${{ matrix.model }}.json
      
      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: report-${{ matrix.model }}
          path: report-${{ matrix.model }}.json
```

### GitLab CI Parallel

```yaml
model-check:
  stage: test
  image: python:3.12-slim
  parallel:
    matrix:
      - MODEL: [models/llama-3.1-8b.gguf, models/qwen3.6-27b.gguf, models/gemma-4-31b.gguf]
  script:
    - pip install cancerbero
    - cancerbero check $MODEL --no-interactive --json report.json
  artifacts:
    paths:
      - report.json
```

## Monitoring and Reporting

### Track Model Inventory

```bash
# List all GGUF files with sizes
find ./models -name "*.gguf" -exec ls -lh {} \; | awk '{print $5, $9}'

# Count models by architecture
for model in ./models/*.gguf; do
    arch=$(cancerbero check "$model" --summary-only --no-interactive 2>&1 | grep "Artifact" | grep -o "GGUF v[0-9]*")
    echo "$arch"
done | sort | uniq -c
```

### Generate Summary Report

```bash
#!/bin/bash

echo "Model Inventory Report"
echo "====================="
echo ""

total=0
suitable=0
not_suitable=0
undetermined=0

for model in ./models/*.gguf; do
    total=$((total + 1))
    result=$(cancerbero check "$model" --summary-only --no-interactive 2>&1)
    
    if echo "$result" | grep -q "SUITABLE"; then
        suitable=$((suitable + 1))
    elif echo "$result" | grep -q "NOT SUITABLE"; then
        not_suitable=$((not_suitable + 1))
        echo "ISSUE: $model"
    else
        undetermined=$((undetermined + 1))
    fi
done

echo ""
echo "Total models: $total"
echo "Suitable: $suitable"
echo "Not suitable: $not_suitable"
echo "Undetermined: $undetermined"
```

## Best Practices

### 1. Use Configuration Files

```yaml
# cancerbero-batch.yaml
format: json
no_color: true
no_banner: true
no_interactive: true
```

```bash
cancerbero check ./models/ --config cancerbero-batch.yaml
```

### 2. Generate Reports for Auditing

```bash
# Timestamped reports
timestamp=$(date +%Y%m%d_%H%M%S)
cancerbero check ./models/ --no-interactive --json "reports/batch-${timestamp}.json"
```

### 3. Monitor for Changes

```bash
# Check only new or modified models
find ./models -name "*.gguf" -newer last-check.txt -exec cancerbero check {} --no-interactive \;
touch last-check.txt
```

### 4. Use Exit Codes for Gating

```bash
#!/bin/bash

# Check all models, fail if any have issues
for model in ./models/*.gguf; do
    cancerbero check "$model" --no-interactive
    if [ $? -ne 0 ]; then
        echo "Failed: $model"
        exit 1
    fi
done
```

### 5. Parallel Processing with Limits

```bash
# Process 4 models at a time
find ./models -name "*.gguf" | xargs -P 4 -I {} sh -c '
    cancerbero check {} --no-interactive --summary-only
    if [ $? -ne 0 ]; then
        echo "ISSUE: {}"
    fi
'
```

## Performance Considerations

### File Size Impact

| File Size | Inspection Time | Hash Time |
|-----------|----------------|-----------|
| < 1 GB | < 1s | ~2s |
| 1-10 GB | 1-2s | 2-20s |
| 10-50 GB | 2-5s | 20-100s |
| > 50 GB | 5-10s | > 100s |

### Directory Size Impact

| Models | Inspection Time |
|--------|----------------|
| 1-10 | < 10s |
| 10-50 | 10-50s |
| 50-100 | 50-100s |
| > 100 | Consider parallel |

### Memory Usage

| Operation | Peak Memory |
|-----------|-------------|
| Single model | < 200 MB |
| Directory (10 models) | < 500 MB |
| Directory (50 models) | < 1 GB |

## Troubleshooting

### Issue: Slow batch processing

**Cause**: Large files or many files.

**Solutions**:
1. Use `--summary-only` for quick checks
2. Process in parallel
3. Skip hash calculation (don't use `--full`)

### Issue: Too many reports

**Cause**: Individual reports for each model.

**Solution**: Use single report for directory:
```bash
cancerbero check ./models/ --json all-models.json
```

### Issue: Pipeline fails on first error

**Cause**: Script exits on first non-zero exit code.

**Solution**: Continue on error:
```bash
for model in ./models/*.gguf; do
    cancerbero check "$model" --no-interactive || true
done
```

## Examples

### Complete Batch Script

```bash
#!/bin/bash

# Batch model checker
# Usage: ./batch-check.sh [models-directory]

MODELS_DIR=${1:-./models}
REPORT_DIR="./reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$REPORT_DIR"

echo "Checking models in $MODELS_DIR..."
echo ""

# Check all models
cancerbero check "$MODELS_DIR" \
    --no-interactive \
    --no-banner \
    --json "$REPORT_DIR/batch-${TIMESTAMP}.json"

EXIT_CODE=$?

echo ""
echo "Report saved to: $REPORT_DIR/batch-${TIMESTAMP}.json"
echo "Exit code: $EXIT_CODE"

exit $EXIT_CODE
```

### Inventory Script

```bash
#!/bin/bash

# Model inventory
# Usage: ./inventory.sh [models-directory]

MODELS_DIR=${1:-./models}

echo "Model Inventory"
echo "==============="
echo ""

for model in "$MODELS_DIR"/*.gguf; do
    if [ -f "$model" ]; then
        name=$(basename "$model")
        size=$(ls -lh "$model" | awk '{print $5}')
        result=$(cancerbero check "$model" --summary-only --no-interactive 2>&1)
        verdict=$(echo "$result" | grep "Cancerbero —" | awk '{print $3}')
        
        echo "$name | $size | $verdict"
    fi
done
```
