# CI/CD Integration

This guide explains how to integrate Cancerbero into your CI/CD pipeline.

## GitHub Actions

### Basic Workflow

```yaml
name: Model Security Check
on:
  push:
    paths:
      - 'models/**'
  pull_request:
    paths:
      - 'models/**'

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install Cancerbero
        run: pip install cancerbero
      
      - name: Check models
        run: |
          cancerbero check ./models/ \
            --no-interactive \
            --no-banner \
            --no-color \
            --json report.json
      
      - name: Upload report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: cancerbero-report
          path: report.json
```

### With Runtime Version

```yaml
      - name: Check models with runtime
        run: |
          cancerbero check ./models/ \
            --runtime ./llama-cli \
            --runtime-version b8146 \
            --no-interactive \
            --no-banner \
            --no-color \
            --json report.json
```

### Gate Deployment

```yaml
      - name: Gate deployment
        run: |
          cancerbero check ./models/ \
            --no-interactive \
            --no-banner \
            --no-color
          # Exit code 0 = SUITABLE, 1 = NOT SUITABLE, 2 = UNDETERMINED
```

## GitLab CI

### Basic Pipeline

```yaml
model-security:
  stage: test
  image: python:3.11
  script:
    - pip install cancerbero
    - cancerbero check ./models/ --no-interactive --json report.json
  artifacts:
    when: always
    paths:
      - report.json
  rules:
    - changes:
        - models/**
```

### With Runtime Version

```yaml
model-security:
  stage: test
  image: python:3.11
  script:
    - pip install cancerbero
    - cancerbero check ./models/ \
        --runtime ./llama-cli \
        --runtime-version b8146 \
        --no-interactive \
        --json report.json
  artifacts:
    when: always
    paths:
      - report.json
```

## Jenkins

### Pipeline

```groovy
pipeline {
    agent any
    stages {
        stage('Model Security') {
            steps {
                sh 'pip install cancerbero'
                sh 'cancerbero check ./models/ --no-interactive --json report.json'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'report.json', allowEmptyArchive: true
                }
            }
        }
    }
}
```

## Exit Codes

Use exit codes to control pipeline flow:

| Code | Meaning | Pipeline Action |
|------|---------|-----------------|
| `0` | SUITABLE | Continue |
| `1` | NOT SUITABLE | Block deployment |
| `2` | UNDETERMINED | Review required |
| `3` | ERROR | Fail pipeline |

### Example: Gate Deployment

```bash
# Exit 1 if not suitable
cancerbero check ./models/ --no-interactive || exit 1
```

### Example: Allow Undetermined

```bash
# Exit 0 for suitable, 1 for not suitable, 0 for undetermined
cancerbero check ./models/ --no-interactive
EXIT_CODE=$?
if [ $EXIT_CODE -eq 1 ]; then
  exit 1
fi
```

## Output Formats

### JSON (Recommended for CI/CD)

```bash
cancerbero check ./models/ --json report.json
```

- Deterministic output
- Machine-readable
- Includes all findings and evidence

### SARIF (GitHub Code Scanning)

```bash
cancerbero check ./models/ --format sarif > results.sarif
```

- Compatible with GitHub Code Scanning
- Maps findings to SARIF result levels
- Shows in GitHub Security tab

### Markdown (Documentation)

```bash
cancerbero check ./models/ --format markdown > report.md
```

- Human-readable
- Suitable for PRs and issues
- Includes tables and badges

## Configuration

### Environment Variables

| Variable | Description |
|----------|-------------|
| `CANCERBERO_CONFIG` | Path to configuration file |

### Configuration File

Create `cancerbero.yaml` in your project root:

```yaml
runtime: /path/to/llama-cli
runtime_version: b8146
format: json
verbose: false
```

## Best Practices

### 1. Always Provide Runtime Version

```bash
# Good: Provides runtime for advisory join
cancerbero check ./models/ --runtime ./llama-cli --runtime-version b8146

# Bad: No runtime, verdict will be UNDETERMINED
cancerbero check ./models/
```

### 2. Use JSON for Automation

```bash
# Good: Machine-readable output
cancerbero check ./models/ --json report.json

# Bad: Human-readable output
cancerbero check ./models/
```

### 3. Gate on Exit Code

```bash
# Good: Exit 1 if not suitable
cancerbero check ./models/ --no-interactive || exit 1

# Bad: Always exit 0
cancerbero check ./models/ --no-interactive
```

### 4. Upload Reports as Artifacts

```yaml
# GitHub Actions
- name: Upload report
  uses: actions/upload-artifact@v4
  if: always()
  with:
    name: cancerbero-report
    path: report.json
```

### 5. Review UNDETERMINED Results

```bash
# Check exit code
cancerbero check ./models/ --no-interactive
EXIT_CODE=$?
if [ $EXIT_CODE -eq 2 ]; then
  echo "Review required: some checks could not be completed"
  # Optionally fail pipeline
  # exit 1
fi
```

## Examples

### Complete GitHub Actions Workflow

See [examples/github-actions.yml](../examples/github-actions.yml) for a complete workflow.

### Complete GitLab CI Configuration

See [examples/gitlab-ci.yml](../examples/gitlab-ci.yml) for a complete configuration.

## Troubleshooting

### Common Issues

1. **Exit code 2 (UNDETERMINED)**
   - Missing runtime version
   - Missing core checks
   - Solution: Provide `--runtime` and `--runtime-version`

2. **Exit code 3 (ERROR)**
   - Invalid input
   - Operational failure
   - Solution: Check input files and permissions

3. **No findings in report**
   - Model not found
   - Wrong path
   - Solution: Check target path

### Getting Help

- [Troubleshooting Guide](troubleshooting.md)
- [CLI Reference](../reference/cli.md)
- [Exit Codes](../reference/exit-codes.md)
