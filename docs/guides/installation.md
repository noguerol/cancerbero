# Installation Guide

## System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| Python | 3.10 | 3.12+ |
| OS | Linux, macOS, Windows | Linux |
| Disk Space | 50 MB | 100 MB |
| RAM | 256 MB | 512 MB |

## Installation Methods

### From Source (Recommended)

```bash
# Clone the repository
git clone https://github.com/cancerbero-security/cancerbero.git
cd cancerbero

# Install in development mode
pip install -e .

# Or install with development dependencies
pip install -e ".[dev]"
```

### Using pip (when published)

```bash
pip install cancerbero
```

### Using uv (fast installer)

```bash
uv pip install cancerbero
```

## Dependencies

Cancerbero has minimal dependencies by design:

| Dependency | Purpose | Required |
|------------|---------|----------|
| Jinja2 | Template AST parsing | Yes |
| Python stdlib | Everything else | Yes |

**No ML frameworks are required.** Cancerbero does not import PyTorch, Transformers, TensorFlow, JAX, or any other ML library.

## Verification

After installation, verify Cancerbero is working:

```bash
# Check version
cancerbero --version

# Run a simple check
cancerbero check --help
```

Expected output:
```
cancerbero 0.1.0
```

## Platform-Specific Notes

### Linux

Cancerbero works natively on Linux. For best performance with large models, ensure your filesystem supports efficient sequential reads.

### macOS

Cancerbero works on macOS. The `--no-color` flag may be useful if your terminal doesn't support ANSI colors.

### Windows

Cancerbero works on Windows with Python 3.10+. Use PowerShell or Windows Terminal for best experience.

## Development Installation

For contributing to Cancerbero:

```bash
# Clone and install with dev dependencies
git clone https://github.com/cancerbero-security/cancerbero.git
cd cancerbero
pip install -e ".[dev]"

# Run tests
pytest

# Run linter
ruff check src tests
```

## Updating

To update Cancerbero:

```bash
# From source
cd cancerbero
git pull
pip install -e .

# From pip
pip install --upgrade cancerbero
```

## Uninstalling

```bash
pip uninstall cancerbero
```

## Next Steps

- [Quick Start Guide](quickstart.md) — Run your first inspection
- [Configuration](configuration.md) — Customize Cancerbero's behavior
- [How It Works](how-it-works.md) — Understand the inspection pipeline
