"""Shared test configuration."""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure the project root is importable for test helper modules.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
