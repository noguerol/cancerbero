"""Optional adapters for explicitly requested third-party static scanners.

Adapters normalize tool output and exit codes. They run with an environment
allowlist, bounded captured output, a timeout, and platform-supported resource
limits. They are not a network or filesystem sandbox.
"""

from __future__ import annotations

from cancerbero.delegates.base import DelegateResult, DelegateRunner
from cancerbero.delegates.fickling import FicklingDelegate
from cancerbero.delegates.modelaudit import ModelAuditDelegate
from cancerbero.delegates.modelscan import ModelScanDelegate
from cancerbero.delegates.picklescan import PickleScanDelegate

__all__ = [
    "DelegateResult",
    "DelegateRunner",
    "FicklingDelegate",
    "ModelAuditDelegate",
    "ModelScanDelegate",
    "PickleScanDelegate",
]
