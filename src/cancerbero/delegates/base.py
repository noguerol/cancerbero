"""Resource-bounded execution support for optional third-party scanners."""

from __future__ import annotations

import contextlib
import os
import shutil
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:  # ``resource`` is unavailable on Windows.
    import resource
except ImportError:  # pragma: no cover - exercised by Windows CI
    resource = None  # type: ignore[assignment]


@dataclass(frozen=True, slots=True)
class DelegateResult:
    """Normalized result from one delegate execution."""

    tool: str
    version: str | None
    available: bool
    success: bool
    findings: list[dict[str, Any]]
    raw_output: str | None = None
    error: str | None = None
    duration_ms: int = 0
    telemetry_disabled: bool = False


@dataclass(frozen=True, slots=True)
class DelegateLimits:
    """Wall-clock, output, and best-effort memory limits for a delegate."""

    timeout_seconds: int = 60
    max_output_bytes: int = 1024 * 1024
    max_memory_mb: int = 1024

    def __post_init__(self) -> None:
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.max_output_bytes <= 0:
            raise ValueError("max_output_bytes must be positive")
        if self.max_memory_mb < 0:
            raise ValueError("max_memory_mb must not be negative")


DEFAULT_LIMITS = DelegateLimits()
_OUTPUT_TRUNCATED = b"\n[output truncated by Cancerbero]\n"
_READ_CHUNK_BYTES = 64 * 1024

# Deliberately excludes credential-bearing variables such as *_TOKEN, *_KEY,
# AWS_*, cloud credentials, proxy configuration, and repository credentials.
_ENV_ALLOWLIST = frozenset(
    {
        "COMSPEC",
        "HOME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "WINDIR",
    }
)


def _create_delegate_env(overrides: dict[str, str] | None = None) -> dict[str, str]:
    """Return a minimal environment with telemetry opt-outs enforced."""

    environment = {
        key: value for key in _ENV_ALLOWLIST if (value := os.environ.get(key)) is not None
    }
    environment.update(
        {
            "DO_NOT_TRACK": "1",
            "HF_HUB_DISABLE_TELEMETRY": "1",
            "NO_ANALYTICS": "1",
            "PROMPTFOO_DISABLE_TELEMETRY": "1",
        }
    )
    if overrides:
        # Delegate adapters may add opt-out controls, but may not reintroduce
        # arbitrary parent-process credentials.
        allowed_overrides = _ENV_ALLOWLIST | {
            "DO_NOT_TRACK",
            "HF_HUB_DISABLE_TELEMETRY",
            "NO_ANALYTICS",
            "PROMPTFOO_DISABLE_TELEMETRY",
        }
        environment.update(
            {key: value for key, value in overrides.items() if key in allowed_overrides}
        )
    return environment


def _set_posix_resource_limits(limits: DelegateLimits) -> None:
    """Apply child-only POSIX limits before executing a delegate.

    No-op on non-POSIX platforms, where ``resource`` is unavailable.
    """

    if os.name != "posix" or resource is None:  # pragma: no cover - Windows
        return
    if limits.max_memory_mb:
        maximum_bytes = limits.max_memory_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (maximum_bytes, maximum_bytes))
    cpu_seconds = max(1, limits.timeout_seconds)
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 1))
    # Delegates do not need to create large files through inherited descriptors.
    resource.setrlimit(
        resource.RLIMIT_FSIZE,
        (limits.max_output_bytes, limits.max_output_bytes),
    )


def _capture_bounded(stream: Any, limit: int, destination: bytearray) -> None:
    """Drain a pipe completely while retaining at most *limit* bytes."""

    truncated = False
    try:
        while True:
            chunk = stream.read(_READ_CHUNK_BYTES)
            if not chunk:
                break
            remaining = limit - len(destination)
            if remaining > 0:
                destination.extend(chunk[:remaining])
            if len(chunk) > remaining:
                truncated = True
    finally:
        stream.close()
    if truncated and len(_OUTPUT_TRUNCATED) <= limit:
        del destination[max(0, limit - len(_OUTPUT_TRUNCATED)) :]
        destination.extend(_OUTPUT_TRUNCATED)


class DelegateRunner:
    """Base class for optional, explicitly requested third-party scanners.

    Delegates run without a shell, inherit only an environment allowlist, have
    bounded captured output and a wall-clock timeout, and receive POSIX memory,
    CPU, and file-size limits on POSIX platforms. On Windows the child runs in a
    new process group instead. This is process hardening, not a network or
    filesystem sandbox.
    """

    name: str = "unknown"
    command: str = "unknown"

    def _command_path(self) -> str | None:
        """Resolve the executable once through the current allowlisted PATH."""

        return shutil.which(self.command)

    def is_available(self) -> bool:
        """Return whether the delegate executable is available."""

        return self._command_path() is not None

    def get_version(self) -> str | None:
        """Get the delegate version, or ``None`` when unavailable/unsupported."""

        raise NotImplementedError

    def run(
        self,
        target: Path,
        *,
        limits: DelegateLimits = DEFAULT_LIMITS,
        extra_args: list[str] | None = None,
    ) -> DelegateResult:
        """Run the delegate against *target* and normalize its result."""

        raise NotImplementedError

    def _execute(
        self,
        args: list[str],
        *,
        limits: DelegateLimits = DEFAULT_LIMITS,
        env: dict[str, str] | None = None,
    ) -> tuple[int, str, str, int]:
        """Execute without a shell and capture output with hard memory bounds."""

        if not args:
            raise ValueError("delegate command must not be empty")
        command_path = self._command_path() if args[0] == self.command else shutil.which(args[0])
        if command_path is None:
            return -1, "", f"Command not found: {args[0]}", 0
        command = [command_path, *args[1:]]
        process_environment = _create_delegate_env(env)
        started = time.monotonic()

        popen_options: dict[str, Any] = {
            "env": process_environment,
            "shell": False,
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
        }
        if os.name == "posix":
            popen_options["start_new_session"] = True
            popen_options["preexec_fn"] = lambda: _set_posix_resource_limits(limits)
        elif os.name == "nt":  # pragma: no cover - Windows CI
            popen_options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

        try:
            process = subprocess.Popen(command, **popen_options)
        except OSError as error:
            duration_ms = int((time.monotonic() - started) * 1000)
            return -1, "", str(error), duration_ms

        assert process.stdout is not None
        assert process.stderr is not None
        stdout_buffer = bytearray()
        stderr_buffer = bytearray()
        readers = [
            threading.Thread(
                target=_capture_bounded,
                args=(process.stdout, limits.max_output_bytes, stdout_buffer),
                daemon=True,
            ),
            threading.Thread(
                target=_capture_bounded,
                args=(process.stderr, limits.max_output_bytes, stderr_buffer),
                daemon=True,
            ),
        ]
        for reader in readers:
            reader.start()

        timed_out = False
        try:
            process.wait(timeout=limits.timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            if os.name == "posix":
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
            else:  # pragma: no cover - Windows CI
                process.kill()
            process.wait()
        finally:
            for reader in readers:
                reader.join(timeout=5)

        duration_ms = int((time.monotonic() - started) * 1000)
        stdout = stdout_buffer.decode("utf-8", errors="replace")
        stderr = stderr_buffer.decode("utf-8", errors="replace")
        if timed_out:
            timeout_error = f"Timeout after {limits.timeout_seconds}s"
            stderr = f"{stderr}\n{timeout_error}".strip()
            return -1, stdout, stderr, duration_ms
        return process.returncode, stdout, stderr, duration_ms

    def _not_available_result(self) -> DelegateResult:
        """Return a normalized unavailable result."""

        return DelegateResult(
            tool=self.name,
            version=None,
            available=False,
            success=False,
            findings=[],
            error=f"{self.name} is not installed or not available on PATH",
            telemetry_disabled=True,
        )
