"""Terminal UI components: banner, progress, spinners, and colors."""

from __future__ import annotations

import sys
import threading
import time
from contextlib import contextmanager
from typing import TextIO

from cancerbero import __version__


# ANSI color codes
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    # Foreground
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    # Bright
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"

    # Background
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"


def supports_color(stream: TextIO = sys.stderr) -> bool:
    """Check if the stream supports ANSI colors."""
    if not hasattr(stream, "isatty"):
        return False
    return stream.isatty()


def colored(text: str, color: str, *, force: bool = False) -> str:
    """Apply color to text if the terminal supports it."""
    if not force and not supports_color():
        return text
    return f"{color}{text}{Colors.RESET}"


def bold(text: str) -> str:
    """Make text bold."""
    return colored(text, Colors.BOLD)


def dim(text: str) -> str:
    """Make text dimmed."""
    return colored(text, Colors.DIM)


# ASCII Art Banner
BANNER = r"""
  ██████╗ █████╗ ███╗   ██╗ ██████╗███████╗██████╗ ██████╗ ███████╗██████╗  ██████╗
  ██╔════╝██╔══██╗████╗  ██║██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔═══██╗
  ██║     ███████║██╔██╗ ██║██║     █████╗  ██████╔╝██████╔╝█████╗  ██████╔╝██║   ██║
  ██║     ██╔══██║██║╚██╗██║██║     ██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██╔══██╗██║   ██║
  ╚██████╗██║  ██║██║ ╚████║╚██████╗███████╗██║  ██║██████╔╝███████╗██║  ██║╚██████╔╝
  ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝
"""


def render_banner(*, no_color: bool = False) -> str:
    """Render the Cancerbero banner with version."""
    lines = []

    if no_color or not supports_color():
        lines.append(BANNER)
        lines.append(f"  v{__version__} — Local GGUF & llama.cpp inspector")
        lines.append("")
    else:
        # Color the banner
        banner_lines = BANNER.strip().split("\n")
        for line in banner_lines:
            lines.append(colored(line, Colors.BRIGHT_CYAN))
        lines.append("")
        lines.append(
            f"  {colored('v' + __version__, Colors.BRIGHT_YELLOW)}"
            f" {colored('—', Colors.DIM)}"
            f" {colored('Local GGUF & llama.cpp inspector', Colors.WHITE)}"
        )
        lines.append("")

    return "\n".join(lines)


# Spinner frames
SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
SPINNER_DONE = "✓"
SPINNER_FAIL = "✗"
SPINNER_WARN = "⚠"


class Spinner:
    """Animated spinner for long-running operations."""

    def __init__(
        self,
        message: str,
        stream: TextIO = sys.stderr,
        *,
        no_color: bool = False,
    ) -> None:
        self.message = message
        self.stream = stream
        self.no_color = no_color
        self._running = False
        self._thread: threading.Thread | None = None
        self._frame = 0
        self._done = False

    def _animate(self) -> None:
        while self._running:
            frame = SPINNER_FRAMES[self._frame % len(SPINNER_FRAMES)]
            if self.no_color:
                self.stream.write(f"\r  {frame} {self.message}...")
            else:
                self.stream.write(f"\r  {colored(frame, Colors.BRIGHT_CYAN)} {self.message}...")
            self.stream.flush()
            self._frame += 1
            time.sleep(0.08)

    def start(self) -> None:
        """Start the spinner animation."""
        self._running = True
        self._thread = threading.Thread(target=self._animate, daemon=True)
        self._thread.start()

    def stop(self, *, success: bool = True, message: str | None = None) -> None:
        """Stop the spinner and show result."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=0.2)

        # Clear the line
        self.stream.write("\r" + " " * 80 + "\r")

        icon = SPINNER_DONE if success else SPINNER_FAIL
        color = Colors.BRIGHT_GREEN if success else Colors.BRIGHT_RED
        msg = message or self.message

        if self.no_color:
            self.stream.write(f"  {icon} {msg}\n")
        else:
            self.stream.write(f"  {colored(icon, color)} {msg}\n")
        self.stream.flush()

    def __enter__(self) -> Spinner:
        self.start()
        return self

    def __exit__(self, *args: object) -> None:
        self.stop(success=True)


@contextmanager
def spinner(
    message: str,
    stream: TextIO = sys.stderr,
    *,
    no_color: bool = False,
):
    """Context manager for a spinner."""
    s = Spinner(message, stream, no_color=no_color)
    s.start()
    try:
        yield s
    except Exception:
        s.stop(success=False, message=f"{message} — FAILED")
        raise
    else:
        s.stop(success=True)


class ProgressBar:
    """Simple progress bar for batch operations."""

    def __init__(
        self,
        total: int,
        prefix: str = "",
        stream: TextIO = sys.stderr,
        *,
        no_color: bool = False,
    ) -> None:
        self.total = total
        self.prefix = prefix
        self.stream = stream
        self.no_color = no_color
        self.current = 0
        self._lock = threading.Lock()

    def update(self, n: int = 1, message: str = "") -> None:
        """Update progress by n steps."""
        with self._lock:
            self.current = min(self.current + n, self.total)
            self._render(message)

    def _render(self, message: str = "") -> None:
        if self.total == 0:
            return

        pct = self.current / self.total
        width = 30
        filled = int(width * pct)
        bar = "█" * filled + "░" * (width - filled)

        if self.no_color:
            line = f"\r  {self.prefix} [{bar}] {self.current}/{self.total}"
        else:
            bar_colored = colored("█" * filled, Colors.BRIGHT_GREEN) + colored(
                "░" * (width - filled), Colors.DIM
            )
            line = f"\r  {self.prefix} [{bar_colored}] {colored(str(self.current), Colors.BRIGHT_YELLOW)}/{self.total}"

        if message:
            line += f" {dim(message)}"

        self.stream.write(line)
        self.stream.flush()

    def finish(self, message: str = "Done") -> None:
        """Complete the progress bar."""
        self.current = self.total
        self._render(message)
        self.stream.write("\n")
        self.stream.flush()


def step(message: str, *, no_color: bool = False, stream: TextIO = sys.stderr) -> None:
    """Print a step indicator."""
    if no_color:
        stream.write(f"  ▸ {message}\n")
    else:
        stream.write(f"  {colored('▸', Colors.BRIGHT_BLUE)} {message}\n")
    stream.flush()


def info(message: str, *, no_color: bool = False, stream: TextIO = sys.stderr) -> None:
    """Print an info message."""
    if no_color:
        stream.write(f"  ℹ {message}\n")
    else:
        stream.write(f"  {colored('ℹ', Colors.BRIGHT_CYAN)} {message}\n")
    stream.flush()


def success(message: str, *, no_color: bool = False, stream: TextIO = sys.stderr) -> None:
    """Print a success message."""
    if no_color:
        stream.write(f"  ✓ {message}\n")
    else:
        stream.write(f"  {colored('✓', Colors.BRIGHT_GREEN)} {message}\n")
    stream.flush()


def warning(message: str, *, no_color: bool = False, stream: TextIO = sys.stderr) -> None:
    """Print a warning message."""
    if no_color:
        stream.write(f"  ⚠ {message}\n")
    else:
        stream.write(f"  {colored('⚠', Colors.BRIGHT_YELLOW)} {message}\n")
    stream.flush()


def error(message: str, *, no_color: bool = False, stream: TextIO = sys.stderr) -> None:
    """Print an error message."""
    if no_color:
        stream.write(f"  ✗ {message}\n")
    else:
        stream.write(f"  {colored('✗', Colors.BRIGHT_RED)} {message}\n")
    stream.flush()


def prompt_choice(
    message: str,
    options: list[str],
    *,
    no_color: bool = False,
    stream: TextIO = sys.stderr,
    input_stream: TextIO = sys.stdin,
) -> str | None:
    """Prompt user to choose from options. Returns choice or None if cancelled."""
    stream.write("\n")
    if no_color:
        stream.write(f"  {message}\n")
    else:
        stream.write(f"  {colored('?', Colors.BRIGHT_CYAN)} {bold(message)}\n")

    for i, option in enumerate(options, 1):
        if no_color:
            stream.write(f"    {i}. {option}\n")
        else:
            stream.write(f"    {colored(str(i), Colors.BRIGHT_YELLOW)}. {option}\n")

    if no_color:
        stream.write("    0. Skip\n")
    else:
        stream.write(f"    {colored('0', Colors.DIM)}. Skip\n")

    stream.write("\n")
    stream.flush()

    try:
        choice = input_stream.readline().strip()
        if not choice or choice == "0":
            return None
        idx = int(choice) - 1
        if 0 <= idx < len(options):
            return options[idx]
        return None
    except (ValueError, EOFError):
        return None


__all__ = [
    "Colors",
    "colored",
    "bold",
    "dim",
    "supports_color",
    "BANNER",
    "render_banner",
    "Spinner",
    "spinner",
    "ProgressBar",
    "step",
    "info",
    "success",
    "warning",
    "error",
    "prompt_choice",
]
