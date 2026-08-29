"""Cancerbero command-line interface."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from cancerbero import __version__


class CancerberoArgumentParser(argparse.ArgumentParser):
    """Use the documented operational-error exit code for invalid input."""

    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(3, f"{self.prog}: error: {message}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = CancerberoArgumentParser(
        prog="cancerbero",
        description=(
            "Inspect GGUF artifacts and llama.cpp runtimes before loading a model. "
            "Results apply only to checks performed and are not a safety certification."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--config",
        type=Path,
        metavar="PATH",
        help="path to cancerbero.yaml configuration file",
    )
    # ``--no-color``, ``--no-banner``, ``--no-interactive`` are accepted
    # BEFORE the subcommand only. The subparser registers them as well
    # so ``cancerbero check --no-color x.gguf`` continues to work.
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable terminal colors and animations",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="skip the ASCII art banner",
    )
    parser.add_argument(
        "--no-interactive",
        action="store_true",
        help="disable interactive prompts (for CI/CD)",
    )
    subparsers = parser.add_subparsers(
        dest="command", required=True, parser_class=CancerberoArgumentParser
    )

    check = subparsers.add_parser(
        "check",
        help="inspect local targets without loading a model",
        description="Inspect local GGUF and llama.cpp targets without loading the model.",
    )
    check.add_argument("targets", metavar="TARGET", nargs="+", type=Path)
    # Output flags (also defined at the top level so they work in any
    # position; see M5). Duplicating them here lets the subparser accept
    # ``check --no-interactive x.gguf`` directly.
    check.add_argument("--no-color", action="store_true", help=argparse.SUPPRESS)
    check.add_argument("--no-banner", action="store_true", help=argparse.SUPPRESS)
    check.add_argument("--no-interactive", action="store_true", help=argparse.SUPPRESS)
    check.add_argument("--runtime", type=Path, help="explicit llama.cpp executable or directory")
    check.add_argument(
        "--runtime-version",
        metavar="VERSION_OR_BUILD",
        help="trusted runtime version/build override (for example b8146)",
    )
    check.add_argument(
        "--full",
        action="store_true",
        help="stream each artifact to calculate a complete SHA-256",
    )
    check.add_argument(
        "--expected-sha256",
        metavar="HEX",
        help="trusted expected SHA-256 (implies a complete hash; one artifact only)",
    )
    check.add_argument(
        "--allow-runtime-exec",
        action="store_true",
        help="explicitly run the selected runtime with --version in a constrained subprocess",
    )
    check.add_argument(
        "--format",
        choices=["terminal", "json", "markdown", "md", "sarif"],
        default="terminal",
        help="output format (default: terminal)",
    )
    check.add_argument("--json", metavar="PATH|-", dest="json_path", help="write canonical JSON")
    check.add_argument(
        "--include-observations",
        action="store_true",
        help="include non-deterministic timings in JSON",
    )
    check.add_argument("--verbose", action="store_true", help="show technical evidence")
    check.add_argument(
        "--explain",
        metavar="FINDING_ID",
        help="show detailed explanation for a specific finding",
    )
    check.add_argument(
        "--summary-only",
        action="store_true",
        help="show only the verdict summary (useful for batch checks)",
    )

    # Third-party delegate flags
    delegates = check.add_argument_group(
        "delegates",
        description="Optional third-party tool integrations. Each tool is optional; "
        "if not installed, the check reports 'unchecked' for that tool.",
    )
    delegates.add_argument(
        "--modelaudit",
        action="store_true",
        help="run ModelAudit for broad format scanning (42+ formats)",
    )
    delegates.add_argument(
        "--picklescan",
        action="store_true",
        help="run PickleScan for pickle bytecode analysis",
    )
    delegates.add_argument(
        "--fickling",
        action="store_true",
        help="run Fickling for allowlist-based pickle scanning",
    )
    delegates.add_argument(
        "--modelscan",
        action="store_true",
        help="run ModelScan for multi-framework model scanning",
    )
    delegates.add_argument(
        "--all-delegates",
        action="store_true",
        help="run all available delegates",
    )
    return parser


def _render_explain(report: object, finding_id: str) -> str:
    """Render detailed explanation for a specific finding."""
    findings = getattr(report, "findings", [])
    finding = None
    for f in findings:
        if f.id == finding_id:
            finding = f
            break

    if finding is None:
        return f"Finding '{finding_id}' not found in this report.\n"

    lines = [
        f"━━━ Finding: {finding.id} ━━━",
        "",
        f"Status:   {finding.status.value}",
        f"Severity: {finding.severity.value}",
        f"Confidence: {finding.confidence.value}",
        f"Head:     {finding.head}",
        f"Check:    {finding.check}",
        "",
        "Summary:",
        f"  {finding.summary}",
        "",
    ]

    if finding.action:
        lines.extend(
            [
                "Recommended Action:",
                f"  {finding.action}",
                "",
            ]
        )

    if finding.evidence:
        lines.extend(
            [
                "Evidence:",
            ]
        )
        for key, value in sorted(finding.evidence.items()):
            lines.append(f"  {key}: {value}")
        lines.append("")

    if finding.references:
        lines.extend(
            [
                "References:",
            ]
        )
        for ref in finding.references:
            lines.append(f"  - {ref}")
        lines.append("")

    return "\n".join(lines)


def parse_known_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse argv and OR top-level ``--no-*`` flags into the result.

    ``cancerbero --no-interactive check x.gguf`` and
    ``cancerbero check --no-interactive x.gguf`` must be equivalent
    (M5). argparse cannot express that directly because the subparser
    action overwrites the namespace, so we lift the flag values out of
    the raw argv before delegating to the parser.
    """
    parser = build_parser()
    raw = list(sys.argv[1:] if argv is None else argv)
    pre = {"no_color": False, "no_banner": False, "no_interactive": False}
    for token in raw:
        if token == "--no-color":
            pre["no_color"] = True
        elif token == "--no-banner":
            pre["no_banner"] = True
        elif token == "--no-interactive":
            pre["no_interactive"] = True
    args = parser.parse_args(raw)
    for flag, seen in pre.items():
        if seen:
            setattr(args, flag, True)
    return args


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parse_known_args(argv)
    if args.command != "check":
        parser.error(f"unsupported command: {args.command}")

    if args.expected_sha256 and len(args.targets) != 1:
        parser.error("--expected-sha256 requires exactly one target")
    if args.runtime_version and not args.runtime:
        parser.error("--runtime-version requires --runtime")
    if args.allow_runtime_exec and not args.runtime:
        parser.error("--allow-runtime-exec requires an explicit --runtime")

    try:
        from cancerbero.audit import CheckOptions, run_check
        from cancerbero.config_file import load_config, merge_config
        from cancerbero.report import (
            canonical_json,
            render_markdown,
            render_sarif,
            render_terminal,
            write_json_report,
        )
        from cancerbero.ui import (
            error,
            info,
            prompt_choice,
            render_banner,
            step,
            success,
            warning,
        )

        no_color = getattr(args, "no_color", False)
        no_banner = getattr(args, "no_banner", False)
        no_interactive = getattr(args, "no_interactive", False)

        # Show banner only when explicitly requested AND stderr is a TTY.
        # Writing the ASCII banner to a non-TTY stderr corrupts CI logs,
        # SARIF output, and any other consumer that pipes stderr (M5).
        if not no_banner and not no_color and sys.stderr.isatty():
            sys.stderr.write(render_banner(no_color=no_color))
            sys.stderr.flush()

        # Load config file and merge with CLI args
        config = load_config(getattr(args, "config", None))
        config = merge_config(
            config,
            runtime=args.runtime,
            runtime_version=args.runtime_version,
            allow_runtime_exec=args.allow_runtime_exec,
            full_hash=args.full,
            expected_sha256=args.expected_sha256,
            format=getattr(args, "format", None),
            json_path=getattr(args, "json_path", None),
            include_observations=getattr(args, "include_observations", None),
            verbose=getattr(args, "verbose", None),
            no_color=no_color,
            explain=getattr(args, "explain", None),
            summary_only=getattr(args, "summary_only", None),
        )

        # Show what we're going to do
        step(f"Checking {len(args.targets)} target(s)...", no_color=no_color)

        options = CheckOptions(
            targets=tuple(args.targets),
            runtime=config.runtime,
            runtime_version=config.runtime_version,
            full_hash=config.full_hash or bool(config.expected_sha256),
            expected_sha256=config.expected_sha256,
            allow_runtime_exec=config.allow_runtime_exec,
            # Delegate flags
            use_modelaudit=getattr(args, "modelaudit", False),
            use_picklescan=getattr(args, "picklescan", False),
            use_fickling=getattr(args, "fickling", False),
            use_modelscan=getattr(args, "modelscan", False),
            use_all_delegates=getattr(args, "all_delegates", False),
        )

        # Create progress callback
        from cancerbero.audit import ProgressCallback

        class CLIProgress(ProgressCallback):
            def on_bundle_loaded(self, version: str) -> None:
                success(f"Knowledge bundle {version} loaded", no_color=no_color)

            def on_discovery_start(self, target_count: int) -> None:
                if target_count > 0:
                    info(f"Found {target_count} GGUF artifact(s) to inspect", no_color=no_color)

            def on_artifact_inspected(self, path: Path, success_flag: bool) -> None:
                name = path.name
                if success_flag:
                    success(f"Inspected: {name}", no_color=no_color)
                else:
                    error(f"Failed: {name}", no_color=no_color)

            def on_runtime_inspected(self, path: Path, success_flag: bool) -> None:
                name = path.name
                if success_flag:
                    success(f"Runtime identified: {name}", no_color=no_color)
                else:
                    warning(f"Runtime build unknown: {name}", no_color=no_color)

            def on_template_analyzed(self, has_template: bool) -> None:
                if has_template:
                    info("Chat template analyzed", no_color=no_color)
                else:
                    info("No chat template found", no_color=no_color)

            def on_hash_complete(self, path: Path, digest: str) -> None:
                success(f"SHA-256: {digest[:16]}…", no_color=no_color)

            def on_advisory_join(self, rule_count: int) -> None:
                info(f"Checked against {rule_count} advisory rule(s)", no_color=no_color)

        # Run the check with progress
        report = run_check(
            options,
            command=["cancerbero", *list(argv or sys.argv[1:])],
            progress=CLIProgress(),
        )

        # Show summary of what was found
        artifact_count = len(report.artifacts)
        runtime_count = len(report.runtimes)
        finding_count = len([f for f in report.findings if f.status.value == "suspicious"])
        error_count = len([f for f in report.findings if f.status.value == "error"])

        if artifact_count:
            info(f"Analyzed {artifact_count} artifact(s)", no_color=no_color)
        if runtime_count:
            info(f"Identified {runtime_count} runtime(s)", no_color=no_color)
        if finding_count:
            warning(f"Found {finding_count} suspicious condition(s)", no_color=no_color)
        if error_count:
            error(f"Encountered {error_count} error(s)", no_color=no_color)

        # Handle --explain
        if config.explain:
            print(_render_explain(report, config.explain))
            return report.exit_code

        # Determine output format
        output_format = config.format or "terminal"
        if config.json_path:
            output_format = "json"

        # Render output
        if output_format == "json":
            if config.json_path == "-":
                # Print terminal to stderr, JSON to stdout
                print(render_terminal(report, verbose=config.verbose), file=sys.stderr, end="")
                print(canonical_json(report, include_observations=config.include_observations))
            elif config.json_path:
                write_json_report(
                    report,
                    config.json_path,
                    include_observations=config.include_observations,
                )
                # Also print terminal to stderr
                print(render_terminal(report, verbose=config.verbose), file=sys.stderr)
            else:
                print(canonical_json(report, include_observations=config.include_observations))
        elif output_format in ("markdown", "md"):
            print(render_markdown(report, include_observations=config.include_observations))
        elif output_format == "sarif":
            print(render_sarif(report))
        else:
            # Terminal output
            if config.summary_only:
                # Just print the verdict line
                verdict_map = {
                    "suitable": "SUITABLE",
                    "not_suitable": "NOT SUITABLE",
                    "undetermined": "UNDETERMINED",
                }
                print(f"Cancerbero — {verdict_map.get(report.verdict.value, report.verdict.value)}")
            else:
                print(render_terminal(report, verbose=config.verbose))

        # Interactive format prompt (only for terminal output and TTY)
        if (
            not no_interactive
            and output_format == "terminal"
            and not config.summary_only
            and sys.stdin.isatty()
            and sys.stderr.isatty()
        ):
            format_options = [
                "JSON (machine-readable)",
                "Markdown (documentation)",
                "SARIF (GitHub Code Scanning)",
            ]
            choice = prompt_choice(
                "Export to another format?",
                format_options,
                no_color=no_color,
            )
            if choice:
                if "JSON" in choice:
                    # Write to a default filename
                    import datetime

                    ts = datetime.datetime.now().strftime("%Y%m%dT%H%M%SZ")
                    out_path = f"cancerbero-{ts}.json"
                    write_json_report(
                        report, out_path, include_observations=config.include_observations
                    )
                    success(f"Written to {out_path}", no_color=no_color)
                elif "Markdown" in choice:
                    import datetime

                    ts = datetime.datetime.now().strftime("%Y%m%dT%H%M%SZ")
                    out_path = f"cancerbero-{ts}.md"
                    Path(out_path).write_text(
                        render_markdown(report, include_observations=config.include_observations),
                        encoding="utf-8",
                    )
                    success(f"Written to {out_path}", no_color=no_color)
                elif "SARIF" in choice:
                    import datetime

                    ts = datetime.datetime.now().strftime("%Y%m%dT%H%M%SZ")
                    out_path = f"cancerbero-{ts}.sarif"
                    Path(out_path).write_text(render_sarif(report), encoding="utf-8")
                    success(f"Written to {out_path}", no_color=no_color)

        return report.exit_code
    except (OSError, ValueError) as error:
        print(f"Cancerbero error: {error}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
