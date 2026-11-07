"""Noninteractive phase-one CLI; independent of the application and GUI entry point."""

import argparse
import json
import sys
import uuid


class UsageError(Exception):
    """Arguments could not be parsed; raw user values must not be echoed."""


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise UsageError()


def _parser():
    parser = Parser(
        prog="viruswise", add_help=False, allow_abbrev=False,
        description="Read-only VirusWise automation entry point (phase one).",
        epilog=("No scan or test execution yet. Doctor exit 0 means observations "
                "completed, not that all engines are healthy. Default output is JSON."),
    )
    parser.add_argument("command", nargs="?", metavar="{capabilities,doctor}",
                        help="capabilities: implemented interfaces; doctor: local diagnostics")
    parser.add_argument("-h", "--help", action="store_true", help="show help without diagnostics")
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--json", action="store_true", help="one final JSON object")
    output.add_argument("--jsonl", action="store_true", help="JSON events ending in a result event")
    return parser


def _fail(response, code, message, next_action, status="failed"):
    response["status"] = status
    response["result"] = None
    response["errors"] = [{"code": code, "message": message, "next_action": next_action}]


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    # Select error framing even when argument parsing fails. With both flags,
    # prefer a single JSON error object; never print argparse's raw user values.
    option_args = argv[:argv.index("--")] if "--" in argv else argv
    jsonl = "--jsonl" in option_args and "--json" not in option_args
    known_commands = {"capabilities", "doctor", "scan", "test"}
    response = {
        "schema_version": "1.0",
        "request_id": "req-" + uuid.uuid4().hex,
        "command": "unknown", "status": "completed", "result": None, "errors": [],
    }
    exit_code = 0
    try:
        parser = _parser()
        args = parser.parse_args(argv)
        if args.command in known_commands:
            response["command"] = args.command
        if args.help:
            if not (args.json or args.jsonl):
                print(parser.format_help(), end="")
                return 0
            response["command"] = args.command if args.command in known_commands else "help"
            response["result"] = {"help": parser.format_help()}
        elif args.command in ("scan", "test"):
            _fail(response, "CAPABILITY_UNAVAILABLE", "This command is not implemented in phase one.",
                  "Run capabilities --json for implemented commands.")
            exit_code = 3
        elif args.command not in ("capabilities", "doctor"):
            raise UsageError()
        else:
            # No main, utils.paths, scanner, GUI, or configuration imports.
            from core import diagnostics
            operation = diagnostics.capabilities if args.command == "capabilities" else diagnostics.doctor
            response["result"] = operation()
    except UsageError:
        _fail(response, "INVALID_ARGUMENTS", "Missing, unknown, or conflicting arguments.",
              "Run --help; choose capabilities or doctor and at most one output format.")
        exit_code = 2
    except ImportError:
        _fail(response, "DEPENDENCY_UNAVAILABLE", "A required CLI module could not be imported.",
              "Check the local CLI installation; no dependencies were installed automatically.")
        exit_code = 3
    except KeyboardInterrupt:
        _fail(response, "CANCELLED", "Local diagnostics were interrupted; no scan was started.",
              "Rerun the command when ready.", status="cancelled")
        exit_code = 130
    except Exception:
        # Exception strings may contain credentials or sensitive paths.
        _fail(response, "EXECUTION_FAILED", "The CLI could not complete the requested operation.",
              "Check the local CLI installation and rerun; do not infer engine health.")
        exit_code = 5
    if jsonl:
        response["event"] = "result"
    try:
        # ASCII escaping also works with legacy Windows console encodings.
        print(json.dumps(response, ensure_ascii=True, separators=(",", ":")))
        sys.stdout.flush()
    except KeyboardInterrupt:
        # Output may already be partial; do not append a second JSON object.
        return 130
    except (OSError, ValueError):
        return 5
    return exit_code


if __name__ == "__main__":
    # Keep the read-only command from creating application bytecode caches.
    sys.dont_write_bytecode = True
    try:
        exit_code = main()
    except KeyboardInterrupt:
        # Initialization/output can be interrupted before a response exists.
        exit_code = 130
    sys.exit(exit_code)
