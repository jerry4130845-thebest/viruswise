"""Noninteractive VirusWise CLI, independent of GUI and application startup."""

import argparse
import json
import math
import sys
import uuid


class UsageError(Exception):
    """Invalid arguments; never echo raw user values."""


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise UsageError()


def _parser():
    parser = Parser(
        prog="viruswise", add_help=False, allow_abbrev=False,
        description="VirusWise diagnostics, explicitly authorized scans and installed-service control.",
        epilog=("Doctor success is not engine health. Service readiness is not proven protection. "
                "Tests and GUI instance control are not implemented. Default output is JSON."),
    )
    parser.add_argument("command", nargs="?", metavar="{capabilities,doctor,scan,defense}")
    parser.add_argument("target", nargs="?", help="scan: file/directory; defense: status/start/stop")
    parser.add_argument("-h", "--help", action="store_true")
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--json", action="store_true", help="one final JSON object (default)")
    output.add_argument("--jsonl", action="store_true", help="one final result event")
    parser.add_argument("--engine", choices=("defender", "virustotal"))
    parser.add_argument("--timeout", type=float, help="operation budget in seconds (default 120; not a hard I/O deadline)")
    parser.add_argument("--allow-network", action="store_true", help="allow VirusTotal hash queries")
    parser.add_argument("--allow-upload", action="store_true", help="also allow complete-file uploads to VirusTotal")
    parser.add_argument("--allow-system-effects", action="store_true", help="allow Defender remediation or defense service changes")
    return parser


def _fail(response, code, message, next_action, status="failed"):
    response["status"] = status
    response["result"] = None
    response["errors"] = [{"code": code, "message": message, "next_action": next_action}]


def _validate(args):
    if args.timeout is not None and (not math.isfinite(args.timeout) or args.timeout <= 0):
        raise UsageError()
    permissions = args.allow_network or args.allow_upload or args.allow_system_effects
    if args.command in ("capabilities", "doctor", "test"):
        if args.target is not None or args.engine is not None or args.timeout is not None or permissions:
            raise UsageError()
    elif args.command == "scan":
        if not args.target or args.engine is None:
            raise UsageError()
        if args.engine == "defender" and (args.allow_network or args.allow_upload):
            raise UsageError()
        if args.engine == "virustotal" and args.allow_system_effects:
            raise UsageError()
    elif args.command == "defense":
        if args.target not in ("status", "start", "stop") or args.engine is not None or args.allow_network or args.allow_upload:
            raise UsageError()
        if args.target == "status" and (args.timeout is not None or args.allow_system_effects):
            raise UsageError()
    else:
        raise UsageError()


def _outcome(response, result):
    """Preserve partial evidence while giving automation an honest process status."""
    response["result"] = result
    status = result.get("status", "completed")
    exit_code = result.get("exit_code")
    if exit_code is None:
        exit_code = {"completed": 0, "cancelled": 130, "timeout": 124,
                     "timed_out": 124, "failed": 5, "unavailable": 3,
                     "unsupported": 3}.get(status, 6)
    if exit_code == 0:
        response["status"] = "completed"
    else:
        response["status"] = "cancelled" if exit_code == 130 else "partial" if exit_code == 6 else "failed"
        response["errors"] = [{
            "code": result.get("code") or {3: "CAPABILITY_UNAVAILABLE", 4: "AUTHORIZATION_REQUIRED",
                     5: "EXECUTION_FAILED", 6: "RESULT_UNCONFIRMED", 124: "OPERATION_TIMEOUT",
                     130: "CANCELLED"}.get(exit_code, "EXECUTION_FAILED"),
            "message": "The operation did not produce a fully confirmed result.",
            "next_action": "Inspect result evidence and limitations before retrying; do not infer protection or file safety.",
        }]
    return exit_code


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    option_args = argv[:argv.index("--")] if "--" in argv else argv
    jsonl = "--jsonl" in option_args and "--json" not in option_args
    known_commands = {"capabilities", "doctor", "scan", "defense", "test"}
    response = {
        "schema_version": "1.0", "request_id": "req-" + uuid.uuid4().hex,
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
        else:
            _validate(args)
            timeout = 120 if args.timeout is None else args.timeout
            if args.command == "test":
                _fail(response, "CAPABILITY_UNAVAILABLE", "Test execution is not implemented.",
                      "Run capabilities --json for implemented commands.")
                exit_code = 3
            elif args.command in ("capabilities", "doctor"):
                from core import diagnostics
                response["result"] = getattr(diagnostics, args.command)()
            elif ((args.command == "scan" and not (args.allow_network if args.engine == "virustotal" else args.allow_system_effects))
                  or (args.command == "defense" and args.target != "status" and not args.allow_system_effects)):
                _fail(response, "AUTHORIZATION_REQUIRED", "Explicit permission is required before this operation.",
                      "Use --allow-network for VirusTotal, or --allow-system-effects for Defender/service changes; review --help.")
                exit_code = 4
            elif args.command == "scan":
                import os
                from core import scanning
                try:
                    result = scanning.scan_path(
                        args.target, args.engine, allow_network=args.allow_network,
                        allow_upload=args.allow_upload, allow_system_effects=args.allow_system_effects,
                        api_key=os.environ.get("VIRUSWISE_VT_API_KEY", "") if args.engine == "virustotal" else "",
                        timeout=timeout,
                    )
                    exit_code = _outcome(response, result)
                except scanning.ScanError as exc:
                    _fail(response, exc.code.upper(), "The scan request could not be accepted.",
                          "Check path, explicit permissions, engine dependencies and VIRUSWISE_VT_API_KEY for VirusTotal.")
                    exit_code = exc.exit_code
            else:
                from core import defense_control
                operation = getattr(defense_control, args.target)
                result = operation() if args.target == "status" else operation(
                    timeout=timeout, allow_system_effects=args.allow_system_effects)
                exit_code = _outcome(response, result)
    except UsageError:
        _fail(response, "INVALID_ARGUMENTS", "Missing, unknown, or conflicting arguments.",
              "Run --help; use only options applicable to the chosen command and one output format.")
        exit_code = 2
    except ImportError:
        _fail(response, "DEPENDENCY_UNAVAILABLE", "A required CLI module could not be imported.",
              "Check the installation; no dependencies were installed automatically.")
        exit_code = 3
    except KeyboardInterrupt:
        _fail(response, "CANCELLED", "The operation was interrupted; completed external effects are not rolled back.",
              "Check the relevant service or Windows Security state before retrying.", status="cancelled")
        exit_code = 130
    except Exception:
        _fail(response, "EXECUTION_FAILED", "The CLI could not complete the requested operation.",
              "Check installation and external state before retrying; no engine health is implied.")
        exit_code = 5
    if jsonl:
        response["event"] = "result"
    try:
        print(json.dumps(response, ensure_ascii=True, separators=(",", ":")))
        sys.stdout.flush()
    except KeyboardInterrupt:
        return 130
    except Exception:
        return 5
    return exit_code


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    try:
        exit_code = main()
    except KeyboardInterrupt:
        exit_code = 130
    sys.exit(exit_code)
