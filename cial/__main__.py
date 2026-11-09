"""Jason Stys: genuine signed-identity/OPA matrix runner, nonoverwriting reports and owned-loopback preview."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: save — line 32
# parameter: output — line 32
# parameter: report — line 32
# variable: output — line 34
# variable: path — line 36
# definition: main — line 45
# parameter: argv — line 45
# variable: parser — line 47
# variable: args — line 56
# variable: comparison — line 66
# variable: report — line 74
# variable: row — line 75
# variable: successes — line 75
# variable: listener — line 84
# END CODE MAP

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from . import recertify
from .evidence import canonical, digest, passed, render
from .identity import Rejected
from .scenarios import run
from .server import server


def save(report: dict[str, Any], output: Path) -> None:
    """Create a new nonlinked evidence directory; never overwrite or automatically delete earlier reports."""
    output = output.absolute()
    if any(
        path.is_symlink() or path.is_junction() for path in (output, *output.parents)
    ):
        raise Rejected("linked_output")
    output.mkdir(mode=0o700)
    (output / "decisions.json").write_bytes(canonical(report))
    (output / "decisions.html").write_text(render(report), encoding="utf-8")
    (output / "decisions.sha256").write_text(digest(report) + "\n", encoding="ascii")


def main(argv: list[str] | None = None) -> int:
    """Run real assurance before serving; missing tools or mismatched outcomes are nonzero failures, never skipped."""
    parser = argparse.ArgumentParser(
        description="Jason Stys: synthetic identity/access evidence, no cloud changes"
    )
    parser.add_argument("command", choices=["run", "serve", "recertify"])
    parser.add_argument("--out", type=Path)
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--at", type=int)
    args = parser.parse_args(argv)
    try:
        if args.command == "recertify":
            if (
                args.baseline is None
                or args.candidate is None
                or args.at is None
                or args.out is None
            ):
                raise Rejected("review_arguments")
            comparison = recertify.compare(args.baseline, args.candidate, args.at)
            recertify.save(comparison, args.out)
            print(
                f"Potential permission changes: {len(comparison['permission_gains'])} gains / {len(comparison['permission_losses'])} losses"
            )
            return int(comparison["review_required"])
        if args.command == "run" and args.out is None:
            raise Rejected("output_required")
        report = run()
        successes = sum(passed(row) for row in report["cases"])
        if args.out is not None:
            save(report, args.out)
        print(
            f"Observed identity/policy scenarios: {successes}/{len(report['cases'])} passed"
        )
        if successes != len(report["cases"]):
            return 1
        if args.command == "serve":
            with server(report, args.port) as listener:
                print(
                    f"Local synthetic evidence: http://127.0.0.1:{listener.server_port}/",
                    flush=True,
                )
                try:
                    listener.serve_forever()
                except KeyboardInterrupt:
                    pass
        return 0
    except (OSError, Rejected):
        print(
            "Rejected: lab_tool_input_or_evidence_failed; inspect prerequisites and build commands"
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
