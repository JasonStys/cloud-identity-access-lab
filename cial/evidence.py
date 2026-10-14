"""Jason Stys: bounded truthful decision evidence, canonical hashes and inert HTML exports."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROW — line 38
# definition: validate — line 51
# parameter: report — line 51
# variable: rows — line 65
# variable: ids — line 68
# variable: row — line 69
# variable: field — line 72
# variable: char — line 76
# variable: elapsed — line 94
# definition: passed — line 104
# parameter: row — line 104
# definition: canonical — line 109
# parameter: report — line 109
# definition: digest — line 123
# parameter: report — line 123
# definition: render — line 128
# parameter: report — line 128
# variable: report — line 130
# variable: rows — line 131
# variable: field — line 135
# variable: row — line 138
# END CODE MAP

from __future__ import annotations

import hashlib
import html
import json
import math
import re
from typing import Any

from .engine import ACTIONS, REASONS, RESOURCES
from .identity import Rejected

ROW = {
    "id",
    "title",
    "principal",
    "action",
    "resource",
    "expected",
    "observed",
    "reason",
    "elapsed_ms",
}


def validate(report: Any) -> dict[str, Any]:
    """Reject malformed/duplicate/nonfinite/private-bearing evidence rather than infer or invent a passing verdict."""
    if (
        not isinstance(report, dict)
        or set(report) != {"schema", "synthetic", "source", "cases"}
        or type(report["schema"]) is not int
        or report["schema"] != 1
        or report["synthetic"] is not True
    ):
        raise Rejected("report_rejected")
    if not isinstance(report["source"], str) or not re.fullmatch(
        r"(?:[a-f0-9]{40}|uncommitted)", report["source"]
    ):
        raise Rejected("report_rejected")
    rows = report["cases"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= 128:
        raise Rejected("report_rejected")
    ids: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != ROW:
            raise Rejected("report_rejected")
        for field in ("id", "title", "principal", "action", "resource", "reason"):
            if (
                not isinstance(row[field], str)
                or not 1 <= len(row[field]) <= 200
                or any(ord(char) < 32 for char in row[field])
            ):
                raise Rejected("report_rejected")
        if (
            not re.fullmatch(r"[A-Z][A-Z0-9-]{1,63}", row["id"])
            or row["id"] in ids
            or row["action"] not in ACTIONS
            or row["resource"] not in RESOURCES
            or row["reason"] not in REASONS
        ):
            raise Rejected("report_rejected")
        ids.add(row["id"])
        if (
            type(row["expected"]) is not bool
            or type(row["observed"]) is not bool
            or (row["reason"] == "allowed") != row["observed"]
        ):
            raise Rejected("report_rejected")
        elapsed = row["elapsed_ms"]
        if (
            type(elapsed) not in {int, float}
            or not math.isfinite(elapsed)
            or not 0 <= elapsed <= 60000
        ):
            raise Rejected("report_rejected")
    return dict(report)


def passed(row: dict[str, Any]) -> bool:
    """An expected denial is a passing regression only when the observed decision really denies."""
    return bool(row["expected"] == row["observed"])


def canonical(report: dict[str, Any]) -> bytes:
    """Serialize only validated finite evidence with stable key order, never token/claim material."""
    return (
        json.dumps(
            validate(report),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode()


def digest(report: dict[str, Any]) -> str:
    """Fingerprint the exact exported JSON bytes for reproducible evidence comparison."""
    return hashlib.sha256(canonical(report)).hexdigest()


def render(report: dict[str, Any]) -> str:
    """Generate a self-contained escaped read-only summary; no scripts, remote URLs or active user markup."""
    report = validate(report)
    rows = "".join(
        "<tr>"
        + "".join(
            "<td>" + html.escape(str(row[field])) + "</td>"
            for field in ("id", "title", "principal", "expected", "observed", "reason")
        )
        + "</tr>"
        for row in report["cases"]
    )
    return (
        '<!doctype html><html lang="en"><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'"><title>Identity evidence · Jason Stys</title><h1>Identity evidence · Jason Stys</h1><p>Synthetic local integration, not a live-cloud assurance claim.</p><p>Source: '
        + html.escape(report["source"])
        + "</p><p>SHA256: "
        + digest(report)
        + "</p><table><caption>Expected versus observed decisions</caption><thead><tr><th>ID</th><th>Scenario</th><th>Principal</th><th>Expected allow</th><th>Observed allow</th><th>Reason</th></tr></thead><tbody>"
        + rows
        + "</tbody></table></html>"
    )
