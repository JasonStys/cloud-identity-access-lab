"""Real signed-context/OPA entitlement comparison of trusted synthetic registries. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: closed — line 88
# parameter: names — line 88
# parameter: value — line 88
# definition: token — line 95
# parameter: subject — line 95
# parameter: value — line 95
# definition: registry — line 108
# parameter: path — line 108
# variable: stream — line 112
# variable: content — line 113
# variable: root — line 117
# variable: data — line 120
# variable: name — line 129
# variable: raw — line 129
# variable: row — line 131
# variable: raw — line 135
# variable: row — line 136
# variable: raw — line 138
# variable: actions — line 139
# variable: action — line 145
# variable: grant — line 150
# variable: key — line 165
# variable: approvers — line 170
# variable: name — line 173
# definition: encoded — line 180
# parameter: value — line 180
# definition: compare — line 187
# parameter: baseline — line 187
# parameter: candidate — line 187
# parameter: now — line 187
# variable: after — line 191
# variable: before — line 191
# variable: subjects — line 192
# variable: started — line 197
# variable: issuer — line 198
# variable: observed — line 199
# variable: opa — line 200
# variable: temporary — line 201
# variable: root — line 202
# variable: engines — line 203
# variable: data — line 204
# variable: name — line 204
# variable: path — line 205
# variable: subject — line 208
# variable: mfa — line 209
# variable: credential — line 210
# variable: action — line 211
# variable: resource — line 212
# variable: new — line 215
# variable: old — line 215
# variable: engine — line 217
# variable: gains — line 229
# variable: row — line 230
# variable: losses — line 232
# variable: row — line 233
# variable: grant — line 235
# variable: row — line 250
# definition: save — line 267
# parameter: output — line 267
# parameter: result — line 267
# variable: absolute — line 269
# variable: path — line 272
# variable: text — line 275
# variable: rows — line 276
# variable: key — line 280
# variable: row — line 290
# variable: page — line 292
# END CODE MAP

from __future__ import annotations

import hashlib
import html
import json
import re
import tempfile
import time
from pathlib import Path
from typing import Any

from .engine import ACTIONS, RESOURCES, Engine
from .identity import FixtureIssuer, Rejected, Verifier, unique_pairs
from .tooling import executable


def closed(value: Any, names: set[str]) -> dict[str, Any]:
    """Reject unknown registry fields before considering any proposed trusted configuration."""
    if not isinstance(value, dict) or set(value) != names:
        raise Rejected("registry_fields")
    return value


def token(value: Any, subject: bool = False) -> str:
    """Validate bounded synthetic identifiers without free text, wildcards, credentials or markup."""
    if (
        not isinstance(value, str)
        or re.fullmatch(
            r"[A-Za-z0-9:/.@_-]{1,180}" if subject else r"[A-Za-z0-9_-]{1,80}", value
        )
        is None
    ):
        raise Rejected("registry_identifier")
    return value


def registry(path: Path) -> dict[str, Any]:
    """Read a closed <=64KiB trusted synthetic registry; never accept policies or executable code."""
    if path.is_symlink() or path.is_junction() or not path.is_file():
        raise Rejected("registry_file")
    with path.open("rb") as stream:
        content = stream.read(65537)
    if len(content) > 65536:
        raise Rejected("registry_bound")
    try:
        root = closed(json.loads(content, object_pairs_hook=unique_pairs), {"lab"})
    except (ValueError, UnicodeError, RecursionError):
        raise Rejected("registry_json") from None
    data = closed(root["lab"], {"synthetic", "principals", "resources", "emergency"})
    if (
        data["synthetic"] is not True
        or not isinstance(data["principals"], dict)
        or not 1 <= len(data["principals"]) <= 8
        or not isinstance(data["resources"], dict)
        or set(data["resources"]) != RESOURCES
    ):
        raise Rejected("registry_scope")
    for name, raw in data["principals"].items():
        token(name, subject=True)
        row = closed(raw, {"kind", "tenant", "actions"})
        if row["kind"] not in ("human", "workload"):
            raise Rejected("registry_kind")
        token(row["tenant"])
    for raw in data["resources"].values():
        row = closed(raw, {"tenant", "actions"})
        token(row["tenant"])
    for raw in [*data["principals"].values(), *data["resources"].values()]:
        actions = raw["actions"]
        if (
            not isinstance(actions, list)
            or not 1 <= len(actions) <= 4
            or any(
                not isinstance(action, str) or action not in ACTIONS
                for action in actions
            )
            or len(set(actions)) != len(actions)
        ):
            raise Rejected("registry_actions")
    grant = closed(
        data["emergency"],
        {"subject", "action", "resource", "starts", "expires", "approvers"},
    )
    token(grant["subject"], subject=True)
    if (
        grant["subject"] not in data["principals"]
        or grant["action"] != "rotate"
        or not isinstance(grant["resource"], str)
        or grant["resource"] not in RESOURCES
    ):
        raise Rejected("registry_grant_scope")
    if (
        any(
            type(grant[key]) is not int or not 0 <= grant[key] <= 4102444800
            for key in ("starts", "expires")
        )
        or not 0 < grant["expires"] - grant["starts"] <= 900
    ):
        raise Rejected("registry_grant_time")
    approvers = grant["approvers"]
    if not isinstance(approvers, list) or len(approvers) != 2:
        raise Rejected("registry_grant_approvers")
    for name in approvers:
        token(name, subject=True)
    if len(set(approvers)) != 2 or grant["subject"] in approvers:
        raise Rejected("registry_grant_approvers")
    return root


def encoded(value: dict[str, Any]) -> bytes:
    """Encode finite deterministic review data; it contains neither private keys nor signed tokens."""
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode()


def compare(baseline: Path, candidate: Path, now: int) -> dict[str, Any]:
    """Enumerate <=256 fixed contexts through real signature verification and both native OPA registries."""
    if type(now) is not int or not 0 <= now <= 4102444500:
        raise Rejected("review_clock")
    before, after = registry(baseline), registry(candidate)
    subjects = sorted(
        before["lab"]["principals"].keys() | after["lab"]["principals"].keys()
    )
    if len(subjects) > 8:
        raise Rejected("review_context_bound")
    started = time.monotonic()
    issuer = FixtureIssuer()
    observed = []
    opa = executable("opa")
    with tempfile.TemporaryDirectory(prefix="cial-recertify-") as temporary:
        root = Path(temporary)
        engines = []
        for name, data in (("baseline", before), ("candidate", after)):
            path = root / f"{name}.json"
            path.write_bytes(encoded(data))
            engines.append(Engine(opa, Verifier(issuer.public_key), path))
        for subject in subjects:
            for mfa in (False, True):
                credential = issuer.issue(subject, now, mfa=mfa)
                for action in sorted(ACTIONS):
                    for resource in sorted(RESOURCES):
                        if time.monotonic() - started > 120:
                            raise Rejected("review_time_bound")
                        old, new = [
                            engine.decide(credential, now, action, resource)["allow"]
                            for engine in engines
                        ]
                        observed.append(
                            {
                                "subject": subject,
                                "mfa_fresh": mfa,
                                "action": action,
                                "resource": resource,
                                "baseline_allow": old,
                                "candidate_allow": new,
                            }
                        )
    gains = [
        row for row in observed if row["candidate_allow"] and not row["baseline_allow"]
    ]
    losses = [
        row for row in observed if row["baseline_allow"] and not row["candidate_allow"]
    ]
    grant = after["lab"]["emergency"]
    return {
        "schema": 1,
        "kind": "synthetic_entitlement_recertification",
        "author": "Jason Stys",
        "as_of": now,
        "baseline_sha256": hashlib.sha256(encoded(before)).hexdigest(),
        "candidate_sha256": hashlib.sha256(encoded(after)).hexdigest(),
        "policy_sha256": hashlib.sha256(
            (Path(__file__).resolve().parents[1] / "policy/access.rego").read_bytes()
        ).hexdigest(),
        "contexts_evaluated": len(observed),
        "native_decisions": len(observed) * 2,
        "permission_gains": gains,
        "permission_losses": losses,
        "candidate_entitlements": [row for row in observed if row["candidate_allow"]],
        "emergency": {
            "subject": grant["subject"],
            "starts": grant["starts"],
            "expires": grant["expires"],
            "state": "not_started"
            if now < grant["starts"]
            else "expired"
            if now >= grant["expires"]
            else "active",
            "remaining_seconds": max(0, grant["expires"] - max(now, grant["starts"])),
        },
        "review_required": bool(gains or losses),
        "scope": "Potential synthetic signed-context permissions under this fixed Rego model; not real authentication, effective AWS authorization, approval or a cloud change. MFA contexts are assertions, not completed challenges.",
    }


def save(result: dict[str, Any], output: Path) -> None:
    """Write a new private JSON/inert HTML permission review; do not modify authoritative registries."""
    absolute = output.absolute()
    if any(
        path.is_symlink() or path.is_junction()
        for path in (absolute, *absolute.parents)
    ):
        raise Rejected("linked_output")
    text = encoded(result).decode()
    rows = "".join(
        "<tr>"
        + "".join(
            f"<td>{html.escape(str(row[key]))}</td>"
            for key in (
                "subject",
                "mfa_fresh",
                "action",
                "resource",
                "baseline_allow",
                "candidate_allow",
            )
        )
        + "</tr>"
        for row in [*result["permission_gains"], *result["permission_losses"]]
    )
    page = (
        '<!doctype html><html lang="en"><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'"><title>Entitlement review — Jason Stys</title><h1>Potential permission changes</h1><p>Created by Jason Stys. Synthetic signed contexts; not live-cloud authorization.</p><table><caption>Review gains and losses</caption><tr><th>Subject</th><th>Fresh MFA</th><th>Action</th><th>Resource</th><th>Baseline</th><th>Candidate</th></tr>'
        + rows
        + "</table><details><summary>Full entitlements, expiry and evidence identities</summary><pre>"
        + html.escape(text)
        + "</pre></details></html>"
    )
    absolute.mkdir(mode=0o700)
    (absolute / "entitlements.json").write_bytes(encoded(result))
    (absolute / "entitlements.html").write_text(page, encoding="utf-8")
