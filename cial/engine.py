"""Jason Stys: trusted fixed-policy OPA adapter, closed request contract and privacy-safe decisions."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 71
# variable: ACTIONS — line 72
# variable: RESOURCES — line 73
# variable: REASONS — line 74
# variable: BATCH_QUERY — line 75
# definition: Engine — line 78
# definition: __init__ — line 81
# parameter: executable — line 82
# parameter: registry — line 82
# parameter: self — line 82
# parameter: verifier — line 82
# attribute: executable — line 85
# attribute: verifier — line 86
# attribute: registry — line 87
# definition: decide — line 91
# parameter: action — line 92
# parameter: now — line 92
# parameter: resource — line 92
# parameter: self — line 92
# parameter: token — line 92
# variable: identity — line 103
# variable: context — line 106
# definition: decide_many — line 115
# parameter: requests — line 116
# parameter: self — line 116
# variable: outputs — line 121
# variable: contexts — line 122
# variable: positions — line 123
# variable: index — line 124
# variable: request — line 124
# variable: action — line 127
# variable: now — line 127
# variable: resource — line 127
# variable: token — line 127
# variable: identity — line 136
# variable: observed — line 152
# variable: decision — line 153
# variable: position — line 153
# variable: value — line 155
# variable: value — line 157
# definition: _evaluate — line 159
# parameter: batch — line 159
# parameter: context — line 159
# parameter: self — line 159
# variable: query — line 161
# variable: payload — line 162
# variable: result — line 166
# variable: key — line 187
# variable: results — line 196
# variable: expressions — line 201
# variable: value — line 204
# variable: observed — line 215
# variable: index — line 216
# variable: row — line 216
# definition: decision — line 228
# parameter: value — line 228
# END CODE MAP

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

from .identity import Rejected, Verifier, unique_pairs

ROOT = Path(__file__).resolve().parents[1]
ACTIONS = {"read", "publish", "delete", "rotate"}
RESOURCES = {"alpha-docs", "alpha-artifacts", "beta-docs", "alpha-keys"}
REASONS = {"allowed", "policy_denied", "credential_rejected"}
BATCH_QUERY = '[{"index": index, "decision": decision} | some index; context := input[index]; decision := data.cial.decision with input as context]'


class Engine:
    """Evaluate only reviewed local Rego and registry; no caller scripts, remote policy or shell interpolation."""

    def __init__(
        self, executable: Path, verifier: Verifier, registry: Path | None = None
    ) -> None:
        """Bind a trusted installed OPA executable and pinned identity verifier."""
        self.executable = executable
        self.verifier = verifier
        self.registry = (
            registry if registry is not None else ROOT / "policy/registry.json"
        )

    def decide(
        self, token: str, now: int, action: str, resource: str
    ) -> dict[str, Any]:
        """Authenticate first, then evaluate authorization with no raw token exposed to OPA or reports."""
        if (
            not isinstance(action, str)
            or not isinstance(resource, str)
            or action not in ACTIONS
            or resource not in RESOURCES
        ):
            raise Rejected("request_rejected")
        try:
            identity = self.verifier.verify(token, now)
        except Rejected:
            return {"allow": False, "reason": "credential_rejected"}
        context = {
            "subject": identity.subject,
            "mfa_fresh": identity.mfa_fresh,
            "now": now,
            "action": action,
            "resource": resource,
        }
        return dict(self._evaluate(context, batch=False))

    def decide_many(
        self, requests: list[tuple[str, int, str, str]]
    ) -> list[dict[str, Any]]:
        """Verify every token individually, then evaluate at most256 ordered contexts in one fixed native query."""
        if not isinstance(requests, list) or not 1 <= len(requests) <= 256:
            raise Rejected("request_batch_bound")
        outputs: list[dict[str, Any] | None] = []
        contexts: list[dict[str, Any]] = []
        positions: list[int] = []
        for index, request in enumerate(requests):
            if not isinstance(request, tuple) or len(request) != 4:
                raise Rejected("request_rejected")
            token, now, action, resource = request
            if (
                not isinstance(action, str)
                or not isinstance(resource, str)
                or action not in ACTIONS
                or resource not in RESOURCES
            ):
                raise Rejected("request_rejected")
            try:
                identity = self.verifier.verify(token, now)
            except Rejected:
                outputs.append({"allow": False, "reason": "credential_rejected"})
                continue
            positions.append(index)
            outputs.append(None)
            contexts.append(
                {
                    "subject": identity.subject,
                    "mfa_fresh": identity.mfa_fresh,
                    "now": now,
                    "action": action,
                    "resource": resource,
                }
            )
        if contexts:
            observed = self._evaluate(contexts, batch=True)
            for position, decision in zip(positions, observed, strict=True):
                outputs[position] = dict(decision)
        if any(value is None for value in outputs):
            raise Rejected("policy_engine_failed")
        return [dict(value) for value in outputs if value is not None]

    def _evaluate(self, context: object, *, batch: bool) -> Any:
        """Invoke only the two authored queries and validate complete finite native evidence before returning any decision."""
        query = BATCH_QUERY if batch else "data.cial.decision"
        payload = json.dumps(context)
        if len(payload.encode("utf8")) > 128 * 1024:
            raise Rejected("request_batch_bound")
        try:
            result = subprocess.run(
                [
                    str(self.executable),
                    "eval",
                    "--strict",
                    "--strict-builtin-errors",
                    "--format=json",
                    "--stdin-input",
                    "--data",
                    str(ROOT / "policy/access.rego"),
                    "--data",
                    str(self.registry),
                    query,
                ],
                input=payload,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
                env={
                    key: os.environ[key]
                    for key in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP")
                    if key in os.environ
                },
            )
        except (OSError, subprocess.TimeoutExpired):
            raise Rejected("policy_engine_failed") from None
        if result.returncode != 0 or len(result.stdout) > 65536:
            raise Rejected("policy_engine_failed")
        try:
            results = json.loads(result.stdout, object_pairs_hook=unique_pairs)[
                "result"
            ]
            if not isinstance(results, list) or len(results) != 1:
                raise Rejected("policy_engine_failed")
            expressions = results[0]["expressions"]
            if not isinstance(expressions, list) or len(expressions) != 1:
                raise Rejected("policy_engine_failed")
            value = expressions[0]["value"]
        except (ValueError, KeyError, IndexError, TypeError):
            raise Rejected("policy_engine_failed") from None
        if not batch:
            return decision(value)
        if (
            not isinstance(context, list)
            or not isinstance(value, list)
            or len(value) != len(context)
        ):
            raise Rejected("policy_engine_failed")
        observed = []
        for index, row in enumerate(value):
            if (
                not isinstance(row, dict)
                or set(row) != {"index", "decision"}
                or type(row["index"]) is not int
                or row["index"] != index
            ):
                raise Rejected("policy_engine_failed")
            observed.append(decision(row["decision"]))
        return observed


def decision(value: Any) -> dict[str, Any]:
    """Accept only the original closed boolean/reason pair; denials cannot masquerade as valid allows."""
    if (
        not isinstance(value, dict)
        or set(value) != {"allow", "reason"}
        or type(value["allow"]) is not bool
        or not isinstance(value["reason"], str)
        or value["reason"] not in {"allowed", "policy_denied"}
        or (value["reason"] == "allowed") != value["allow"]
    ):
        raise Rejected("policy_engine_failed")
    return dict(value)
