"""Jason Stys: trusted fixed-policy OPA adapter, closed request contract and privacy-safe decisions."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 35
# variable: ACTIONS — line 36
# variable: RESOURCES — line 37
# variable: REASONS — line 38
# definition: Engine — line 41
# definition: __init__ — line 44
# parameter: executable — line 44
# parameter: self — line 44
# parameter: verifier — line 44
# attribute: executable — line 46
# attribute: verifier — line 47
# definition: decide — line 49
# parameter: action — line 50
# parameter: now — line 50
# parameter: resource — line 50
# parameter: self — line 50
# parameter: token — line 50
# variable: identity — line 61
# variable: context — line 64
# variable: result — line 72
# variable: value — line 97
# END CODE MAP

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from .identity import Rejected, Verifier

ROOT = Path(__file__).resolve().parents[1]
ACTIONS = {"read", "publish", "delete", "rotate"}
RESOURCES = {"alpha-docs", "alpha-artifacts", "beta-docs", "alpha-keys"}
REASONS = {"allowed", "policy_denied", "credential_rejected"}


class Engine:
    """Evaluate only reviewed local Rego and registry; no caller scripts, remote policy or shell interpolation."""

    def __init__(self, executable: Path, verifier: Verifier) -> None:
        """Bind a trusted installed OPA executable and pinned identity verifier."""
        self.executable = executable
        self.verifier = verifier

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
                    str(ROOT / "policy/registry.json"),
                    "data.cial.decision",
                ],
                input=json.dumps(context),
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise Rejected("policy_engine_failed") from None
        if result.returncode != 0 or len(result.stdout) > 65536:
            raise Rejected("policy_engine_failed")
        try:
            value = json.loads(result.stdout)["result"][0]["expressions"][0]["value"]
        except (ValueError, KeyError, IndexError, TypeError):
            raise Rejected("policy_engine_failed") from None
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
