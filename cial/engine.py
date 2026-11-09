"""Jason Stys: trusted fixed-policy OPA adapter, closed request contract and privacy-safe decisions."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 37
# variable: ACTIONS — line 38
# variable: RESOURCES — line 39
# variable: REASONS — line 40
# definition: Engine — line 43
# definition: __init__ — line 46
# parameter: executable — line 47
# parameter: registry — line 47
# parameter: self — line 47
# parameter: verifier — line 47
# attribute: executable — line 50
# attribute: verifier — line 51
# attribute: registry — line 52
# definition: decide — line 56
# parameter: action — line 57
# parameter: now — line 57
# parameter: resource — line 57
# parameter: self — line 57
# parameter: token — line 57
# variable: identity — line 68
# variable: context — line 71
# variable: result — line 79
# variable: value — line 104
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
