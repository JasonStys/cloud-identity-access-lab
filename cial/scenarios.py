"""Jason Stys: real signed-credential and OPA conformance scenarios; outcomes are observed, not canned success."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: NOW — line 41
# variable: WORKLOAD — line 42
# definition: run — line 45
# variable: issuer — line 47
# variable: verifier — line 48
# variable: engine — line 49
# variable: rows — line 50
# definition: check — line 52
# parameter: identifier — line 53
# parameter: title — line 54
# parameter: subject — line 55
# parameter: action — line 56
# parameter: resource — line 57
# parameter: expected — line 58
# parameter: now — line 60
# parameter: token — line 61
# parameter: mfa — line 62
# parameter: claims — line 63
# variable: credential — line 66
# variable: started — line 71
# variable: result — line 72
# variable: first — line 288
# variable: peer — line 289
# variable: source — line 365
# variable: source — line 373
# END CODE MAP

from __future__ import annotations

import subprocess
import time
from typing import Any

from .engine import Engine
from .evidence import validate
from .identity import FixtureIssuer, Verifier
from .tooling import ROOT, executable

NOW = 2000000000
WORKLOAD = "repo:synthetic-org@101/synthetic-release@202:ref:refs/heads/main"


def run() -> dict[str, Any]:
    """Use fresh in-memory issuer keys and actual native Rego decisions for this deterministic clocked matrix."""
    issuer = FixtureIssuer()
    verifier = Verifier(issuer.public_key)
    engine = Engine(executable("opa"), verifier)
    rows: list[dict[str, Any]] = []

    def check(
        identifier: str,
        title: str,
        subject: str,
        action: str,
        resource: str,
        expected: bool,
        *,
        now: int = NOW,
        token: str | None = None,
        mfa: bool = True,
        **claims: Any,
    ) -> None:
        """Evaluate one genuine credential-to-policy boundary and retain only sanitized public scenario evidence."""
        credential = (
            token
            if token is not None
            else issuer.issue(subject, now, mfa=mfa, **claims)
        )
        started = time.perf_counter()
        result = engine.decide(credential, now, action, resource)
        rows.append(
            {
                "id": identifier,
                "title": title,
                "principal": subject,
                "action": action,
                "resource": resource,
                "expected": expected,
                "observed": result["allow"],
                "reason": result["reason"],
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
            }
        )

    check(
        "H-READ",
        "Human reads own documentation",
        "engineer-alpha",
        "read",
        "alpha-docs",
        True,
    )
    check(
        "H-MFA",
        "Fresh MFA permits publishing",
        "engineer-alpha",
        "publish",
        "alpha-artifacts",
        True,
    )
    check(
        "H-NO-MFA",
        "Password-only assertion cannot publish",
        "engineer-alpha",
        "publish",
        "alpha-artifacts",
        False,
        mfa=False,
    )
    check(
        "H-STALE-MFA",
        "MFA freshness boundary is exclusive",
        "engineer-alpha",
        "publish",
        "alpha-artifacts",
        False,
        auth_time=NOW - 300,
    )
    check(
        "H-CROSS-TENANT",
        "Cross-tenant records remain inaccessible",
        "engineer-alpha",
        "read",
        "beta-docs",
        False,
    )
    check(
        "H-RESOURCE-CEILING",
        "Identity permission alone cannot publish documents",
        "engineer-alpha",
        "publish",
        "alpha-docs",
        False,
    )
    check(
        "H-EXPLICIT-DENY",
        "Delete has no grant path",
        "engineer-alpha",
        "delete",
        "alpha-artifacts",
        False,
    )
    check(
        "H-BETA-READ",
        "Beta reader accesses its own tenant",
        "reader-beta",
        "read",
        "beta-docs",
        True,
    )
    check(
        "H-UNKNOWN",
        "An authenticated but unregistered subject is denied",
        "unregistered",
        "read",
        "alpha-docs",
        False,
    )
    check(
        "W-RELEASE",
        "Exact immutable workload subject can publish",
        WORKLOAD,
        "publish",
        "alpha-artifacts",
        True,
        mfa=False,
        amr=["workload"],
    )
    check(
        "W-READ-DENIED",
        "Workload cannot inherit human read privileges",
        WORKLOAD,
        "read",
        "alpha-artifacts",
        False,
        amr=["workload"],
    )
    check(
        "W-FORK",
        "Fork or repository change is not trusted",
        WORKLOAD.replace("@202", "@303"),
        "publish",
        "alpha-artifacts",
        False,
        amr=["workload"],
    )
    check(
        "W-BRANCH",
        "Unexpected branch is not trusted",
        WORKLOAD.replace("/main", "/feature"),
        "publish",
        "alpha-artifacts",
        False,
        amr=["workload"],
    )
    check(
        "T-AUDIENCE",
        "A token for a different service is rejected",
        "engineer-alpha",
        "read",
        "alpha-docs",
        False,
        aud="other-service",
    )
    check(
        "T-AUD-LIST",
        "Ambiguous audience lists are rejected",
        "engineer-alpha",
        "read",
        "alpha-docs",
        False,
        aud=["cloud-identity-access-lab", "other"],
    )
    check(
        "T-ISSUER",
        "Wrong issuer is rejected even with a valid local signature",
        "engineer-alpha",
        "read",
        "alpha-docs",
        False,
        iss="https://untrusted.example.invalid",
    )
    check(
        "T-ID-TOKEN",
        "ID-token substitution is rejected",
        "engineer-alpha",
        "read",
        "alpha-docs",
        False,
        token_use="id",
    )
    check(
        "T-EXPIRED",
        "Expiry boundary denies without leeway",
        "engineer-alpha",
        "read",
        "alpha-docs",
        False,
        exp=NOW,
    )
    check(
        "T-NOT-YET",
        "Future not-before time is rejected",
        "engineer-alpha",
        "read",
        "alpha-docs",
        False,
        nbf=NOW + 1,
    )
    check(
        "T-LONG-LIVED",
        "Credential lifetime cannot exceed 300 seconds",
        "engineer-alpha",
        "read",
        "alpha-docs",
        False,
        exp=NOW + 301,
    )
    check(
        "T-CLAIMED-ROLE",
        "Unrecognized role claim cannot grant privileges",
        "engineer-alpha",
        "read",
        "alpha-docs",
        False,
        role="admin",
    )
    check(
        "T-OTHER-KEY",
        "Another issuer key cannot sign a trusted identity",
        "engineer-alpha",
        "read",
        "alpha-docs",
        False,
        token=FixtureIssuer().issue("engineer-alpha", NOW),
    )
    check(
        "T-MALFORMED",
        "Malformed credential fails closed",
        "engineer-alpha",
        "read",
        "alpha-docs",
        False,
        token="not-a-token",
    )
    first = issuer.issue("engineer-alpha", NOW)
    peer = issuer.issue("engineer-alpha", NOW)
    verifier.revoke(verifier.verify(first, NOW))
    check(
        "R-REVOKED",
        "Revoked credential is rejected immediately",
        "engineer-alpha",
        "read",
        "alpha-docs",
        False,
        token=first,
    )
    check(
        "R-PEER",
        "Revoking one credential preserves a separate session",
        "engineer-alpha",
        "read",
        "alpha-docs",
        True,
        token=peer,
    )
    verifier.disable("engineer-alpha")
    check(
        "R-DISABLED",
        "Disabling a subject invalidates its remaining credentials",
        "engineer-alpha",
        "read",
        "alpha-docs",
        False,
        token=peer,
    )
    check(
        "E-START",
        "Two-approver emergency privilege starts exactly on time",
        "responder-alpha",
        "rotate",
        "alpha-keys",
        True,
    )
    check(
        "E-NO-MFA",
        "Emergency privilege still requires fresh MFA",
        "responder-alpha",
        "rotate",
        "alpha-keys",
        False,
        mfa=False,
    )
    check(
        "E-LAST-SECOND",
        "Emergency grant is live before expiry",
        "responder-alpha",
        "rotate",
        "alpha-keys",
        True,
        now=NOW + 59,
    )
    check(
        "E-EXPIRED",
        "Emergency privilege ends exactly at expiry",
        "responder-alpha",
        "rotate",
        "alpha-keys",
        False,
        now=NOW + 60,
    )
    # Backward trusted time must fail closed rather than revive the expired privilege.
    check(
        "T-CLOCK-ROLLBACK",
        "Backward clock is rejected",
        "responder-alpha",
        "read",
        "alpha-docs",
        False,
        now=NOW + 59,
    )
    try:
        source = (
            subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=ROOT, stderr=subprocess.DEVNULL
            )
            .decode()
            .strip()
        )
    except subprocess.CalledProcessError:
        source = "uncommitted"
    return validate({"schema": 1, "synthetic": True, "source": source, "cases": rows})
