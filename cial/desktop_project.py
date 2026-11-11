"""Actual signed-request, credential-lifecycle and fixed-OPA entitlement workflows for the native app. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 87
# variable: PRODUCT — line 88
# variable: PROFILE — line 88
# variable: TITLE — line 89
# variable: VERSION — line 89
# variable: COLUMNS — line 90
# variable: RESOURCES — line 96
# variable: RESOURCE_LIMITS — line 110
# variable: MODES — line 111
# variable: REVIEW_MODE — line 116
# variable: CHOICES — line 117
# variable: FIELDS — line 135
# variable: ACTIVE_FIELDS — line 159
# variable: SCENARIOS — line 173
# variable: HELP — line 183
# definition: scenario — line 190
# parameter: name — line 190
# variable: index — line 194
# variable: value — line 195
# definition: clock — line 229
# parameter: value — line 229
# definition: text_bundle — line 240
# parameter: value — line 240
# variable: raw — line 242
# variable: page — line 243
# definition: analyze — line 251
# parameter: parameters — line 252
# parameter: stage — line 252
# parameter: state — line 252
# variable: mode — line 255
# variable: identity — line 259
# variable: report — line 260
# variable: matching — line 265
# variable: row — line 265
# variable: now — line 274
# variable: value — line 276
# variable: path — line 285
# variable: selected — line 288
# variable: subject — line 289
# variable: action — line 290
# variable: resource — line 290
# variable: expected — line 291
# variable: lifecycle — line 291
# variable: profile — line 291
# variable: registry — line 302
# variable: issuer — line 304
# variable: verifier — line 305
# variable: issued — line 310
# variable: asserted — line 311
# variable: credential — line 314
# variable: decision — line 327
# variable: value — line 330
# variable: row — line 353
# definition: views — line 361
# parameter: files — line 361
# variable: value — line 364
# variable: row — line 368
# variable: value — line 372
# variable: key — line 380
# variable: row — line 380
# variable: value — line 390
# variable: key — line 394
# variable: row — line 394
# definition: cells — line 399
# parameter: row — line 399
# variable: observed — line 401
# END CODE MAP

from __future__ import annotations

import hashlib
import html
import sys
from pathlib import Path
from typing import Any

from . import evidence, recertify, scenarios
from .desktop_io import Rejected, canonical, json_value, read_bytes
from .desktop_state import Workspace, package_identity
from .engine import ACTIONS, Engine
from .engine import RESOURCES as POLICY_RESOURCES
from .identity import FixtureIssuer, Verifier
from .tooling import executable

ROOT = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[1]))
PRODUCT, PROFILE = "cloud-identity-access-lab", "CloudIdentityAccessLab"
TITLE, VERSION = "Cloud Identity Access Workbench", "1.1.1"
COLUMNS = (
    "Subject / scenario",
    "Request / scope",
    "Observed reason",
    "Decision / change",
)
RESOURCES = (
    "policy/access.rego",
    "policy/registry.json",
    "examples/desktop/proposed-registry.json",
    "tools.lock.json",
    ".tools/opa.exe",
    "licenses/OPA-LICENSE.txt",
    "licenses/GO-LICENSE.txt",
    "licenses/opa-linked-modules.txt",
    "licenses/OPA-THIRD-PARTY.txt",
    "notices.txt",
    "app.ico",
    "python314.dll",
)
RESOURCE_LIMITS = {".tools/opa.exe": 128 * 1024 * 1024}
MODES = (
    "Evaluate signed synthetic request",
    "Compare proposed entitlements",
    "Run original 31-case assurance suite",
)
REVIEW_MODE = None
CHOICES = {
    "action": tuple(sorted(ACTIONS)),
    "resource": tuple(sorted(POLICY_RESOURCES)),
    "mfa": (
        "fresh issuer assertion",
        "password-only assertion",
        "stale issuer assertion",
    ),
    "lifecycle": (
        "valid",
        "expired",
        "revoked",
        "subject disabled",
        "wrong signing key",
        "clock rollback",
    ),
    "expected": ("allow", "deny"),
}
FIELDS = (
    ("registry", "Authorized synthetic registry JSON (data only; fixed Rego)", "file"),
    (
        "subject",
        "Synthetic subject or exact workload identifier (not a real login)",
        "text",
    ),
    ("action", "Requested action", "choice"),
    ("resource", "Requested synthetic resource", "choice"),
    (
        "as_of",
        "Explicit evaluation time (integer Unix seconds, not wall clock)",
        "text",
    ),
    ("mfa", "Issuer-attested MFA profile (no real challenge/enrollment)", "choice"),
    ("lifecycle", "Controlled credential lifecycle / signature condition", "choice"),
    (
        "expected",
        "Expected decision (regression oracle, never a permission grant)",
        "choice",
    ),
    ("baseline", "Earlier trusted synthetic registry JSON", "file"),
    ("candidate", "Proposed trusted synthetic registry JSON (never applied)", "file"),
)
ACTIVE_FIELDS = {
    MODES[0]: (
        "registry",
        "subject",
        "action",
        "resource",
        "as_of",
        "mfa",
        "lifecycle",
        "expected",
    ),
    MODES[1]: ("baseline", "candidate", "as_of"),
    MODES[2]: (),
}
SCENARIOS = (
    "Human publication with fresh MFA assertion",
    "Human publication without MFA",
    "Cross-tenant access stays denied",
    "Emergency rotation starts on time",
    "Emergency rotation expires exactly",
    "Revoked credential stays denied",
    "Proposed tenant move and publisher removal",
    "Original 31-case signature/policy suite",
)
HELP = """Review synthetic signed identities through real Ed25519 verification and the pinned native Open Policy Agent.
Select your closed-schema synthetic registry, subject, request, explicit as-of time, MFA assertion and controlled lifecycle condition. Expected allow/deny is only a regression oracle. It cannot grant access. Keys and signed tokens are generated in memory, never accepted from a user account or written into reports.
Compare two authorized synthetic registries to see true permission gains/losses, full candidate entitlements, exact policy/input hashes and emergency expiry. No registry or cloud setting is applied. The original 31-case assurance suite keeps its original fixed clock/registry and independent expected outcomes.
Fixed local Rego receives only verified context, never token bytes or caller scripts. OPA executes a bounded fixed argv, not a server or shell; provider/Python/Node environment is not passed to it. No AWS calls, cloud credentials, MFA enrollment, external identity exchange, Terraform apply or live enforcement occurs.
This owner-local plaintext lab is not production authentication, a complete AWS IAM evaluator or proof of real MFA. Search filters current saved evidence. Original TypeScript browser/CLI and provider-free Terraform tests remain separate supported interfaces."""


def scenario(name: str) -> dict[str, str]:
    """Prepare ordinary project controls without signing, evaluating, applying or saving anything automatically."""
    if name not in SCENARIOS:
        raise Rejected("unknown_prepared_scenario")
    index = SCENARIOS.index(name)
    value = {
        "mode": MODES[0],
        "registry": str(ROOT / "policy/registry.json"),
        "subject": "engineer-alpha",
        "action": "publish",
        "resource": "alpha-artifacts",
        "as_of": "2000000000",
        "mfa": CHOICES["mfa"][0],
        "lifecycle": "valid",
        "expected": "allow",
        "baseline": str(ROOT / "policy/registry.json"),
        "candidate": str(ROOT / "examples/desktop/proposed-registry.json"),
    }
    if index == 1:
        value.update(mfa=CHOICES["mfa"][1], expected="deny")
    elif index == 2:
        value.update(action="read", resource="beta-docs", expected="deny")
    elif index in (3, 4):
        value.update(
            subject="responder-alpha",
            action="rotate",
            resource="alpha-keys",
            as_of="2000000060" if index == 4 else "2000000000",
            expected="deny" if index == 4 else "allow",
        )
    elif index == 5:
        value.update(lifecycle="revoked", expected="deny")
    elif index == 6:
        value["mode"] = MODES[1]
    elif index == 7:
        value["mode"] = MODES[2]
    return value


def clock(value: str) -> int:
    """Reject fractional, signed, Unicode-digit and out-of-domain clocks rather than silently use current time."""
    if (
        not value.isascii()
        or not value.isdecimal()
        or not 0 <= int(value) <= 4102444500
    ):
        raise Rejected("evaluation_clock")
    return int(value)


def text_bundle(value: dict[str, Any]) -> dict[str, bytes]:
    """Retain literal metadata-only observed decisions and an inert escaped review copy, never credentials."""
    raw = canonical(value)
    page = (
        "<!doctype html><html lang='en'><meta charset='utf-8'><meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; base-uri 'none'; form-action 'none'\"><title>Signed-context review — Jason Stys</title><h1>Signed-context review</h1><p>Synthetic fixed-policy evidence, not live-cloud authorization.</p><pre>"
        + html.escape(raw.decode())
        + "</pre></html>"
    )
    return {"result.json": raw, "result.html": page.encode()}


def analyze(
    state: Workspace, parameters: dict[str, str], stage: Path
) -> tuple[str, str, dict[str, bytes]]:
    """Invoke actual signatures/OPA or original comparison/suite; no input selects a program, Rego source or network URL."""
    mode = parameters.get("mode", "")
    if mode not in MODES:
        raise Rejected("unsupported_offline_operation")
    if mode == MODES[2]:
        identity = package_identity(ROOT, PRODUCT, VERSION, RESOURCES, RESOURCE_LIMITS)
        report = scenarios.run(
            source=identity["source"]
            if identity["source"] != "development"
            else "uncommitted"
        )
        matching = sum(evidence.passed(row) for row in report["cases"])
        return (
            mode,
            f"{matching}/{len(report['cases'])} original signature/policy oracles match; fixed synthetic clock",
            {
                "assurance.json": evidence.canonical(report),
                "assurance.html": evidence.render(report).encode(),
            },
        )
    now = clock(parameters.get("as_of", ""))
    if mode == MODES[1]:
        value = recertify.compare(
            Path(parameters["baseline"]), Path(parameters["candidate"]), now
        )
        recertify.save(value, stage / "review")
        return (
            mode,
            f"{len(value['permission_gains'])} gains / {len(value['permission_losses'])} losses across {value['contexts_evaluated']} signed contexts; proposed registry not applied",
            {
                path.name: read_bytes(path, 32 * 1024 * 1024)
                for path in (stage / "review").iterdir()
            },
        )
    selected = recertify.registry(Path(parameters["registry"]))
    subject = recertify.token(parameters["subject"], subject=True)
    action, resource = parameters["action"], parameters["resource"]
    profile, lifecycle, expected = (
        parameters["mfa"],
        parameters["lifecycle"],
        parameters["expected"],
    )
    if (
        profile not in CHOICES["mfa"]
        or lifecycle not in CHOICES["lifecycle"]
        or expected not in CHOICES["expected"]
    ):
        raise Rejected("unsupported_credential_profile")
    registry = stage / "validated-registry.json"
    registry.write_bytes(recertify.encoded(selected))
    issuer = FixtureIssuer()
    verifier = Verifier(
        FixtureIssuer().public_key
        if lifecycle == "wrong signing key"
        else issuer.public_key
    )
    issued = now - 120 if lifecycle == "expired" else now
    asserted = now - 300 if profile == CHOICES["mfa"][2] else issued
    if issued < 0 or asserted < 0:
        raise Rejected("credential_profile_clock")
    credential = issuer.issue(
        subject,
        issued,
        mfa=profile != CHOICES["mfa"][1],
        auth_time=asserted,
        exp=now if lifecycle == "expired" else now + 120,
    )
    if lifecycle == "revoked":
        verifier.revoke(verifier.verify(credential, now))
    elif lifecycle == "subject disabled":
        verifier.disable(subject)
    elif lifecycle == "clock rollback":
        verifier.verify(credential, now)
    decision = Engine(executable("opa"), verifier, registry).decide(
        credential, now - 1 if lifecycle == "clock rollback" else now, action, resource
    )
    value = {
        "schema": 1,
        "kind": "synthetic_signed_request",
        "as_of": now,
        "registry_sha256": hashlib.sha256(recertify.encoded(selected)).hexdigest(),
        "policy_sha256": hashlib.sha256(
            read_bytes(ROOT / "policy/access.rego", 65536)
        ).hexdigest(),
        "records": [
            {
                "subject": subject,
                "action": action,
                "resource": resource,
                "credential_profile": lifecycle,
                "mfa_assertion": profile,
                "expected_allow": expected == "allow",
                "observed_allow": decision["allow"],
                "reason": decision["reason"],
                "oracle_match": (expected == "allow") == decision["allow"],
            }
        ],
        "scope": "Local synthetic issuer/signature and fixed Rego decision only. No real user authentication, MFA challenge or cloud authorization; token/key/claims omitted.",
    }
    row = value["records"][0]
    return (
        mode,
        f"Observed {'allow' if row['observed_allow'] else 'deny'} / {row['reason']}; expected {expected}; oracle {'matches' if row['oracle_match'] else 'MISMATCH'}",
        text_bundle(value),
    )


def views(files: dict[str, bytes]) -> dict[str, list[dict[str, Any]]]:
    """Expose original decisions and actual comparison denominators without issuer keys, tokens or raw claims."""
    if "assurance.json" in files:
        value = json_value(files["assurance.json"])
        return {
            "Original 31-case decisions": value["cases"],
            "Expected-outcome regressions": [
                row for row in value["cases"] if not evidence.passed(row)
            ],
        }
    if "entitlements.json" in files:
        value = json_value(files["entitlements.json"])
        return {
            "Permission gains": value["permission_gains"],
            "Permission losses": value["permission_losses"],
            "Candidate signed-context entitlements": value["candidate_entitlements"],
            "Emergency and exact review scope": [
                {
                    key: row
                    for key, row in value.items()
                    if key
                    not in (
                        "permission_gains",
                        "permission_losses",
                        "candidate_entitlements",
                    )
                }
            ],
        }
    value = json_value(files["result.json"])
    return {
        "Observed signed request": value["records"],
        "Exact input identities and scope": [
            {key: row for key, row in value.items() if key != "records"}
        ],
    }


def cells(row: dict[str, Any]) -> tuple[str, str, str, str]:
    """Keep actual decision/reason and gains/losses visible; full selected context remains copyable."""
    observed = row.get(
        "observed_allow", row.get("observed", row.get("candidate_allow"))
    )
    return (
        str(row.get("subject", row.get("principal", row.get("id", "Review scope")))),
        str(row.get("action", "counts and expiry"))
        + " / "
        + str(row.get("resource", "fixed policy")),
        str(
            row.get(
                "reason",
                "Fresh issuer MFA"
                if row.get("mfa_fresh") is True
                else "No fresh issuer MFA"
                if row.get("mfa_fresh") is False
                else "inspect exact context",
            )
        ),
        "MISMATCH"
        if row.get("oracle_match") is False
        else str(observed)
        if observed is not None
        else str(row.get("contexts_evaluated", "metadata")),
    )
