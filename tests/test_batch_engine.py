"""Genuine all-256 single/batch OPA equivalence and independent fail-closed batch controls. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: NOW — line 108
# definition: CountingVerifier — line 111
# definition: __init__ — line 114
# parameter: key — line 114
# parameter: self — line 114
# attribute: calls — line 117
# definition: verify — line 119
# parameter: now — line 119
# parameter: self — line 119
# parameter: token — line 119
# attribute: calls — line 121
# definition: test_all_256_policy_decisions_match_original_single_calls_and_keep_256_signature_checks — line 125
# parameter: monkeypatch — line 126
# variable: root — line 129
# variable: source — line 130
# variable: subjects — line 131
# variable: issuer — line 132
# variable: requests — line 133
# variable: action — line 135
# variable: mfa — line 135
# variable: resource — line 135
# variable: subject — line 135
# variable: real_run — line 140
# variable: processes — line 141
# definition: observed — line 143
# parameter: argv — line 143
# parameter: kwargs — line 143
# variable: counts — line 149
# variable: durations — line 149
# variable: outputs — line 150
# variable: name — line 151
# variable: started — line 152
# variable: signatures — line 153
# variable: values — line 153
# variable: selected — line 154
# variable: verifier — line 155
# variable: evaluator — line 156
# variable: result — line 157
# variable: request — line 158
# variable: signatures — line 162
# variable: after — line 169
# variable: before — line 169
# variable: new — line 173
# variable: old — line 173
# variable: new — line 180
# variable: old — line 180
# variable: path — line 184
# variable: name — line 193
# definition: envelope — line 205
# parameter: rows — line 205
# definition: test_missing_reordered_duplicate_or_malformed_batch_cannot_return_partial_success — line 246
# parameter: monkeypatch — line 247
# parameter: rows — line 247
# variable: issuer — line 250
# variable: token — line 251
# parameter: _args — line 255
# parameter: _kwargs — line 255
# definition: test_rejected_tokens_keep_original_positions_and_no_token_reaches_native_batch — line 265
# parameter: monkeypatch — line 266
# variable: issuer — line 269
# variable: valid — line 270
# variable: verifier — line 271
# variable: seen — line 272
# definition: observe — line 274
# parameter: argv — line 274
# parameter: kwargs — line 274
# variable: contexts — line 276
# variable: evaluator — line 288
# variable: rows — line 289
# definition: test_closed_batch_input_and_subprocess_failure_guards — line 316
# parameter: defect — line 316
# parameter: monkeypatch — line 316
# variable: issuer — line 318
# variable: token — line 319
# variable: request — line 320
# variable: requests — line 321
# definition: fail — line 333
# parameter: _args — line 333
# parameter: _kwargs — line 333
# variable: stdout — line 337
# definition: test_valid_first_native_value_cannot_hide_additional_results — line 354
# parameter: extra — line 354
# parameter: monkeypatch — line 354
# variable: issuer — line 356
# variable: token — line 357
# variable: response — line 358
# parameter: _args — line 368
# parameter: _kwargs — line 368
# END CODE MAP

import json
import subprocess
import time
from itertools import product
from pathlib import Path
from types import SimpleNamespace

import pytest

from cial import engine as module
from cial.engine import ACTIONS, RESOURCES, Engine
from cial.identity import FixtureIssuer, Rejected, Verifier
from cial.recertify import registry
from cial.tooling import executable

NOW = 2000000000


class CountingVerifier(Verifier):
    """Count actual inherited cryptographic verifications without storing tokens, claims or keys in evidence."""

    def __init__(self, key):
        """Retain the ordinary pinned verifier and an aggregate counter only."""
        super().__init__(key)
        self.calls = 0

    def verify(self, token, now):
        """Every observed batch item still invokes the genuine signature/profile implementation."""
        self.calls += 1
        return super().verify(token, now)


def test_all_256_policy_decisions_match_original_single_calls_and_keep_256_signature_checks(
    monkeypatch,
):
    """Both registries, four subjects, both MFA states, four actions and four resources use actual native OPA on both paths."""
    root = Path(__file__).resolve().parents[1]
    source = root / "policy/registry.json"
    subjects = sorted(registry(source)["lab"]["principals"])
    issuer = FixtureIssuer()
    requests = [
        (issuer.issue(subject, NOW, mfa=mfa), NOW, action, resource)
        for subject, mfa, action, resource in product(
            subjects, (False, True), sorted(ACTIONS), sorted(RESOURCES)
        )
    ]
    assert len(requests) == 128
    real_run = module.subprocess.run
    processes = []

    def observed(argv, **kwargs):
        """Observe the real process boundary while forwarding every call unchanged to native OPA."""
        processes.append("batch" if argv[-1] == module.BATCH_QUERY else "single")
        return real_run(argv, **kwargs)

    monkeypatch.setattr(module.subprocess, "run", observed)
    counts, durations = {}, {}
    outputs = []
    for name in ("single", "batch"):
        started = time.perf_counter()
        values, signatures = [], 0
        for selected in (source, root / "examples/desktop/proposed-registry.json"):
            verifier = CountingVerifier(issuer.public_key)
            evaluator = Engine(executable("opa"), verifier, selected)
            result = (
                [evaluator.decide(*request) for request in requests]
                if name == "single"
                else evaluator.decide_many(requests)
            )
            signatures += verifier.calls
            values.append(result)
        counts[name] = signatures
        durations[name] = round((time.perf_counter() - started) * 1000, 3)
        outputs.append(values)
    assert outputs[0] == outputs[1] and counts == {"single": 256, "batch": 256}
    assert processes.count("single") == 256 and processes.count("batch") == 2
    before, after = outputs[1]
    assert (
        sum(
            new["allow"] and not old["allow"]
            for old, new in zip(before, after, strict=True)
        )
        == 4
    )
    assert (
        sum(
            old["allow"] and not new["allow"]
            for old, new in zip(before, after, strict=True)
        )
        == 3
    )
    path = root / "out/batch-differential.json"
    path.parent.mkdir(exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "passed": True,
                "decisions_per_path": 256,
                "signature_checks": counts,
                "actual_processes": {
                    name: processes.count(name) for name in ("single", "batch")
                },
                "elapsed_ms": durations,
                "scope": "Diagnostic same-test Windows single/batch comparison, not a production SLO or worst-case performance guarantee.",
            },
            indent=2,
        )
        + "\n",
        encoding="utf8",
    )


def envelope(rows):
    """Construct the public native return wrapper independently of production parsing."""
    return json.dumps({"result": [{"expressions": [{"value": rows}]}]})


@pytest.mark.parametrize(
    "rows",
    [
        None,
        [],
        [{"index": 0, "decision": {"allow": True, "reason": "allowed"}}],
        [
            {"index": 0, "decision": {"allow": True, "reason": "allowed"}},
            {"index": 0, "decision": {"allow": False, "reason": "policy_denied"}},
        ],
        [
            {"index": 1, "decision": {"allow": True, "reason": "allowed"}},
            {"index": 0, "decision": {"allow": False, "reason": "policy_denied"}},
        ],
        [
            {"index": False, "decision": {"allow": True, "reason": "allowed"}},
            {"index": 1, "decision": {"allow": False, "reason": "policy_denied"}},
        ],
        [
            {"index": 0, "decision": {"allow": 1, "reason": "allowed"}},
            {"index": 1, "decision": {"allow": False, "reason": "policy_denied"}},
        ],
        [
            {"index": 0, "decision": {"allow": True, "reason": "policy_denied"}},
            {"index": 1, "decision": {"allow": False, "reason": "policy_denied"}},
        ],
        [
            {
                "index": 0,
                "decision": {"allow": True, "reason": "allowed"},
                "extra": True,
            },
            {"index": 1, "decision": {"allow": False, "reason": "policy_denied"}},
        ],
    ],
)
def test_missing_reordered_duplicate_or_malformed_batch_cannot_return_partial_success(
    monkeypatch, rows
):
    """Count, positional indexes, exact keys and boolean/reason agreement are independent acceptance invariants."""
    issuer = FixtureIssuer()
    token = issuer.issue("engineer-alpha", NOW)
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout=envelope(rows)),
    )
    with pytest.raises(Rejected, match="policy_engine_failed"):
        Engine(
            Path("fixed executable with spaces"), Verifier(issuer.public_key)
        ).decide_many(
            [(token, NOW, "read", "alpha-docs"), (token, NOW, "read", "beta-docs")]
        )


def test_rejected_tokens_keep_original_positions_and_no_token_reaches_native_batch(
    monkeypatch,
):
    """Invalid credentials are individually verified and denied; valid-context indexes cannot slide onto their input positions."""
    issuer = FixtureIssuer()
    valid = issuer.issue("engineer-alpha", NOW)
    verifier = CountingVerifier(issuer.public_key)
    seen = []

    def observe(argv, **kwargs):
        """Only the one verified context reaches the authored native query, never either signed/malformed token."""
        contexts = json.loads(kwargs["input"])
        assert argv[-1] == module.BATCH_QUERY and len(contexts) == 1
        assert valid not in kwargs["input"] and "bad-token" not in kwargs["input"]
        seen.append(contexts)
        return SimpleNamespace(
            returncode=0,
            stdout=envelope(
                [{"index": 0, "decision": {"allow": True, "reason": "allowed"}}]
            ),
        )

    monkeypatch.setattr(module.subprocess, "run", observe)
    evaluator = Engine(Path("pinned"), verifier)
    rows = evaluator.decide_many(
        [("bad-token", NOW, "read", "alpha-docs"), (valid, NOW, "read", "alpha-docs")]
    )
    assert rows == [
        {"allow": False, "reason": "credential_rejected"},
        {"allow": True, "reason": "allowed"},
    ]
    assert verifier.calls == 2 and len(seen) == 1
    assert evaluator.decide_many([("bad-token", NOW, "read", "alpha-docs")]) == [
        {"allow": False, "reason": "credential_rejected"}
    ]
    assert len(seen) == 1


@pytest.mark.parametrize(
    "defect",
    [
        "empty",
        "many",
        "shape",
        "action",
        "nonzero",
        "too-long",
        "timeout",
        "duplicate-json",
    ],
)
def test_closed_batch_input_and_subprocess_failure_guards(monkeypatch, defect):
    """No invented query, oversized batch, process fault, duplicate JSON or timeout becomes a measured allow list."""
    issuer = FixtureIssuer()
    token = issuer.issue("engineer-alpha", NOW)
    request = (token, NOW, "read", "alpha-docs")
    requests = (
        []
        if defect == "empty"
        else [request] * 257
        if defect == "many"
        else [(token, NOW)]
        if defect == "shape"
        else [(token, NOW, "*", "alpha-docs")]
        if defect == "action"
        else [request]
    )

    def fail(*_args, **_kwargs):
        """Inject only native-boundary faults, never a substitute successful policy decision."""
        if defect == "timeout":
            raise subprocess.TimeoutExpired("fixed-opa", 10)
        stdout = (
            "x" * 65537
            if defect == "too-long"
            else '{"result":[],"result":[]}'
            if defect == "duplicate-json"
            else "{}"
        )
        return SimpleNamespace(
            returncode=1 if defect == "nonzero" else 0, stdout=stdout
        )

    monkeypatch.setattr(module.subprocess, "run", fail)
    with pytest.raises(Rejected):
        Engine(Path("pinned"), Verifier(issuer.public_key)).decide_many(requests)


@pytest.mark.parametrize("extra", ["results", "expressions"])
def test_valid_first_native_value_cannot_hide_additional_results(monkeypatch, extra):
    """The authored one-expression query requires exactly one result, not a selected apparently valid prefix."""
    issuer = FixtureIssuer()
    token = issuer.issue("engineer-alpha", NOW)
    response = json.loads(
        envelope([{"index": 0, "decision": {"allow": True, "reason": "allowed"}}])
    )
    if extra == "results":
        response["result"].append({"expressions": [{"value": None}]})
    else:
        response["result"][0]["expressions"].append({"value": None})
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0, stdout=json.dumps(response)
        ),
    )
    with pytest.raises(Rejected, match="policy_engine_failed"):
        Engine(Path("pinned"), Verifier(issuer.public_key)).decide_many(
            [(token, NOW, "read", "alpha-docs")]
        )
