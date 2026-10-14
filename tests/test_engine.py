"""Jason Stys: real native OPA conformance plus isolated adapter-shape/time-out failure checks."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: test_actual_matrix — line 36
# variable: report — line 38
# variable: row — line 40
# variable: row — line 41
# variable: word — line 47
# definition: test_adapter_rejects_bad_evidence — line 72
# parameter: monkeypatch — line 72
# parameter: response — line 72
# variable: issuer — line 74
# parameter: args — line 75
# parameter: kwargs — line 75
# definition: test_closed_input_and_timeout — line 82
# parameter: monkeypatch — line 82
# variable: issuer — line 84
# variable: engine — line 85
# definition: timeout — line 95
# parameter: args — line 95
# parameter: kwargs — line 95
# END CODE MAP

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from cial.engine import Engine
from cial.evidence import passed
from cial.identity import FixtureIssuer, Rejected, Verifier
from cial.scenarios import NOW, run


def test_actual_matrix():
    """Execute the real Ed25519 verifier and installed native OPA for every public scenario."""
    report = run()
    assert len(report["cases"]) == 31
    assert all(passed(row) for row in report["cases"])
    assert {row["reason"] for row in report["cases"]} == {
        "allowed",
        "policy_denied",
        "credential_rejected",
    }
    assert not any(
        word in json.dumps(report) for word in ("eyJ", "PRIVATE KEY", '"jti"')
    )


@pytest.mark.parametrize(
    "response",
    [
        SimpleNamespace(returncode=1, stdout="private details"),
        SimpleNamespace(returncode=0, stdout="x" * 65537),
        SimpleNamespace(returncode=0, stdout="null"),
        SimpleNamespace(returncode=0, stdout="{}"),
        SimpleNamespace(returncode=0, stdout='{"result":[]}'),
        SimpleNamespace(
            returncode=0, stdout='{"result":[{"expressions":[{"value":null}]}]}'
        ),
        SimpleNamespace(
            returncode=0,
            stdout='{"result":[{"expressions":[{"value":{"allow":"true","reason":"allowed"}}]}]}',
        ),
        SimpleNamespace(
            returncode=0,
            stdout='{"result":[{"expressions":[{"value":{"allow":true,"reason":"policy_denied"}}]}]}',
        ),
    ],
)
def test_adapter_rejects_bad_evidence(monkeypatch, response):
    """Mocks test the subprocess boundary only; they do not count as native policy acceptance."""
    issuer = FixtureIssuer()
    monkeypatch.setattr("cial.engine.subprocess.run", lambda *args, **kwargs: response)
    with pytest.raises(Rejected, match="policy_engine_failed"):
        Engine(Path("trusted"), Verifier(issuer.public_key)).decide(
            issuer.issue("engineer-alpha", NOW), NOW, "read", "alpha-docs"
        )


def test_closed_input_and_timeout(monkeypatch):
    """Unknown access requests reject before subprocess; actual subprocess failures must not become allowed results."""
    issuer = FixtureIssuer()
    engine = Engine(Path("trusted"), Verifier(issuer.public_key))
    with pytest.raises(Rejected):
        engine.decide("bad", NOW, "*", "alpha-docs")
    with pytest.raises(Rejected):
        engine.decide("bad", NOW, "read", "../private")
    with pytest.raises(Rejected):
        engine.decide("bad", NOW, {}, "alpha-docs")
    with pytest.raises(Rejected):
        engine.decide("bad", NOW, "read", [])

    def timeout(*args, **kwargs):
        """Simulate only process timeout, not any authorization outcome."""
        raise subprocess.TimeoutExpired("trusted", 10)

    monkeypatch.setattr("cial.engine.subprocess.run", timeout)
    with pytest.raises(Rejected, match="policy_engine_failed"):
        engine.decide(issuer.issue("engineer-alpha", NOW), NOW, "read", "alpha-docs")
