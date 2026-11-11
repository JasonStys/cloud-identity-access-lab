"""Real signed-request/native-OPA desktop oracles, registry changes and secret omission. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: state — line 90
# parameter: tmp_path — line 90
# variable: value — line 92
# definition: run — line 99
# parameter: changes — line 99
# parameter: index — line 99
# parameter: state — line 99
# parameter: tmp_path — line 99
# variable: parameters — line 101
# variable: temporary — line 102
# variable: files — line 103
# variable: kind — line 103
# variable: summary — line 103
# definition: test_actual_signed_requests_mfa_tenant_expiry_and_revocation — line 119
# parameter: allowed — line 120
# parameter: index — line 120
# parameter: reason — line 120
# parameter: state — line 120
# parameter: tmp_path — line 120
# variable: files — line 123
# variable: summary — line 123
# variable: value — line 124
# variable: raw — line 135
# definition: test_controlled_invalid_credentials_are_rejected_not_successful_policy_calls — line 142
# parameter: condition — line 143
# parameter: state — line 143
# parameter: tmp_path — line 143
# variable: _ — line 146
# variable: files — line 146
# definition: test_user_selected_registry_changes_real_outcome_without_mutation_or_oracle_rewrite — line 153
# parameter: state — line 154
# parameter: tmp_path — line 154
# variable: source — line 157
# variable: value — line 158
# variable: original — line 161
# variable: files — line 162
# variable: summary — line 162
# variable: row — line 163
# variable: _ — line 170
# variable: files — line 170
# definition: test_original_entitlement_review_preserves_true_denominator_and_emergency_window — line 174
# parameter: state — line 175
# parameter: tmp_path — line 175
# variable: files — line 178
# variable: summary — line 178
# variable: value — line 179
# variable: views — line 187
# variable: row — line 192
# definition: test_original_assurance_suite_runs_without_git_and_carries_its_actual_source_identity — line 195
# parameter: monkeypatch — line 196
# parameter: state — line 196
# parameter: tmp_path — line 196
# parameter: _args — line 202
# variable: files — line 204
# variable: summary — line 204
# variable: value — line 205
# variable: row — line 207
# definition: test_invalid_inputs_do_not_replace_accepted_evidence — line 231
# parameter: changes — line 231
# parameter: state — line 231
# parameter: tmp_path — line 231
# variable: _ — line 233
# variable: first — line 233
# definition: test_unknown_scenario_and_unix_epoch_are_handled_explicitly — line 239
# definition: test_expired_profile_uses_previously_valid_credential_not_zero_lifetime_invalidity — line 246
# parameter: state — line 247
# parameter: tmp_path — line 247
# variable: issuer — line 250
# variable: credential — line 251
# variable: verifier — line 252
# variable: _ — line 256
# variable: files — line 256
# END CODE MAP

import json
import tempfile
from pathlib import Path

import pytest

from cial import desktop_project as project
from cial.desktop_io import Rejected, json_value
from cial.desktop_state import Workspace
from cial.identity import FixtureIssuer, Verifier


@pytest.fixture
def state(tmp_path):
    """Own a fresh marked local history, never a normal profile or live identity account."""
    value = Workspace(tmp_path / "profile", project.PRODUCT, project.ROOT)
    try:
        yield value
    finally:
        value.close()


def run(state, tmp_path, index=0, **changes):
    """Execute actual crypto/OPA rather than mock a policy outcome; retain the exact resulting bundle."""
    parameters = project.scenario(project.SCENARIOS[index]) | changes
    with tempfile.TemporaryDirectory(dir=tmp_path) as temporary:
        kind, summary, files = project.analyze(state, parameters, Path(temporary))
    state.save(kind, summary, parameters, files)
    return files, summary


@pytest.mark.parametrize(
    "index,allowed,reason",
    [
        (0, True, "allowed"),
        (1, False, "policy_denied"),
        (2, False, "policy_denied"),
        (3, True, "allowed"),
        (4, False, "policy_denied"),
        (5, False, "credential_rejected"),
    ],
)
def test_actual_signed_requests_mfa_tenant_expiry_and_revocation(
    state, tmp_path, index, allowed, reason
):
    """Independent expected outcomes include the exact emergency expiry and genuine post-signature revocation."""
    files, summary = run(state, tmp_path, index)
    value = json_value(files["result.json"])
    assert value["records"][0]["observed_allow"] is allowed
    assert (
        value["records"][0]["reason"] == reason
        and value["records"][0]["oracle_match"] is True
    )
    assert (
        "matches" in summary
        and project.views(files)
        and len(project.cells(value["records"][0])) == 4
    )
    for raw in files.values():
        assert b"eyJ" not in raw and b'"jti"' not in raw and b"PRIVATE KEY" not in raw


@pytest.mark.parametrize(
    "condition", ["expired", "subject disabled", "wrong signing key", "clock rollback"]
)
def test_controlled_invalid_credentials_are_rejected_not_successful_policy_calls(
    state, tmp_path, condition
):
    """A valid expected deny never hides a signature/expiry/revocation/clock failure as a policy allow."""
    files, _ = run(state, tmp_path, lifecycle=condition, expected="deny")
    assert (
        json_value(files["result.json"])["records"][0]["reason"]
        == "credential_rejected"
    )


def test_user_selected_registry_changes_real_outcome_without_mutation_or_oracle_rewrite(
    state, tmp_path
):
    """Removing publisher authority in an external data-only file genuinely denies and leaves the user's allow oracle mismatched."""
    source = tmp_path / "authorized.json"
    value = json.loads((project.ROOT / "policy/registry.json").read_bytes())
    value["lab"]["principals"]["engineer-alpha"]["actions"] = ["read"]
    source.write_text(json.dumps(value), encoding="utf8")
    original = source.read_bytes()
    files, summary = run(state, tmp_path, registry=str(source))
    row = json_value(files["result.json"])["records"][0]
    assert (
        row["observed_allow"] is False
        and row["oracle_match"] is False
        and "MISMATCH" in summary
    )
    assert "MISMATCH" in project.cells(row) and source.read_bytes() == original
    files, _ = run(state, tmp_path, mfa=project.CHOICES["mfa"][2], expected="deny")
    assert json_value(files["result.json"])["records"][0]["reason"] == "policy_denied"


def test_original_entitlement_review_preserves_true_denominator_and_emergency_window(
    state, tmp_path
):
    """The GUI invokes genuine signatures and all 256 native OPA decisions, not a static illustration of proposed permissions."""
    files, summary = run(state, tmp_path, 6)
    value = json_value(files["entitlements.json"])
    assert value["contexts_evaluated"] == 128 and value["native_decisions"] == 256
    assert len(value["permission_gains"]) == 4 and len(value["permission_losses"]) == 3
    assert (
        value["emergency"]["state"] == "active"
        and value["emergency"]["remaining_seconds"] == 60
    )
    assert "4 gains / 3 losses" in summary
    views = project.views(files)
    assert (
        len(views["Permission gains"]) == 4
        and views["Candidate signed-context entitlements"]
    )
    assert all(row["action"] != "delete" for row in value["candidate_entitlements"])


def test_original_assurance_suite_runs_without_git_and_carries_its_actual_source_identity(
    state, tmp_path, monkeypatch
):
    """Frozen applications need no Git installation; all 31 original crypto/policy negatives still execute."""
    monkeypatch.setattr(
        project,
        "package_identity",
        lambda *_args: {"source": "a" * 40, "source_dirty": False},
    )
    files, summary = run(state, tmp_path, 7)
    value = json_value(files["assurance.json"])
    assert value["source"] == "a" * 40 and len(value["cases"]) == 31
    assert all(row["expected"] is row["observed"] for row in value["cases"])
    assert (
        "31/31" in summary
        and project.views(files)["Expected-outcome regressions"] == []
    )
    assert project.cells({"observed": False, "principal": "synthetic"})[-1] == "False"


@pytest.mark.parametrize(
    "changes",
    [
        {"mode": "apply AWS credentials"},
        {"registry": "missing"},
        {"as_of": "NaN"},
        {"as_of": "1.5"},
        {"as_of": "-1"},
        {"as_of": "4102444501"},
        {"mfa": "real factor"},
        {"lifecycle": "network exchange"},
        {"expected": "approved"},
        {"action": "*"},
        {"resource": "../real"},
    ],
)
def test_invalid_inputs_do_not_replace_accepted_evidence(state, tmp_path, changes):
    """Missing files and invented controls fail explicitly rather than fall back to a prepared result or grant access."""
    first, _ = run(state, tmp_path)
    with pytest.raises((Rejected, OSError)):
        run(state, tmp_path, **changes)
    assert len(state.history()) == 1 and state.files(1) == first


def test_unknown_scenario_and_unix_epoch_are_handled_explicitly():
    """The as-of field supports the original nonnegative clock domain, including zero; it never guesses wall time."""
    assert project.clock("0") == 0
    with pytest.raises(Rejected):
        project.scenario("live cloud administrator")


def test_expired_profile_uses_previously_valid_credential_not_zero_lifetime_invalidity(
    state, tmp_path
):
    """A two-minute token is independently valid just before expiry and fails at expiry with no other profile defect."""
    issuer = FixtureIssuer()
    credential = issuer.issue("engineer-alpha", 1999999880)
    verifier = Verifier(issuer.public_key)
    assert verifier.verify(credential, 1999999999).expires == 2000000000
    with pytest.raises(Rejected):
        verifier.verify(credential, 2000000000)
    files, _ = run(state, tmp_path, lifecycle="expired", expected="deny")
    assert (
        json_value(files["result.json"])["records"][0]["reason"]
        == "credential_rejected"
    )
    with pytest.raises(Rejected, match="profile_clock"):
        run(state, tmp_path, lifecycle="expired", as_of="0")
