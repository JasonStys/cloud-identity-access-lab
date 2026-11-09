"""Real signed/native-policy recertification and closed trusted-registry boundaries. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: NOW — line 51
# definition: proposal — line 54
# parameter: tmp_path — line 54
# variable: data — line 56
# variable: path — line 59
# definition: test_native_permissions_and_cli — line 64
# parameter: capsys — line 65
# parameter: tmp_path — line 65
# variable: candidate — line 68
# variable: original — line 69
# variable: result — line 86
# variable: row — line 91
# variable: row — line 92
# variable: row — line 97
# variable: page — line 104
# variable: private — line 111
# definition: test_same_registry_and_expired_grant — line 119
# parameter: tmp_path — line 119
# variable: result — line 121
# variable: row — line 130
# definition: test_bad_registry — line 158
# parameter: bad — line 158
# parameter: tmp_path — line 158
# variable: data — line 160
# variable: lab — line 161
# variable: principal — line 162
# variable: grant — line 163
# variable: path — line 200
# definition: test_bytes_clocks_union_and_timeout — line 206
# parameter: tmp_path — line 206
# variable: source — line 208
# variable: data — line 224
# variable: number — line 225
# variable: candidate — line 230
# variable: proposed — line 235
# END CODE MAP

import copy
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from cial.__main__ import main
from cial.identity import Rejected
from cial.recertify import compare, registry, save

NOW = 2000000000


def proposal(tmp_path: Path) -> Path:
    """Create a trusted synthetic proposal moving a reader's tenant and removing publisher permission."""
    data = json.loads(Path("policy/registry.json").read_text())
    data["lab"]["principals"]["reader-beta"]["tenant"] = "alpha"
    data["lab"]["principals"]["engineer-alpha"]["actions"] = ["read"]
    path = tmp_path / "candidate.json"
    path.write_text(json.dumps(data))
    return path


def test_native_permissions_and_cli(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Genuine signatures and actual OPA reveal tenant gains and losses; no registry is applied or rewritten."""
    candidate = proposal(tmp_path)
    original = candidate.read_bytes()
    assert (
        main(
            [
                "recertify",
                "--baseline",
                "policy/registry.json",
                "--candidate",
                str(candidate),
                "--at",
                str(NOW),
                "--out",
                str(tmp_path / "review"),
            ]
        )
        == 1
    )
    result = json.loads((tmp_path / "review/entitlements.json").read_text())
    assert result["contexts_evaluated"] == 128 and result["native_decisions"] == 256
    assert (
        len(result["permission_gains"]) == 4 and len(result["permission_losses"]) == 3
    )
    assert {row["subject"] for row in result["permission_gains"]} == {"reader-beta"}
    assert {row["resource"] for row in result["permission_gains"]} == {
        "alpha-docs",
        "alpha-artifacts",
    }
    assert not any(
        row["action"] == "delete" for row in result["candidate_entitlements"]
    )
    assert (
        result["emergency"]["state"] == "active"
        and result["emergency"]["remaining_seconds"] == 60
    )
    assert candidate.read_bytes() == original
    page = (tmp_path / "review/entitlements.html").read_text()
    assert (
        "Content-Security-Policy" in page
        and "<script" not in page
        and "Jason Stys" in page
    )
    assert not any(
        private in json.dumps(result) for private in ("eyJ", "PRIVATE KEY", '"jti"')
    )
    assert "4 gains / 3 losses" in capsys.readouterr().out
    with pytest.raises(OSError):
        save(result, tmp_path / "review")
    assert main(["recertify"]) == 2


def test_same_registry_and_expired_grant(tmp_path: Path) -> None:
    """A completed emergency window remains expired, with no rotate entitlements or synthetic permission gain."""
    result = compare(
        Path("policy/registry.json"), Path("policy/registry.json"), NOW + 60
    )
    assert not result["review_required"]
    assert (
        result["emergency"]["state"] == "expired"
        and result["emergency"]["remaining_seconds"] == 0
    )
    assert not any(
        row["action"] == "rotate" for row in result["candidate_entitlements"]
    )
    save(result, tmp_path / "unchanged")


@pytest.mark.parametrize(
    "bad",
    [
        "extra",
        "synthetic",
        "principals",
        "resources",
        "subject",
        "kind",
        "tenant",
        "actions",
        "duplicate-action",
        "grant-subject",
        "grant-action",
        "grant-resource",
        "grant-time",
        "grant-bool",
        "approvers-count",
        "approver",
        "self",
        "duplicate-approver",
    ],
)
def test_bad_registry(bad: str, tmp_path: Path) -> None:
    """Malformed proposed authority never reaches native evaluation or changes a trusted registry."""
    data = json.loads(Path("policy/registry.json").read_text())
    lab = data["lab"]
    principal = lab["principals"]["engineer-alpha"]
    grant = lab["emergency"]
    if bad == "extra":
        data["extra"] = 1
    elif bad == "synthetic":
        lab["synthetic"] = False
    elif bad == "principals":
        lab["principals"] = {}
    elif bad == "resources":
        lab["resources"] = {}
    elif bad == "subject":
        lab["principals"]["<script>"] = principal
    elif bad == "kind":
        principal["kind"] = "admin"
    elif bad == "tenant":
        principal["tenant"] = "*"
    elif bad == "actions":
        principal["actions"] = ["*"]
    elif bad == "duplicate-action":
        principal["actions"] = ["read", "read"]
    elif bad == "grant-subject":
        grant["subject"] = "unknown"
    elif bad == "grant-action":
        grant["action"] = "delete"
    elif bad == "grant-resource":
        grant["resource"] = []
    elif bad == "grant-time":
        grant["expires"] = grant["starts"] + 901
    elif bad == "grant-bool":
        grant["starts"] = True
    elif bad == "approvers-count":
        grant["approvers"] = []
    elif bad == "approver":
        grant["approvers"][0] = "\n"
    elif bad == "self":
        grant["approvers"][0] = grant["subject"]
    else:
        grant["approvers"] = ["same", "same"]
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(data))
    with pytest.raises(Rejected):
        registry(path)


def test_bytes_clocks_union_and_timeout(tmp_path: Path) -> None:
    """Size and time budgets fail explicitly, never return a partial successful permission review."""
    source = tmp_path / "data.json"
    with pytest.raises(Rejected):
        registry(source)
    source.write_bytes(b" " * 65537)
    with pytest.raises(Rejected):
        registry(source)
    source.write_text('{"lab":{},"lab":{}}')
    with pytest.raises(Rejected):
        registry(source)
    with pytest.raises(Rejected):
        compare(Path("policy/registry.json"), Path("policy/registry.json"), True)
    with (
        patch("cial.recertify.time.monotonic", side_effect=[0, 121]),
        pytest.raises(Rejected, match="time_bound"),
    ):
        compare(Path("policy/registry.json"), Path("policy/registry.json"), NOW)
    data = json.loads(Path("policy/registry.json").read_text())
    for number in range(4):
        data["lab"]["principals"][f"extra{number}"] = copy.deepcopy(
            data["lab"]["principals"]["reader-beta"]
        )
    source.write_text(json.dumps(data))
    candidate = copy.deepcopy(data)
    del candidate["lab"]["principals"]["extra0"]
    candidate["lab"]["principals"]["new-extra"] = copy.deepcopy(
        candidate["lab"]["principals"]["reader-beta"]
    )
    proposed = tmp_path / "proposed.json"
    proposed.write_text(json.dumps(candidate))
    with pytest.raises(Rejected, match="context_bound"):
        compare(source, proposed, NOW)
