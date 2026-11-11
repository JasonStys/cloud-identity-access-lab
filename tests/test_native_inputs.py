"""Independent real descriptor, child-environment and exact native-resource boundaries. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: test_actual_input_bytes_hash_limits_and_changed_same_descriptor — line 59
# parameter: monkeypatch — line 60
# parameter: tmp_path — line 60
# variable: selected — line 63
# variable: function — line 67
# variable: actual — line 74
# variable: count — line 75
# definition: mutate — line 77
# parameter: descriptor — line 77
# variable: count — line 80
# variable: stream — line 82
# definition: test_hardlink_and_descriptor_type_swap_are_refused — line 91
# parameter: monkeypatch — line 91
# parameter: tmp_path — line 91
# variable: selected — line 93
# variable: alias — line 95
# variable: actual — line 100
# parameter: descriptor — line 104
# definition: test_regular_registry_swapped_to_fifo_cannot_block_child — line 114
# parameter: tmp_path — line 114
# variable: source — line 116
# variable: script — line 118
# variable: observed — line 132
# definition: test_fixed_child_argv_receives_only_verified_context_and_no_provider_environment — line 142
# parameter: monkeypatch — line 143
# variable: issuer — line 146
# variable: credential — line 147
# variable: seen — line 148
# definition: observe — line 152
# parameter: argv — line 152
# parameter: kwargs — line 152
# variable: context — line 158
# definition: test_native_large_tool_resource_has_a_separate_fixed_bound — line 179
# parameter: tmp_path — line 179
# variable: metadata — line 182
# variable: limits — line 204
# definition: test_original_registry_reader_uses_bounded_ordinary_input — line 216
# parameter: tmp_path — line 216
# variable: selected — line 218
# END CODE MAP

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from cial import desktop_state, inputs, recertify
from cial.engine import Engine
from cial.identity import FixtureIssuer, Rejected, Verifier


def test_actual_input_bytes_hash_limits_and_changed_same_descriptor(
    tmp_path, monkeypatch
):
    """A byte-limit or file mutation must fail before a purported complete registry/tool fingerprint is returned."""
    selected = tmp_path / "data"
    selected.write_bytes(b"0123456789")
    assert inputs.read_source(selected, 10) == b"0123456789"
    assert inputs.file_hash(selected, 10) == hashlib.sha256(b"0123456789").hexdigest()
    for function in (inputs.read_source, inputs.file_hash):
        with pytest.raises(Rejected):
            function(selected, 9)
        with pytest.raises(Rejected):
            function(tmp_path / "missing", 10)
        with pytest.raises(Rejected):
            function(tmp_path, 10)
    actual = inputs.os.fstat
    count = 0

    def mutate(descriptor):
        """Append real bytes between the first and final descriptor observations, not a forged passing digest."""
        nonlocal count
        count += 1
        if count == 2:
            with selected.open("ab") as stream:
                stream.write(b"changed")
        return actual(descriptor)

    monkeypatch.setattr(inputs.os, "fstat", mutate)
    with pytest.raises(Rejected, match="changed"):
        inputs.file_hash(selected, 20)


def test_hardlink_and_descriptor_type_swap_are_refused(tmp_path, monkeypatch):
    """A regular pathname observation cannot authorize a different opened file type or a second linked alias."""
    selected = tmp_path / "data"
    selected.write_bytes(b"{}")
    alias = tmp_path / "alias"
    os.link(selected, alias)
    with pytest.raises(Rejected):
        inputs.read_source(selected, 20)
    alias.unlink()
    actual = inputs.os.fstat
    monkeypatch.setattr(
        inputs.os,
        "fstat",
        lambda descriptor: os.stat_result((0, *tuple(actual(descriptor))[1:])),
    )
    with pytest.raises(Rejected, match="changed"):
        inputs.read_source(selected, 20)


@pytest.mark.skipif(
    os.name == "nt",
    reason="POSIX FIFO swap control; Windows descriptor negatives and actual frozen acceptance run separately",
)
def test_regular_registry_swapped_to_fifo_cannot_block_child(tmp_path):
    """A fresh owned process performs the actual regular→FIFO race under a fixed deadline, with no retry or fake data."""
    source = tmp_path / "registry.json"
    source.write_bytes(b"{}")
    script = """
import os,sys
from pathlib import Path
from cial import inputs
from cial.identity import Rejected
path=Path(sys.argv[1]);opened=inputs.os.open
def replace(selected, flags, *args):
 path.unlink();os.mkfifo(path)
 return opened(selected,flags,*args)
inputs.os.open=replace
try:inputs.read_source(path,65536)
except Rejected:raise SystemExit(0)
raise SystemExit(3)
"""
    observed = subprocess.run(
        [sys.executable, "-c", script, str(source)],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        check=False,
        timeout=3,
    )
    assert observed.returncode == 0


def test_fixed_child_argv_receives_only_verified_context_and_no_provider_environment(
    monkeypatch,
):
    """The boundary mock observes real signature verification while asserting that no key/token/credential environment reaches OPA."""
    issuer = FixtureIssuer()
    credential = issuer.issue("engineer-alpha", 2000000000)
    seen = []
    monkeypatch.setenv("SYNTHETIC_PROVIDER_SECRET", "must-not-enter-child")
    monkeypatch.setenv("PYTHONPATH", "must-not-enter-child")

    def observe(argv, **kwargs):
        """Return only a closed OPA-shaped decision after independently inspecting the actual child invocation."""
        assert argv[1] == "eval" and argv[-1] == "data.cial.decision"
        assert kwargs["timeout"] == 10 and kwargs["check"] is False
        assert "shell" not in kwargs
        assert set(kwargs["env"]) <= {"SYSTEMROOT", "WINDIR", "TEMP", "TMP"}
        context = json.loads(kwargs["input"])
        assert set(context) == {"subject", "mfa_fresh", "now", "action", "resource"}
        assert credential not in kwargs["input"] and "must-not-enter-child" not in str(
            kwargs["env"]
        )
        seen.append(context)
        return SimpleNamespace(
            returncode=0,
            stdout='{"result":[{"expressions":[{"value":{"allow":true,"reason":"allowed"}}]}]}',
        )

    monkeypatch.setattr("cial.engine.subprocess.run", observe)
    assert (
        Engine(Path("pinned-opa"), Verifier(issuer.public_key)).decide(
            credential, 2000000000, "read", "alpha-docs"
        )["allow"]
        is True
    )
    assert len(seen) == 1


def test_native_large_tool_resource_has_a_separate_fixed_bound(tmp_path):
    """OPA's binary allowance cannot silently increase report/history limits or authorize unknown resource names."""
    (tmp_path / "tool.exe").write_bytes(b"inert executable bytes, never run")
    metadata = {
        "schema": 1,
        "product": "fixture-app",
        "version": "1.1.0",
        "source": "a" * 40,
        "source_dirty": False,
        "resources": {
            "tool.exe": hashlib.sha256((tmp_path / "tool.exe").read_bytes()).hexdigest()
        },
    }
    (tmp_path / "native-release.json").write_text(json.dumps(metadata), encoding="utf8")
    assert (
        desktop_state.package_identity(
            tmp_path,
            "fixture-app",
            "1.1.0",
            ("tool.exe",),
            {"tool.exe": 128 * 1024 * 1024},
        )["source"]
        == "a" * 40
    )
    assert desktop_state.MAX_FILE == 32 * 1024 * 1024
    for limits in (
        {"missing.exe": 128 * 1024 * 1024},
        {"tool.exe": True},
        {"tool.exe": 128 * 1024 * 1024 + 1},
        {"tool.exe": 1},
    ):
        with pytest.raises(Rejected, match="resource bounds"):
            desktop_state.package_identity(
                tmp_path, "fixture-app", "1.1.0", ("tool.exe",), limits
            )


def test_original_registry_reader_uses_bounded_ordinary_input(tmp_path):
    """The original CLI path and the graphical adapter share the repaired same-descriptor registry admission."""
    selected = tmp_path / "oversize.json"
    selected.write_bytes(b" " * 65537)
    with pytest.raises(Rejected):
        recertify.registry(selected)
