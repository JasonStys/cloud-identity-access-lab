"""Jason Stys: isolated official-tool download/hash/extraction negative tests; never execute downloaded test bytes."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: configure — line 51
# parameter: content — line 51
# parameter: monkeypatch — line 51
# parameter: name — line 51
# parameter: tmp_path — line 51
# variable: system — line 53
# variable: filename — line 54
# variable: data — line 55
# variable: buffer — line 57
# variable: archive — line 58
# variable: data — line 60
# variable: lock — line 61
# parameter: args — line 77
# parameter: kwargs — line 77
# definition: test_native_tool_integrity — line 83
# parameter: monkeypatch — line 83
# parameter: name — line 83
# parameter: tmp_path — line 83
# variable: target — line 88
# definition: test_platform_source_digest_and_links — line 102
# parameter: monkeypatch — line 102
# parameter: tmp_path — line 102
# variable: lock — line 115
# parameter: self — line 125
# definition: test_download_cap_archive_and_cli — line 130
# parameter: monkeypatch — line 130
# parameter: tmp_path — line 130
# definition: Oversized — line 134
# definition: read — line 137
# parameter: self — line 137
# parameter: size — line 137
# parameter: args — line 142
# parameter: kwargs — line 142
# parameter: self — line 147
# parameter: name — line 150
# END CODE MAP

import hashlib
import io
import json
import zipfile

import pytest

from cial import tooling
from cial.identity import Rejected


def configure(tmp_path, monkeypatch, name="opa", content=b"synthetic-tool"):
    """Build a temporary locked download fixture; no real installed tools or upstream metadata are changed."""
    system = "windows"
    filename = name + ".exe"
    data = content
    if name == "terraform":
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr(filename, content)
        data = buffer.getvalue()
    lock = {
        name: {
            "version": "1.0.0",
            system: {
                "url": "https://github.com/open-policy-agent/opa/releases/download/v1.0.0/opa_windows_amd64.exe"
                if name == "opa"
                else "https://releases.hashicorp.com/terraform/1.0.0/terraform_windows_amd64.zip",
                "sha256": hashlib.sha256(data).hexdigest(),
            },
        }
    }
    (tmp_path / "tools.lock.json").write_text(json.dumps(lock))
    monkeypatch.setattr(tooling, "ROOT", tmp_path)
    monkeypatch.setattr(tooling.platform, "machine", lambda: "AMD64")
    monkeypatch.setattr(tooling.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        tooling.urllib.request, "urlopen", lambda *args, **kwargs: io.BytesIO(data)
    )
    return data


@pytest.mark.parametrize("name", ["opa", "terraform"])
def test_native_tool_integrity(tmp_path, monkeypatch, name):
    """Verify download digest and installed bytes; altering the binary cannot be justified by a forged receipt."""
    configure(tmp_path, monkeypatch, name)
    with pytest.raises(Rejected):
        tooling.executable(name)
    target = tooling.install(name)
    assert tooling.executable(name) == target
    target.write_bytes(b"changed")
    with pytest.raises(Rejected):
        tooling.executable(name)
    if name == "terraform":
        target.with_suffix(".zip").write_bytes(b"changed")
        with pytest.raises(Rejected):
            tooling.executable(name)
        target.with_suffix(".zip").unlink()
        with pytest.raises(Rejected):
            tooling.executable(name)


def test_platform_source_digest_and_links(tmp_path, monkeypatch):
    """Unsupported tools/architectures/systems, redirected source locks and failed hashes are explicit failures."""
    configure(tmp_path, monkeypatch)
    with pytest.raises(Rejected):
        tooling.metadata("unknown")
    monkeypatch.setattr(tooling.platform, "machine", lambda: "arm64")
    with pytest.raises(Rejected):
        tooling.metadata("opa")
    monkeypatch.setattr(tooling.platform, "machine", lambda: "AMD64")
    monkeypatch.setattr(tooling.platform, "system", lambda: "unknown")
    with pytest.raises(Rejected):
        tooling.metadata("opa")
    monkeypatch.setattr(tooling.platform, "system", lambda: "Windows")
    lock = json.loads((tmp_path / "tools.lock.json").read_text())
    lock["opa"]["windows"]["sha256"] = "0" * 64
    (tmp_path / "tools.lock.json").write_text(json.dumps(lock))
    with pytest.raises(Rejected, match="digest"):
        tooling.install("opa")
    lock["opa"]["windows"]["url"] = "https://outside.example.invalid/tool"
    (tmp_path / "tools.lock.json").write_text(json.dumps(lock))
    with pytest.raises(Rejected, match="source"):
        tooling.metadata("opa")
    configure(tmp_path, monkeypatch)
    monkeypatch.setattr(tooling.Path, "is_junction", lambda self: self.name == ".tools")
    with pytest.raises(Rejected, match="linked"):
        tooling.install("opa")


def test_download_cap_archive_and_cli(tmp_path, monkeypatch):
    """Exercise bounded download/archive rejects and CLI selection without executing any test binary."""
    configure(tmp_path, monkeypatch)

    class Oversized(io.BytesIO):
        """Deliver one oversized synthetic chunk to exercise the maximum-download rejection."""

        def read(self, size=-1):
            """Return a bounded allocated witness whose size is just above the defined download cap."""
            return b"x" * (128 * 1024 * 1024 + 1)

    monkeypatch.setattr(
        tooling.urllib.request, "urlopen", lambda *args, **kwargs: Oversized()
    )
    with pytest.raises(Rejected, match="limit"):
        tooling.install("opa")
    configure(tmp_path, monkeypatch, "terraform")
    monkeypatch.setattr(tooling.zipfile.ZipInfo, "is_dir", lambda self: True)
    with pytest.raises(Rejected, match="archive"):
        tooling.install("terraform")
    monkeypatch.setattr(tooling, "install", lambda name: tmp_path / name)
    monkeypatch.setattr("sys.argv", ["tooling", "opa"])
    tooling.main()
