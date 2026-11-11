"""Jason Stys: verify and install fixed official native tools; never execute arbitrary caller-selected programs."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 55
# definition: metadata — line 58
# parameter: name — line 58
# variable: system — line 65
# variable: lock — line 66
# variable: item — line 69
# variable: prefix — line 70
# variable: executable — line 77
# definition: executable — line 81
# parameter: name — line 81
# variable: item — line 83
# variable: target — line 83
# variable: installed — line 86
# variable: correct — line 88
# variable: archive — line 90
# variable: zipped — line 100
# variable: correct — line 101
# definition: install — line 107
# parameter: name — line 107
# variable: item — line 109
# variable: target — line 109
# variable: folder — line 113
# variable: archive — line 114
# variable: digest — line 115
# variable: total — line 116
# variable: response — line 118
# variable: output — line 119
# variable: chunk — line 121
# variable: total — line 122
# variable: candidate — line 129
# variable: zipped — line 131
# variable: info — line 132
# definition: main — line 144
# variable: parser — line 146
# END CODE MAP

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

from .identity import Rejected
from .inputs import file_hash, read_source

ROOT = Path(__file__).resolve().parents[1]


def metadata(name: str) -> tuple[Path, dict[str, Any]]:
    """Resolve an allowlisted tool for x86-64 hosts from the reviewed version/URL/digest lock."""
    if name not in {"opa", "terraform"} or platform.machine().lower() not in {
        "amd64",
        "x86_64",
    }:
        raise Rejected("tool_platform_rejected")
    system = platform.system().lower()
    lock = json.loads((ROOT / "tools.lock.json").read_text(encoding="utf-8"))
    if system not in {"windows", "linux", "darwin"}:
        raise Rejected("tool_platform_rejected")
    item = lock[name][system]
    prefix = (
        f"https://github.com/open-policy-agent/opa/releases/download/v{lock[name]['version']}/"
        if name == "opa"
        else f"https://releases.hashicorp.com/terraform/{lock[name]['version']}/"
    )
    if not item["url"].startswith(prefix):
        raise Rejected("tool_source_rejected")
    executable = ROOT / ".tools" / (name + (".exe" if system == "windows" else ""))
    return executable, dict(item)


def executable(name: str) -> Path:
    """Verify the raw OPA pin or compare Terraform against its retained, officially hash-pinned archive."""
    target, item = metadata(name)
    if target.is_symlink() or target.is_junction() or not target.is_file():
        raise Rejected("tool_not_installed")
    installed = read_source(target, 128 * 1024 * 1024) if name == "terraform" else None
    if name == "opa":
        correct = file_hash(target, 128 * 1024 * 1024) == item["sha256"]
    else:
        archive = target.with_suffix(".zip")
        if (
            archive.is_symlink()
            or archive.is_junction()
            or not archive.is_file()
            or archive.stat().st_size > 128 * 1024 * 1024
        ):
            raise Rejected("tool_integrity_rejected")
        if hashlib.sha256(archive.read_bytes()).hexdigest() != item["sha256"]:
            raise Rejected("tool_integrity_rejected")
        with zipfile.ZipFile(archive) as zipped:
            correct = zipped.read(target.name) == installed
    if not correct:
        raise Rejected("tool_integrity_rejected")
    return target


def install(name: str) -> Path:
    """Download a fixed release, verify before extraction, atomically install only its known regular executable."""
    target, item = metadata(name)
    target.parent.mkdir(mode=0o700, exist_ok=True)
    if target.parent.is_symlink() or target.parent.is_junction():
        raise Rejected("linked_tool_directory")
    with tempfile.TemporaryDirectory(dir=target.parent) as folder:
        archive = Path(folder) / "download"
        digest = hashlib.sha256()
        total = 0
        with (
            urllib.request.urlopen(item["url"], timeout=30) as response,
            archive.open("wb") as output,
        ):
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                if total > 128 * 1024 * 1024:
                    raise Rejected("tool_download_limit")
                output.write(chunk)
                digest.update(chunk)
        if digest.hexdigest() != item["sha256"]:
            raise Rejected("tool_download_digest")
        candidate = Path(folder) / target.name
        if name == "terraform":
            with zipfile.ZipFile(archive) as zipped:
                info = zipped.getinfo(target.name)
                if info.file_size > 128 * 1024 * 1024 or info.is_dir():
                    raise Rejected("tool_archive_rejected")
                candidate.write_bytes(zipped.read(info))
            os.replace(archive, target.with_suffix(".zip"))
        else:
            os.replace(archive, candidate)
        os.chmod(candidate, 0o700)
        os.replace(candidate, target)
    return executable(name)


def main() -> None:
    """Install one reviewed tool on demand, without changing PATH or global runtime configuration."""
    parser = argparse.ArgumentParser(
        description="Jason Stys: pinned official lab tools"
    )
    parser.add_argument("name", choices=["opa", "terraform"])
    print(install(parser.parse_args().name).name)


if __name__ == "__main__":
    main()
