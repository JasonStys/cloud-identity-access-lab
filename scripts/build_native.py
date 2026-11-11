"""Build the complete real offline workbench as one Windows portable executable. Jason Stys.

No publication, installation, shortcut change, host collection or Docker action.
"""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 79
# definition: icon — line 83
# parameter: path — line 83
# variable: size — line 85
# variable: pixels — line 86
# variable: y — line 87
# variable: x — line 88
# variable: shield — line 89
# variable: check — line 95
# variable: color — line 101
# variable: bitmap — line 109
# definition: notices — line 123
# parameter: path — line 123
# variable: root — line 127
# variable: tcl_version — line 130
# variable: tk_version — line 131
# variable: value — line 134
# variable: runtime_notices — line 139
# variable: library — line 140
# variable: title — line 140
# variable: channel — line 144
# variable: raw — line 146
# variable: raw — line 150
# variable: sources — line 158
# variable: name — line 162
# variable: suffix — line 162
# variable: distribution — line 163
# variable: matches — line 164
# variable: entry — line 165
# variable: name — line 177
# variable: distribution — line 178
# variable: entries — line 179
# variable: entry — line 181
# variable: entry — line 187
# variable: name — line 194
# variable: blocks — line 201
# variable: source — line 202
# variable: title — line 202
# variable: _ — line 204
# variable: data — line 204
# variable: data — line 207
# variable: title — line 207
# definition: main — line 211
# variable: version — line 221
# variable: source — line 224
# variable: dirty — line 227
# variable: output — line 232
# variable: release — line 232
# variable: resource_paths — line 238
# variable: name — line 248
# variable: metadata — line 250
# variable: name — line 258
# variable: path — line 258
# variable: command — line 264
# variable: name — line 285
# variable: path — line 285
# variable: command — line 288
# variable: command — line 292
# variable: executable — line 306
# variable: stream — line 307
# variable: digest — line 308
# END CODE MAP

import hashlib
import importlib.metadata
import json
import os
import struct
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def icon(path: Path) -> None:
    """Generate an authored blue shield/check icon as build output, without shipping a graphics dependency."""
    size = 64
    pixels = bytearray()
    for y in reversed(range(size)):
        for x in range(size):
            shield = (
                8 <= x <= 55
                and 5 <= y <= 42
                or 42 < y <= 59
                and abs(x - 31.5) < (60 - y) * 1.4
            )
            check = (
                15 <= x <= 29
                and abs(y - (x + 8)) < 3
                or 27 <= x <= 48
                and abs(y - (65 - x)) < 3
            )
            color = (
                (255, 255, 255, 255)
                if shield and check
                else (220, 100, 24, 255)
                if shield
                else (0, 0, 0, 0)
            )
            pixels.extend(color)
    bitmap = (
        struct.pack(
            "<IIIHHIIIIII", 40, size, size * 2, 1, 32, 0, len(pixels), 0, 0, 0, 0
        )
        + pixels
        + bytes(size * size // 8)
    )
    path.write_bytes(
        struct.pack("<HHH", 0, 1, 1)
        + struct.pack("<BBBBHHII", size, size, 0, 0, 1, 32, len(bitmap), 22)
        + bitmap
    )


def notices(path: Path) -> None:
    """Retain actual Python, Tcl/Tk, application-runtime and bootloader notices, including Tcl9 DLL-embedded resources."""
    import tkinter

    root = tkinter.Tk()
    root.withdraw()
    try:
        tcl_version = root.tk.call("info", "patchlevel")
        tk_version = root.tk.call("package", "require", "Tk")
        if not all(
            str(value).startswith(("8.6.", "9.0."))
            for value in (tcl_version, tk_version)
        ):
            raise ValueError(
                "Review a different Tcl/Tk runtime family before packaging"
            )
        runtime_notices = []
        for title, library in [
            ("Tcl " + str(tcl_version), root.tk.call("info", "library")),
            ("Tk " + str(tk_version), root.tk.eval("set tk_library")),
        ]:
            channel = root.tk.call("open", str(library) + "/license.terms", "rb")
            try:
                raw = root.tk.call("read", channel, 65537)
            finally:
                root.tk.call("close", channel)
            if isinstance(raw, str):
                raw = raw.encode("utf-8")
            if not isinstance(raw, bytes) or not 100 < len(raw) <= 65536:
                raise ValueError(
                    "Actual runtime notice is missing or outside its byte bound"
                )
            runtime_notices.append((title, raw))
    finally:
        root.destroy()
    sources = [
        ("Authored application — MIT", ROOT / "LICENSE"),
        ("Python runtime", Path(sys.base_prefix) / "LICENSE.txt"),
    ]
    for name, suffix in [("pyinstaller", "licenses/COPYING.txt")]:
        distribution = importlib.metadata.distribution(name)
        matches = [
            entry for entry in distribution.files or [] if str(entry).endswith(suffix)
        ]
        if len(matches) != 1:
            raise ValueError("Review runtime license inventory before packaging")
        sources.append(
            (
                name + " license and applicable exception",
                Path(distribution.locate_file(matches[0])),
            )
        )
    # These are actual installed runtime distribution notice files, never guessed
    # licenses or a declaration that linked third-party code has no advisories.
    for name in ("PyJWT", "cryptography", "cffi", "pycparser"):
        distribution = importlib.metadata.distribution(name)
        entries = [
            entry
            for entry in distribution.files or []
            if ".dist-info/" in str(entry)
            and ("license" in str(entry).lower() or "copying" in str(entry).lower())
        ]
        if not entries:
            raise ValueError("Runtime distribution notice inventory is missing")
        for entry in entries:
            sources.append(
                (
                    name + " " + distribution.version + " / " + Path(str(entry)).name,
                    Path(distribution.locate_file(entry)),
                )
            )
    for name in (
        "OPA-LICENSE.txt",
        "GO-LICENSE.txt",
        "OPA-THIRD-PARTY.txt",
        "opa-linked-modules.txt",
    ):
        sources.append(("Verified OPA runtime / " + name, ROOT / "licenses" / name))
    blocks = [
        (title, source.read_bytes()) for title, source in sources
    ] + runtime_notices
    if any(len(data) > 2 * 1024 * 1024 for _, data in blocks):
        raise ValueError("Bundled license exceeds byte bound")
    path.write_bytes(
        b"\n\n".join(title.encode("utf-8") + b"\n" + data for title, data in blocks)
    )


def main() -> None:
    """Freeze exact allowlisted public resources and bind actual source/dirty state without publishing."""
    if sys.platform != "win32" or sys.version_info[:3] != (3, 14, 10):
        raise RuntimeError(
            "This portable recipe requires patched Windows CPython3.14.10"
        )
    from cial import desktop_project as project
    from cial.inputs import file_hash
    from cial.tooling import executable

    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    if version != project.VERSION:
        raise ValueError("Native version coherence failed")
    source = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    dirty = bool(
        subprocess.check_output(
            ["git", "status", "--porcelain"], cwd=ROOT, text=True
        ).strip()
    )
    release, output = ROOT / "release", ROOT / "out"
    release.mkdir(exist_ok=True)
    output.mkdir(exist_ok=True)
    executable("opa")  # Verify the independent official pin before redistribution.
    notices(release / "notices.txt")
    icon(output / "app.ico")
    resource_paths = {
        name: (
            release / name
            if name == "notices.txt"
            else output / name
            if name == "app.ico"
            else Path(sys.base_prefix) / name
            if name == "python314.dll"
            else ROOT / name
        )
        for name in project.RESOURCES
    }
    metadata = {
        "schema": 1,
        "product": project.PRODUCT,
        "version": version,
        "source": source,
        "source_dirty": dirty,
        "resources": {
            name: file_hash(path, project.RESOURCE_LIMITS.get(name, 32 * 1024 * 1024))
            for name, path in resource_paths.items()
        },
    }
    (release / "native-release.json").write_text(
        json.dumps(metadata, indent=2) + "\n", encoding="utf8"
    )
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--windowed",
        "--icon",
        str(output / "app.ico"),
        "--name",
        "CloudIdentityAccessLab",
        "--distpath",
        "release/portable",
        "--workpath",
        "out/native-build",
        "--specpath",
        "out",
        "--paths",
        str(ROOT),
    ]
    for name, path in resource_paths.items():
        if name == "python314.dll":
            continue  # PyInstaller collects the actual interpreter DLL as a binary, not duplicate data.
        command += [
            "--add-binary" if name == ".tools/opa.exe" else "--add-data",
            str(path) + os.pathsep + Path(name).parent.as_posix(),
        ]
    command += [
        "--add-data",
        str(release / "native-release.json") + os.pathsep + ".",
        "scripts/native_entry.py",
    ]
    subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        env={
            **os.environ,
            "PYINSTALLER_CONFIG_DIR": str(output / "native-freezer-cache"),
        },
    )
    executable = release / "portable/CloudIdentityAccessLab.exe"
    with executable.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    executable.with_name(executable.name + ".sha256").write_text(
        digest + "  " + executable.name + "\n", encoding="ascii"
    )
    print(
        "Portable candidate built; source_dirty="
        + str(dirty)
        + "; not published or installed"
    )


if __name__ == "__main__":
    main()
