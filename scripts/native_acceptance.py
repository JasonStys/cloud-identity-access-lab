"""Real frozen widget/core/history/export and honest failure-evidence acceptance. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: capture — line 119
# parameter: target — line 119
# parameter: window — line 119
# variable: load — line 125
# variable: gdi — line 126
# variable: user — line 126
# variable: pointer — line 127
# variable: arguments — line 128
# variable: library — line 128
# variable: name — line 128
# variable: result — line 128
# variable: function — line 154
# attribute: argtypes — line 155
# attribute: restype — line 155
# variable: handle — line 158
# variable: rectangle — line 159
# variable: height — line 162
# variable: width — line 162
# variable: source — line 165
# variable: destination — line 166
# variable: bitmap — line 167
# variable: previous — line 168
# variable: pixels — line 173
# variable: header — line 174
# variable: raw — line 192
# variable: scanlines — line 193
# variable: row — line 194
# variable: column — line 196
# variable: offset — line 197
# definition: chunk — line 200
# parameter: data — line 200
# parameter: name — line 200
# definition: oracle — line 222
# parameter: files — line 222
# parameter: index — line 222
# variable: value — line 225
# variable: value — line 235
# variable: row — line 237
# variable: row — line 238
# variable: value — line 244
# variable: raw — line 254
# definition: exercise — line 258
# parameter: output — line 258
# parameter: reopen — line 258
# parameter: window — line 258
# variable: started — line 263
# variable: deadline — line 264
# variable: expected — line 264
# variable: receipt — line 265
# definition: progress — line 284
# parameter: stage — line 284
# definition: finish — line 291
# parameter: failed — line 291
# attribute: acceptance_result — line 293
# variable: name — line 299
# variable: raw — line 299
# variable: row — line 301
# definition: callback_failed — line 308
# parameter: _traceback — line 309
# parameter: _value — line 309
# parameter: kind — line 309
# attribute: report_callback_exception — line 316
# definition: checked — line 319
# parameter: callback — line 319
# definition: wait — line 327
# parameter: callback — line 327
# definition: layout — line 337
# variable: widgets — line 342
# variable: name — line 343
# variable: widget — line 345
# definition: rejected — line 367
# definition: runtime_notices — line 376
# variable: dialogs — line 380
# variable: child — line 382
# variable: close — line 386
# variable: pending — line 386
# variable: texts — line 386
# variable: widget — line 388
# variable: close — line 396
# definition: completed — line 410
# parameter: index — line 410
# variable: files — line 417
# variable: parent — line 439
# variable: target — line 445
# variable: path — line 446
# variable: bad — line 447
# definition: start — line 456
# parameter: index — line 456
# variable: external — line 463
# variable: value — line 466
# definition: begin — line 482
# variable: identity — line 486
# END CODE MAP

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import struct
import sys
import time
import tkinter as tk
import zlib
from pathlib import Path
from tkinter import ttk
from typing import TYPE_CHECKING, Any

from cial import desktop_project as project
from cial.desktop_io import json_value

if TYPE_CHECKING:
    from cial.desktop import Workbench


def capture(window: Workbench, target: Path) -> None:
    """Capture only this owned synthetic Tk window via PrintWindow, never the user's whole desktop."""
    if sys.platform != "win32":
        raise OSError("native screenshot acceptance targets Windows")
    from ctypes import wintypes

    load = ctypes.WinDLL
    user, gdi = load("user32", use_last_error=True), load("gdi32", use_last_error=True)
    pointer = ctypes.c_void_p
    for library, name, arguments, result in [
        (user, "GetAncestor", [pointer, ctypes.c_uint], pointer),
        (user, "GetWindowDC", [pointer], pointer),
        (gdi, "CreateCompatibleDC", [pointer], pointer),
        (gdi, "CreateCompatibleBitmap", [pointer, ctypes.c_int, ctypes.c_int], pointer),
        (gdi, "SelectObject", [pointer, pointer], pointer),
        (gdi, "DeleteObject", [pointer], ctypes.c_int),
        (gdi, "DeleteDC", [pointer], ctypes.c_int),
        (user, "ReleaseDC", [pointer, pointer], ctypes.c_int),
        (user, "PrintWindow", [pointer, pointer, ctypes.c_uint], ctypes.c_int),
        (user, "GetWindowRect", [pointer, ctypes.POINTER(wintypes.RECT)], ctypes.c_int),
        (
            gdi,
            "GetDIBits",
            [
                pointer,
                pointer,
                ctypes.c_uint,
                ctypes.c_uint,
                pointer,
                pointer,
                ctypes.c_uint,
            ],
            ctypes.c_int,
        ),
    ]:
        function = getattr(library, name)
        function.argtypes, function.restype = arguments, result
    # Flush this owned native window's pending control messages before reading its pixels.
    window.root.update()
    handle = user.GetAncestor(window.root.winfo_id(), 2)
    rectangle = wintypes.RECT()
    if not user.GetWindowRect(handle, ctypes.byref(rectangle)):
        raise OSError("owned window bounds unavailable")
    width, height = rectangle.right - rectangle.left, rectangle.bottom - rectangle.top
    if not 1 <= width <= 4096 or not 1 <= height <= 4096:
        raise OSError("owned screenshot outside bounded dimensions")
    source = user.GetWindowDC(handle)
    destination = gdi.CreateCompatibleDC(source)
    bitmap = gdi.CreateCompatibleBitmap(source, width, height)
    previous = gdi.SelectObject(destination, bitmap)
    try:
        if not user.PrintWindow(handle, destination, 2):
            raise OSError("owned window rendering unavailable")
        gdi.SelectObject(destination, previous)
        pixels = ctypes.create_string_buffer(width * height * 4)
        header = ctypes.create_string_buffer(
            struct.pack(
                "<IiiHHIIiiII",
                40,
                width,
                -height,
                1,
                32,
                0,
                width * height * 4,
                0,
                0,
                0,
                0,
            )
        )
        if gdi.GetDIBits(source, bitmap, 0, height, pixels, header, 0) != height:
            raise OSError("owned screenshot pixels incomplete")
        raw = pixels.raw
        scanlines = bytearray()
        for row in range(height):
            scanlines.append(0)
            for column in range(width):
                offset = (row * width + column) * 4
                scanlines.extend((raw[offset + 2], raw[offset + 1], raw[offset]))

        def chunk(name: bytes, data: bytes) -> bytes:
            """Encode a bounded standard PNG chunk with its actual CRC."""
            return (
                struct.pack(">I", len(data))
                + name
                + data
                + struct.pack(">I", zlib.crc32(name + data))
            )

        target.write_bytes(
            b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(scanlines)))
            + chunk(b"IEND", b"")
        )
    finally:
        gdi.SelectObject(destination, previous)
        gdi.DeleteObject(bitmap)
        gdi.DeleteDC(destination)
        user.ReleaseDC(handle, source)


def oracle(index: int, files: dict[str, bytes]) -> None:
    """Require literal signature/policy outcomes, exact permission deltas and true context counts from the actual frozen app."""
    if index == 6:
        value = json_value(files["entitlements.json"])
        assert value["contexts_evaluated"] == 128 and value["native_decisions"] == 256
        assert (
            len(value["permission_gains"]) == 4 and len(value["permission_losses"]) == 3
        )
        assert (
            value["emergency"]["state"] == "active"
            and value["emergency"]["remaining_seconds"] == 60
        )
    elif index == 7:
        value = json_value(files["assurance.json"])
        assert len(value["cases"]) == 31
        assert all(row["expected"] == row["observed"] for row in value["cases"])
        assert {row["reason"] for row in value["cases"]} == {
            "allowed",
            "policy_denied",
            "credential_rejected",
        }
    else:
        value = json_value(files["result.json"])["records"][0]
        assert value["observed_allow"] is (index in (0, 3))
        assert value["reason"] == (
            "credential_rejected"
            if index == 5
            else "allowed"
            if index in (0, 3)
            else "policy_denied"
        )
        assert value["oracle_match"] is (index != 8)
    for raw in files.values():
        assert b"eyJ" not in raw and b'"jti"' not in raw and b"PRIVATE KEY" not in raw


def exercise(window: Workbench, output: Path, reopen: bool) -> None:
    """Drive the same actual controls/worker/crypto/OPA, with no result mocks, provider keys, cloud calls or test-only auth bypass."""
    from unittest.mock import patch

    output.mkdir(mode=0o700)
    started = time.monotonic()
    deadline, expected = started + 55, 9
    receipt: dict[str, Any] = {
        "schema": 1,
        "product": project.PRODUCT,
        "version": project.VERSION,
        "source": window.identity.get("source"),
        "source_dirty": window.identity.get("source_dirty"),
        "python_version": sys.version.split()[0],
        "python_dll_sha256": window.identity.get("python_dll_sha256"),
        "verified_opa_sha256": window.identity.get("verified_opa_sha256"),
        "pid": os.getpid(),
        "parent_pid": os.getppid(),
        "synthetic": True,
        "reopen": reopen,
        "passed": False,
        "steps": [],
        "tcl_version": str(window.root.tk.call("info", "patchlevel")),
        "tk_version": str(window.root.tk.call("package", "require", "Tk")),
    }

    def progress(stage: str) -> None:
        """Persist bounded value-free stage facts before potentially blocking native operations."""
        receipt["last_stage"] = stage
        (output / "acceptance.json").write_text(
            json.dumps(receipt, indent=2) + "\n", encoding="utf8"
        )

    def finish(failed: bool = False) -> None:
        """Keep exact retained bundle hashes and request normal owned shutdown; never erase an earlier failure or force-kill a process."""
        window.acceptance_result = not failed
        receipt["passed"] = not failed
        receipt["journey_elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
        receipt["bundles"] = {
            str(row["id"]): {
                name: hashlib.sha256(raw).hexdigest()
                for name, raw in window.state.files(row["id"]).items()
            }
            for row in window.state.history()
        }
        (output / "acceptance.json").write_text(
            json.dumps(receipt, indent=2) + "\n", encoding="utf8"
        )
        window.exit()

    def callback_failed(
        kind: type[BaseException], _value: BaseException, _traceback: Any
    ) -> None:
        """A Tk callback exception must fail and close normally, never disappear in a windowed executable's absent stderr."""
        receipt["failure_stage"] = "tk-callback"
        receipt["failure_type"] = kind.__name__[:60]
        finish(True)

    window.root.report_callback_exception = callback_failed
    progress("acceptance-entered")

    def checked(callback: Any) -> None:
        """Retain failed stage names only, with no token/key/claims or raw exception output."""
        try:
            callback()
        except Exception:
            receipt["failure_stage"] = callback.__name__
            finish(True)

    def wait(callback: Any) -> None:
        """Poll only this real worker under the unchanged fixed journey deadline, retaining a failure instead of resampling."""
        if time.monotonic() > deadline:
            receipt["failure_stage"] = "owned-operation-deadline"
            finish(True)
        elif window.busy:
            window.root.after(60, lambda: wait(callback))
        else:
            checked(callback)

    def layout() -> None:
        """Require actual active inputs/Run/lifecycle controls to fit the supported minimum native window."""
        window.root.geometry("980x700")
        window.tabs.tk.call(str(window.tabs), "select", str(window.inputs_page))
        window.root.update()
        widgets: list[ttk.Widget] = [window.run_button, *window.footer_buttons.values()]
        for name in project.ACTIVE_FIELDS[window.mode.get()]:
            widgets.extend(window.field_widgets[name])
        for widget in widgets:
            assert widget.winfo_ismapped()
            assert (
                widget.winfo_rootx() >= window.root.winfo_rootx()
                and widget.winfo_rooty() >= window.root.winfo_rooty()
            )
            assert (
                widget.winfo_rootx() + widget.winfo_width()
                <= window.root.winfo_rootx() + window.root.winfo_width()
            )
            assert (
                widget.winfo_rooty() + widget.winfo_height()
                <= window.root.winfo_rooty() + window.root.winfo_height()
            )
        receipt["minimum_layout"] = {
            "width": 980,
            "height": 700,
            "activeInputsRunAndLifecycleVisible": True,
        }
        window.root.geometry("1260x860")
        window.root.update()

    def rejected() -> None:
        """Actual malformed registry input cannot create a passing result or replace the earlier nine exact bundles."""
        assert (
            len(window.state.history()) == expected
            and "rejected" in window.status.get().lower()
        )
        receipt["steps"].append("actual-invalid-registry-retains-prior-evidence")
        finish()

    def runtime_notices() -> None:
        """Open the real bundled Licenses window and close it through its own button after checking actual upstream notices."""
        window.footer_buttons["Licenses"].invoke()
        window.root.update()
        dialogs = [
            child
            for child in window.root.winfo_children()
            if child.winfo_class() == "Toplevel"
        ]
        assert len(dialogs) == 1
        pending, texts, close = [dialogs[0]], [], None
        while pending:
            widget = pending.pop()
            pending.extend(widget.winfo_children())
            if isinstance(widget, tk.Text):
                texts.append(widget.get("1.0", "end"))
            if (
                isinstance(widget, ttk.Button)
                and widget.cget("text") == "Close licenses"
            ):
                close = widget
        assert (
            len(texts) == 1
            and "Open Policy Agent 1.22.3 linked Go dependency notices" in texts[0]
        )
        assert (
            "Tcl " + str(receipt["tcl_version"]) in texts[0]
            and "cryptography 50.0.2" in texts[0]
            and "Go1.27.3" in texts[0]
        )
        assert close is not None
        close.invoke()
        receipt["steps"].append("actual-bundled-runtime-and84module-license-window")

    def completed(index: int) -> None:
        """Independently inspect actual frozen output, select real rows and capture only this owned synthetic window."""
        assert (
            len(window.state.history()) == index + 1
            and window.selected_run == index + 1
        )
        progress("scenario-" + str(index) + "-check")
        files = window.state.files(index + 1)
        oracle(index, files)
        if index in (0, 6):
            if index == 6:
                window.view.set("Permission gains")
                window.render()
            window.table.selection_set("0")
            window.inspect()
            window.root.update()
            assert json.loads(window.details.get("1.0", "end"))
            capture(
                window,
                output
                / (
                    "selected-evidence.png"
                    if index == 0
                    else "owner-unknown-review.png"
                ),
            )
        receipt["steps"].append("actual-signed-policy-scenario-" + str(index + 1))
        if index + 1 == expected:
            runtime_notices()
            parent = output / "exact-export"
            parent.mkdir()
            with patch(
                "cial.desktop.filedialog.askdirectory", return_value=str(parent)
            ):
                window.export_button.invoke()
            target = next(parent.iterdir())
            assert {path.name: path.read_bytes() for path in target.iterdir()} == files
            bad = output / "bad-registry.json"
            bad.write_text('{"lab":{},"lab":{}}', encoding="utf8")
            window.values["registry"].set(str(bad))
            window.authorized.set(True)
            window.run_button.invoke()
            wait(rejected)
        else:
            start(index + 1)

    def start(index: int) -> None:
        """Prepared inputs and a real edited external registry enter the exact ordinary fields and handlers."""
        progress("scenario-" + str(index) + "-prepare")
        window.prepared.set(project.SCENARIOS[index if index < 8 else 0])
        window.load_prepared()
        assert not window.authorized.get()
        if index in (0, 8):
            external = output / (
                "authorized-registry.json" if index == 0 else "restricted-registry.json"
            )
            value = json.loads((project.ROOT / "policy/registry.json").read_bytes())
            if index == 8:
                value["lab"]["principals"]["engineer-alpha"]["actions"] = ["read"]
            external.write_text(json.dumps(value), encoding="utf8")
            with patch(
                "cial.desktop.filedialog.askopenfilename", return_value=str(external)
            ):
                window.choose("registry", "file")
        progress("scenario-" + str(index) + "-layout")
        layout()
        progress("scenario-" + str(index) + "-invoke")
        window.authorized.set(True)
        window.run_button.invoke()
        progress("scenario-" + str(index) + "-wait")
        wait(lambda: completed(index))

    def begin() -> None:
        """A second frozen process verifies/reopens all original bundles without reissuing tokens or rerunning OPA."""
        if reopen:
            assert len(window.state.history()) == expected
            for identity in range(1, expected + 1):
                window.history_table.selection_set(str(identity))
                window.open_button.invoke()
                assert window.selected_run == identity
                oracle(identity - 1, window.state.files(identity))
            receipt["steps"].append("actual-process-reopen-all-exact-policy-bundles")
            finish()
        else:
            assert not window.state.history()
            window.run_button.invoke()
            assert (
                not window.state.history()
                and "permission" in window.status.get().lower()
            )
            start(0)

    checked(begin)
