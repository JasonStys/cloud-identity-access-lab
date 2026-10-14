"""Jason Stys: actual loopback evidence routes, privacy guards, CLI lifecycle and report nonoverwrite."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: report — line 59
# definition: test_actual_http_and_private_guards — line 81
# parameter: report — line 81
# variable: listener — line 83
# variable: worker — line 84
# definition: request — line 88
# parameter: headers — line 88
# parameter: method — line 88
# parameter: path — line 88
# variable: client — line 90
# variable: response — line 95
# variable: path — line 100
# variable: headers — line 109
# variable: raw — line 109
# variable: status — line 109
# variable: path — line 120
# variable: headers — line 126
# definition: test_save_nonoverwrite_and_links — line 150
# parameter: monkeypatch — line 150
# parameter: report — line 150
# parameter: tmp_path — line 150
# parameter: self — line 157
# definition: test_cli_outcomes_and_owned_teardown — line 162
# parameter: capsys — line 162
# parameter: monkeypatch — line 162
# parameter: report — line 162
# parameter: tmp_path — line 162
# variable: calls — line 171
# definition: Listener — line 173
# variable: server_port — line 176
# definition: serve_forever — line 178
# parameter: self — line 178
# definition: owned — line 183
# parameter: args — line 183
# definition: test_uncommitted_source_fallback — line 196
# parameter: monkeypatch — line 196
# definition: missing — line 200
# parameter: args — line 200
# parameter: kwargs — line 200
# END CODE MAP

import http.client
import json
import subprocess
import threading
from contextlib import contextmanager
from pathlib import Path

import pytest

from cial.__main__ import main, save
from cial.identity import Rejected
from cial.server import server


@pytest.fixture
def report():
    """Synthetic shape fixture only for server/report boundaries, separate from native policy acceptance."""
    return {
        "schema": 1,
        "synthetic": True,
        "source": "uncommitted",
        "cases": [
            {
                "id": "TEST-ONE",
                "title": "Synthetic",
                "principal": "engineer-alpha",
                "action": "read",
                "resource": "alpha-docs",
                "expected": True,
                "observed": True,
                "reason": "allowed",
                "elapsed_ms": 1,
            }
        ],
    }


def test_actual_http_and_private_guards(report):
    """Use real TCP requests to verify fixed routes/attachments, exact origin guards and no mutation capability."""
    with server(report) as listener:
        worker = threading.Thread(target=listener.serve_forever)
        worker.start()
        try:

            def request(path, method="GET", headers=None):
                """Send a bounded actual request and close its owned client in all outcomes."""
                client = http.client.HTTPConnection(
                    "127.0.0.1", listener.server_port, timeout=5
                )
                try:
                    client.request(method, path, headers=headers or {})
                    response = client.getresponse()
                    return response.status, dict(response.getheaders()), response.read()
                finally:
                    client.close()

            for path in [
                "/",
                "/app.js",
                "/model.js",
                "/style.css",
                "/health",
                "/evidence.json",
                "/evidence.html",
            ]:
                status, headers, raw = request(path)
                assert status == 200 and raw
                assert (
                    headers["Cache-Control"] == "no-store"
                    and headers["X-Content-Type-Options"] == "nosniff"
                )
                assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
                assert "Access-Control-Allow-Origin" not in headers
                if path.startswith("/evidence."):
                    assert headers["Content-Disposition"].startswith("attachment;")
            assert json.loads(request("/evidence.json")[2]) == report
            for path in [
                "/.env",
                "/../policy/registry.json",
                "/evidence.json?private=1",
            ]:
                assert request(path)[0] == 404
            for headers in [
                {"Host": "outside.example.invalid"},
                {"Origin": "https://outside.example.invalid"},
                {"Sec-Fetch-Site": "cross-site"},
            ]:
                assert request("/evidence.json", headers=headers)[0] == 403
            assert (
                request(
                    "/health",
                    headers={"Origin": "http://127.0.0.1:" + str(listener.server_port)},
                )[0]
                == 200
            )
            assert request("/session", method="POST")[0] == 405
        finally:
            listener.shutdown()
            worker.join(timeout=5)
            assert not worker.is_alive()
    with pytest.raises(Rejected):
        server(report, -1)
    with pytest.raises(Rejected):
        server(report, True)


def test_save_nonoverwrite_and_links(tmp_path, report, monkeypatch):
    """Save canonical private evidence to a new directory and refuse overwrites or linked destinations."""
    save(report, tmp_path / "new")
    assert json.loads((tmp_path / "new/decisions.json").read_text()) == report
    assert len((tmp_path / "new/decisions.sha256").read_text().strip()) == 64
    with pytest.raises(FileExistsError):
        save(report, tmp_path / "new")
    monkeypatch.setattr(Path, "is_symlink", lambda self: self.name == "linked")
    with pytest.raises(Rejected):
        save(report, tmp_path / "linked")


def test_cli_outcomes_and_owned_teardown(tmp_path, report, monkeypatch, capsys):
    """Mock only CLI orchestration, assert nonzero failed cases and exact context-manager shutdown on interrupt."""
    monkeypatch.setattr("cial.__main__.run", lambda: report)
    assert main(["run"]) == 2
    assert main(["run", "--out", str(tmp_path / "okay")]) == 0
    assert main(["run", "--out", str(tmp_path / "okay")]) == 2
    report["cases"][0]["expected"] = False
    assert main(["run", "--out", str(tmp_path / "failed")]) == 1
    report["cases"][0]["expected"] = True
    calls = []

    class Listener:
        """Owned fake server used only to observe the CLI interrupt path."""

        server_port = 12345

        def serve_forever(self):
            """Raise a controlled user interrupt, not a request outcome."""
            raise KeyboardInterrupt()

    @contextmanager
    def owned(*args):
        """Record ownership teardown even when the serving loop is interrupted."""
        calls.append("open")
        try:
            yield Listener()
        finally:
            calls.append("close")

    monkeypatch.setattr("cial.__main__.server", owned)
    assert main(["serve"]) == 0 and calls == ["open", "close"]
    assert "PRIVATE" not in capsys.readouterr().out


def test_uncommitted_source_fallback(monkeypatch):
    """Absence of a Git commit yields an honest uncommitted label, not a fabricated source hash."""
    from cial.scenarios import run

    def missing(*args, **kwargs):
        """Simulate only Git metadata failure, retaining actual native policy evaluation."""
        raise subprocess.CalledProcessError(128, "git")

    monkeypatch.setattr("cial.scenarios.subprocess.check_output", missing)
    assert run()["source"] == "uncommitted"
