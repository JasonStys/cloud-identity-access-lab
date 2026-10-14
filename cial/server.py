"""Jason Stys: loopback-only immutable synthetic evidence viewer, fixed assets and no credential/input endpoints."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 40
# definition: server — line 43
# parameter: port — line 43
# parameter: report — line 43
# variable: payload — line 47
# variable: document — line 48
# variable: assets — line 49
# definition: Handler — line 71
# definition: setup — line 74
# parameter: self — line 74
# definition: log_message — line 79
# parameter: args — line 79
# parameter: format — line 79
# parameter: self — line 79
# definition: do_GET — line 82
# parameter: self — line 82
# variable: host — line 84
# variable: origin — line 85
# variable: rejected — line 86
# variable: status — line 91
# variable: data — line 92
# variable: kind — line 92
# variable: filename — line 109
# definition: do_POST — line 120
# parameter: self — line 120
# END CODE MAP

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, cast

from .evidence import canonical, render
from .identity import Rejected

ROOT = Path(__file__).resolve().parents[1]


def server(report: dict[str, Any], port: int = 0) -> HTTPServer:
    """Build an owned numeric-loopback listener; only immutable reviewed assets and sanitized evidence are served."""
    if type(port) is not int or not 0 <= port <= 65535:
        raise Rejected("port_rejected")
    payload = canonical(report)
    document = render(report).encode()
    assets = {
        "/": ("text/html; charset=utf-8", (ROOT / "dist/index.html").read_bytes()),
        "/app.js": (
            "text/javascript; charset=utf-8",
            (ROOT / "dist/app.js").read_bytes(),
        ),
        "/model.js": (
            "text/javascript; charset=utf-8",
            (ROOT / "dist/model.js").read_bytes(),
        ),
        "/style.css": (
            "text/css; charset=utf-8",
            (ROOT / "dist/style.css").read_bytes(),
        ),
        "/evidence.json": ("application/json", payload),
        "/evidence.html": ("text/html; charset=utf-8", document),
        "/health": (
            "application/json",
            json.dumps({"component": "cial", "synthetic": True}).encode(),
        ),
    }

    class Handler(BaseHTTPRequestHandler):
        """No request-body readers, file traversal, CORS, token routes or private-content logging."""

        def setup(self) -> None:
            """Enforce a finite socket timeout before parsing or writing the local request."""
            super().setup()
            self.connection.settimeout(5)

        def log_message(self, format: str, *args: Any) -> None:
            """Suppress path/header/input logs; use sanitized static status in CLI instead."""

        def do_GET(self) -> None:
            """Check exact Host/Origin metadata and raw path, then emit no-store/nosniff/CSP evidence."""
            host = "127.0.0.1:" + str(cast(HTTPServer, self.server).server_port)
            origin = "http://" + host
            rejected = (
                self.headers.get_all("Host") != [host]
                or self.headers.get_all("Origin") not in (None, [origin])
                or self.headers.get("Sec-Fetch-Site") == "cross-site"
            )
            status = 403 if rejected else 200 if self.path in assets else 404
            kind, data = (
                assets[self.path]
                if status == 200
                else ("application/json", b'{"error":"request_rejected"}')
            )
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
            )
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Connection", "close")
            if self.path in {"/evidence.json", "/evidence.html"} and status == 200:
                filename = (
                    "evidence.json"
                    if self.path == "/evidence.json"
                    else "evidence.html"
                )
                self.send_header(
                    "Content-Disposition", 'attachment; filename="' + filename + '"'
                )
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self) -> None:
            """Reject mutations without reading supplied content; no identity/login or cloud operation API exists."""
            self.send_response(405)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()

    return HTTPServer(("127.0.0.1", port), Handler)
