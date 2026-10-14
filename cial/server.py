"""Jason Stys: loopback-only immutable synthetic evidence viewer, fixed assets and no credential/input endpoints."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 39
# definition: server — line 42
# parameter: port — line 42
# parameter: report — line 42
# variable: payload — line 46
# variable: document — line 47
# variable: assets — line 48
# definition: Handler — line 70
# definition: setup — line 73
# parameter: self — line 73
# definition: log_message — line 78
# parameter: args — line 78
# parameter: format — line 78
# parameter: self — line 78
# definition: do_GET — line 81
# parameter: self — line 81
# variable: host — line 83
# variable: origin — line 84
# variable: rejected — line 85
# variable: status — line 90
# variable: data — line 91
# variable: kind — line 91
# definition: do_POST — line 115
# parameter: self — line 115
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
                self.send_header(
                    "Content-Disposition",
                    'attachment; filename="' + self.path[1:] + '"',
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
