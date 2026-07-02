"""Small JSON-over-HTTP helpers for M0 runtime services."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import parse_qs, unquote, urlparse


JsonHandler = Callable[["JsonRequest"], tuple[int, Any]]


class JsonRequest:
    def __init__(self, *, method: str, path: str, query: dict[str, list[str]], body: Any | None) -> None:
        self.method = method
        self.path = path
        self.query = query
        self.body = body


class JsonHttpApp:
    def __init__(self) -> None:
        self._routes: dict[tuple[str, str], JsonHandler] = {}
        self._prefix_routes: list[tuple[str, str, JsonHandler]] = []

    def route(self, method: str, path: str) -> Callable[[JsonHandler], JsonHandler]:
        def register(handler: JsonHandler) -> JsonHandler:
            self._routes[(method.upper(), path)] = handler
            return handler

        return register

    def prefix(self, method: str, prefix: str) -> Callable[[JsonHandler], JsonHandler]:
        def register(handler: JsonHandler) -> JsonHandler:
            self._prefix_routes.append((method.upper(), prefix, handler))
            return handler

        return register

    def handle(self, request: JsonRequest) -> tuple[int, Any]:
        route = self._routes.get((request.method, request.path))
        if route is not None:
            return route(request)
        for method, prefix, handler in self._prefix_routes:
            if request.method == method and request.path.startswith(prefix):
                return handler(request)
        return 404, {"error": "not_found"}


def serve_json_app(app: JsonHttpApp, *, host: str, port: int) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self._handle_json()

        def do_POST(self) -> None:
            self._handle_json()

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _handle_json(self) -> None:
            parsed = urlparse(self.path)
            status, payload = app.handle(
                JsonRequest(
                    method=self.command.upper(),
                    path=unquote(parsed.path),
                    query=parse_qs(parsed.query),
                    body=self._read_body(),
                )
            )
            encoded = json.dumps(_jsonable(payload), sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def _read_body(self) -> Any | None:
            length = int(self.headers.get("Content-Length", "0"))
            if length == 0:
                return None
            raw = self.rfile.read(length)
            if not raw:
                return None
            return json.loads(raw)

    ThreadingHTTPServer((host, port), Handler).serve_forever()


def _jsonable(value: Any) -> Any:
    if is_dataclass(value):
        return _jsonable(asdict(value))
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value

