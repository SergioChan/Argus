"""Deployable authenticated Security Engineer pager for S10 quarantine E2E."""

from __future__ import annotations

from copy import deepcopy
import os
import threading
from typing import Any, Mapping

from .auth import UnauthorizedError, require_static_bearer_token
from .http_json import JsonHttpApp, JsonRequest, serve_json_app


_PAGE_FIELDS = frozenset(
    {
        "schema",
        "quarantine_id",
        "job_id",
        "sandbox_id",
        "severity",
        "reason",
        "record_ref",
        "opened_at",
    }
)


class ReferenceSecurityPagerApp:
    """Authenticated write-once page receiver used by deployed S10 acceptance tests."""

    def __init__(
        self,
        *,
        delivery_token: str,
        read_token: str,
        enable_test_control: bool = False,
        hold_deliveries: bool = False,
    ) -> None:
        if not delivery_token or any(char in delivery_token for char in "\r\n"):
            raise ValueError("security pager delivery token is required")
        if not read_token or any(char in read_token for char in "\r\n"):
            raise ValueError("security pager read token is required")
        if delivery_token == read_token:
            raise ValueError("security pager delivery and read tokens must differ")
        if hold_deliveries and not enable_test_control:
            raise ValueError("security pager delivery hold requires explicit test control")
        self._delivery_token = delivery_token
        self._read_token = read_token
        self._enable_test_control = enable_test_control
        self._pages: dict[str, dict[str, str]] = {}
        self._lock = threading.Lock()
        self.delivery_received = threading.Event()
        self._release_deliveries = threading.Event()
        if not hold_deliveries:
            self._release_deliveries.set()
        self.http = JsonHttpApp()
        self._register_routes()

    def _register_routes(self) -> None:
        @self.http.route("GET", "/healthz")
        def health(request: JsonRequest) -> tuple[int, Any]:
            del request
            with self._lock:
                page_count = len(self._pages)
            return 200, {
                "service": "s10-reference-security-pager",
                "status": "ok",
                "accepted_pages": page_count,
            }

        @self.http.route("POST", "/v1/pages")
        def deliver(request: JsonRequest) -> tuple[int, Any]:
            try:
                require_static_bearer_token(
                    request,
                    expected_token=self._delivery_token,
                    purpose="security pager delivery",
                )
            except UnauthorizedError as exc:
                return 401, {"error": "Unauthorized", "message": str(exc)}
            try:
                page = _validated_page(request.body)
            except ValueError as exc:
                return 400, {"error": type(exc).__name__, "message": str(exc)}
            quarantine_id = page["quarantine_id"]
            with self._lock:
                existing = self._pages.get(quarantine_id)
                if existing is not None and existing != page:
                    return 409, {
                        "error": "page_conflict",
                        "message": "quarantine page already exists with different content",
                    }
                if existing is not None:
                    return 200, {"accepted": True, "quarantine_id": quarantine_id}
                self._pages[quarantine_id] = deepcopy(page)
            self.delivery_received.set()
            if not self._release_deliveries.wait(timeout=120):
                return 503, {
                    "error": "delivery_hold_timeout",
                    "message": "test-controlled page delivery was not released",
                }
            return 202, {"accepted": True, "quarantine_id": quarantine_id}

        @self.http.route("GET", "/v1/pages")
        def list_pages(request: JsonRequest) -> tuple[int, Any]:
            denied = self._authorize_reader(request)
            if denied is not None:
                return denied
            with self._lock:
                return 200, [deepcopy(self._pages[key]) for key in sorted(self._pages)]

        @self.http.route("POST", "/v1/test-control/release")
        def release_deliveries(request: JsonRequest) -> tuple[int, Any]:
            denied = self._authorize_reader(request)
            if denied is not None:
                return denied
            if not self._enable_test_control:
                return 404, {"error": "not_found"}
            if request.body not in (None, {}):
                return 400, {"error": "empty_json_object_required"}
            self._release_deliveries.set()
            return 200, {"released": True}

        @self.http.prefix("GET", "/v1/pages/")
        def get_page(request: JsonRequest) -> tuple[int, Any]:
            denied = self._authorize_reader(request)
            if denied is not None:
                return denied
            quarantine_id = request.path.removeprefix("/v1/pages/")
            if not quarantine_id or "/" in quarantine_id:
                return 400, {"error": "invalid_quarantine_id"}
            with self._lock:
                page = self._pages.get(quarantine_id)
                if page is None:
                    return 404, {"error": "page_not_found"}
                return 200, deepcopy(page)

    def _authorize_reader(self, request: JsonRequest) -> tuple[int, dict[str, str]] | None:
        try:
            require_static_bearer_token(
                request,
                expected_token=self._read_token,
                purpose="security pager reader",
            )
        except UnauthorizedError as exc:
            return 401, {"error": "Unauthorized", "message": str(exc)}
        return None


def _validated_page(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != _PAGE_FIELDS:
        raise ValueError("security page fields do not match the contract")
    page = dict(value)
    if any(not isinstance(page[field], str) or not page[field] for field in _PAGE_FIELDS):
        raise ValueError("security page fields must be non-empty strings")
    if page["schema"] != "argus.s10.security-page.v1":
        raise ValueError("security page schema is invalid")
    if page["severity"] != "Sev-1":
        raise ValueError("security page severity must be Sev-1")
    return page  # type: ignore[return-value]


def main() -> None:
    host = os.environ.get("ARGUS_S10_REFERENCE_SECURITY_PAGER_HOST", "127.0.0.1")
    port = int(os.environ.get("ARGUS_S10_REFERENCE_SECURITY_PAGER_PORT", "8080"))
    delivery_token = os.environ.get("ARGUS_S10_SECURITY_PAGER_AUTH_TOKEN", "")
    read_token = os.environ.get("ARGUS_S10_SECURITY_PAGER_READ_TOKEN", "")
    serve_json_app(
        ReferenceSecurityPagerApp(
            delivery_token=delivery_token,
            read_token=read_token,
            enable_test_control=_true_env(
                "ARGUS_S10_REFERENCE_SECURITY_PAGER_ENABLE_TEST_CONTROL"
            ),
            hold_deliveries=_true_env(
                "ARGUS_S10_REFERENCE_SECURITY_PAGER_HOLD_DELIVERIES"
            ),
        ).http,
        host=host,
        port=port,
    )


def _true_env(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


if __name__ == "__main__":
    main()
