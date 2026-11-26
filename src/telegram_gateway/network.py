"""Opt-in network transports; construction never reads secrets or opens sockets.

Callers supply credentials after explicit live approval. Production paths use
verified TLS, fixed Telegram origin / public pinned callback IPs, no proxy
environment and no redirects. Tests inject fake sockets or a test-only loopback
subclass; no configurable production insecure/localhost mode exists here.
"""
from __future__ import annotations

import asyncio
import http.client
import ipaddress
import json
import math
import re
import socket
import ssl
import threading
import time
from typing import Any, Mapping
from urllib.parse import urlsplit

from .bot_api import BotRejected, BotUnavailable, DeliveryUncertain
from .events import CallbackTarget, EventError, MAX_BODY, WebhookResponse, validate_callback

TELEGRAM_ORIGIN = "https://api.telegram.org"
_TOKEN = re.compile(r"[0-9]{5,20}:[A-Za-z0-9_-]{20,128}\Z")
_READ_METHODS = frozenset({"getUpdates", "getMe", "getChat", "getWebhookInfo", "getChatMember"})
_WRITE_METHODS = frozenset({"sendMessage", "forwardMessage"})


class NetworkFailure(RuntimeError):
    """A sanitized transport failure, without URL/body/token details."""


def _seconds(value: Any, name: str) -> float:
    if type(value) not in (int, float) or not math.isfinite(value) or not 0.05 <= value <= 60:
        raise ValueError(f"Invalid {name}")
    return float(value)


def _size(value: Any, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise ValueError("Invalid response limit")
    return value


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise NetworkFailure("Network deadline exceeded")
    return remaining


def _public_ip(value: str) -> str:
    try:
        if not isinstance(value, str) or "%" in value:
            raise ValueError()
        address = ipaddress.ip_address(value)
        if not address.is_global or address.is_multicast or address.is_reserved or address.is_unspecified:
            raise ValueError()
        if isinstance(address, ipaddress.IPv6Address) and (address.ipv4_mapped or address.sixtofour or address.teredo):
            raise ValueError()
        return str(address)
    except ValueError:
        raise NetworkFailure("Public destination required") from None


def resolve_public(hostname: str) -> list[str]:
    """Resolve and validate every address. No request data is sent by DNS.

    Async callers bound this resolver separately before allowing an HTTP send.
    An OS DNS call may outlive its canceled worker; it cannot proceed to HTTP.
    """
    try:
        host = "[" + hostname + "]" if ":" in hostname else hostname
        def resolve(_):
            rows = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
            return list(dict.fromkeys(row[4][0] for row in rows))
        target = validate_callback("https://" + host + "/", resolve)
        return list(target.addresses)
    except Exception:
        raise NetworkFailure("Public destination resolution failed") from None


async def _resolve_with_deadline(resolver, hostname: str, deadline: float) -> list[str]:
    try:
        # Resolver workers only perform DNS. On timeout, no HTTP worker starts.
        return await asyncio.wait_for(asyncio.to_thread(resolver, hostname), timeout=min(5, _remaining(deadline)))
    except asyncio.CancelledError:
        raise
    except Exception:
        raise NetworkFailure("Public destination resolution failed") from None


async def _finish_worker_on_cancel(function, *args):
    """Keep the caller's consumer lock until a possibly-sent request finishes.

    Canceling to_thread alone leaves a live sender behind. The socket deadline
    bounds this wait, and then cancellation propagates to the outbox owner.
    """
    worker = asyncio.create_task(asyncio.to_thread(function, *args))
    try:
        return await asyncio.shield(worker)
    except asyncio.CancelledError:
        while not worker.done():
            try:
                await asyncio.shield(worker)
            except asyncio.CancelledError:
                continue
            except Exception:
                break
        if worker.done() and not worker.cancelled():
            try:
                worker.exception()
            except BaseException:
                pass
        raise


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS with a literal dial address, original SNI and certificate name."""
    def __init__(self, hostname: str, port: int, address: str,
                 *, deadline: float, connect_timeout: float):
        context = ssl.create_default_context()
        if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
            raise NetworkFailure("Verified TLS context required")
        super().__init__(hostname, port=port, timeout=min(connect_timeout, _remaining(deadline)), context=context)
        self._pinned_address = _public_ip(address)
        self._deadline = deadline
        self._connect_timeout = connect_timeout

    def _check_peer(self) -> None:
        if self.sock is None or _public_ip(self.sock.getpeername()[0]) != self._pinned_address:
            raise NetworkFailure("Connected peer does not match validated destination")

    def connect(self) -> None:
        if self._tunnel_host:
            raise NetworkFailure("Proxy tunnels are not supported")
        try:
            self.sock = socket.create_connection(
                (self._pinned_address, self.port), timeout=min(self._connect_timeout, _remaining(self._deadline)))
            self._check_peer()
            # Assign the TLS socket before its handshake, so the deadline
            # watchdog can interrupt a stalled handshake as well as a read.
            self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host, do_handshake_on_connect=False)
            self.sock.settimeout(min(self._connect_timeout, _remaining(self._deadline)))
            self.sock.do_handshake()
            self._check_peer()
            self.sock.settimeout(_remaining(self._deadline))
        except Exception:
            self.close()
            raise NetworkFailure("Verified TLS connection failed") from None


def _abort_connection(connection) -> None:
    sock = getattr(connection, "sock", None)
    if sock is not None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
    try:
        connection.close()
    except Exception:
        pass


def _set_socket_deadline(connection, deadline: float) -> None:
    remaining = _remaining(deadline)
    sock = getattr(connection, "sock", None)
    if sock is not None:
        sock.settimeout(remaining)


def _bounded_post(connection, path: str, body: bytes, headers: dict[str, str],
                  deadline: float, max_response_bytes: int) -> tuple[int, bytes]:
    timed_out = threading.Event()
    active_socket = [None]
    def abort():
        timed_out.set()
        # HTTP/1.0 or Connection: close can detach the socket from the
        # connection while HTTPResponse still reads its file object.
        if active_socket[0] is not None:
            try:
                active_socket[0].shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
        _abort_connection(connection)
    watchdog = threading.Timer(_remaining(deadline), abort)
    watchdog.daemon = True
    watchdog.start()
    try:
        _set_socket_deadline(connection, deadline)
        connection.request("POST", path, body=body, headers=headers, encode_chunked=False)
        active_socket[0] = getattr(connection, "sock", None)
        _set_socket_deadline(connection, deadline)
        response = connection.getresponse()
        if type(response.status) is not int or not 100 <= response.status <= 599:
            raise NetworkFailure("Invalid HTTP status")
        encoding = response.getheader("Content-Encoding")
        if encoding and encoding.lower().strip() != "identity":
            raise NetworkFailure("Compressed response rejected")
        length = response.getheader("Content-Length")
        if length is not None and (not length.isascii() or not length.isdigit() or int(length) > max_response_bytes):
            raise NetworkFailure("Response size rejected")
        if length is not None and response.getheader("Transfer-Encoding"):
            raise NetworkFailure("Ambiguous response framing")
        chunks, size = [], 0
        while True:
            _set_socket_deadline(connection, deadline)
            chunk = response.read(min(65536, max_response_bytes + 1 - size))
            if type(chunk) is not bytes:
                raise NetworkFailure("Invalid response body")
            size += len(chunk)
            if size > max_response_bytes:
                raise NetworkFailure("Response size rejected")
            if not chunk:
                break
            chunks.append(chunk)
        _remaining(deadline)
        if length is not None and size != int(length):
            raise NetworkFailure("Incomplete response body")
        if timed_out.is_set():
            raise NetworkFailure("Network deadline exceeded")
        return response.status, b"".join(chunks)
    except Exception:
        raise NetworkFailure("HTTP exchange failed") from None
    finally:
        watchdog.cancel()
        _abort_connection(connection)


def _json_object(body: bytes) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError()
            result[key] = value
        return result
    def invalid(_):
        raise ValueError()
    try:
        value = json.loads(body.decode("utf-8"), object_pairs_hook=pairs, parse_constant=invalid)
        if type(value) is not dict:
            raise ValueError()
        return value
    except (ValueError, UnicodeError, RecursionError):
        raise NetworkFailure("Invalid JSON response") from None


def _integer(value, low, high) -> bool:
    return type(value) is int and low <= value <= high


def _validate_bot_params(method: str, params: Mapping[str, Any]) -> dict:
    if type(method) is not str or method not in _READ_METHODS | _WRITE_METHODS or type(params) is not dict:
        raise BotRejected("Unsupported Bot API request")
    allowed = {
        "getUpdates": {"offset", "limit", "timeout", "allowed_updates"},
        "getMe": set(), "getWebhookInfo": set(), "getChat": {"chat_id"},
        "getChatMember": {"chat_id", "user_id"},
        "sendMessage": {"chat_id", "message_thread_id", "text", "link_preview_options", "protect_content", "reply_parameters"},
        "forwardMessage": {"chat_id", "message_thread_id", "from_chat_id", "message_id", "protect_content"},
    }[method]
    if set(params) - allowed:
        raise BotRejected("Unsupported Bot API parameters")
    if method == "getUpdates":
        required = {"offset", "limit", "timeout"}
        if (not required <= set(params) or not _integer(params["offset"], 0, 2**63 - 1)
                or not _integer(params["limit"], 1, 100) or not _integer(params["timeout"], 0, 50)
                or ("allowed_updates" in params and params["allowed_updates"] != ["message"])
                or ("allowed_updates" not in params and (params["offset"] != 0 or params["timeout"] != 0))):
            raise BotRejected("Invalid polling parameters")
    elif method in {"getChat", "getChatMember", "sendMessage", "forwardMessage"}:
        if not _integer(params.get("chat_id"), -(2**52) + 1, -1):
            raise BotRejected("Explicit group ID required")
        if "message_thread_id" in params and not _integer(params["message_thread_id"], 1, 2**31 - 1):
            raise BotRejected("Invalid topic ID")
        if method == "getChatMember" and not _integer(params.get("user_id"), 1, 2**52 - 1):
            raise BotRejected("Explicit user ID required")
        if method in _WRITE_METHODS and params.get("protect_content") is not True:
            raise BotRejected("Protected outbound content required")
        if method == "sendMessage":
            if type(params.get("text")) is not str or not 1 <= len(params["text"]) <= 4096:
                raise BotRejected("Invalid outbound text")
            if params.get("link_preview_options") != {"is_disabled": True}:
                raise BotRejected("Link previews must be disabled")
            if "reply_parameters" in params:
                reply = params["reply_parameters"]
                if (type(reply) is not dict or set(reply) != {"message_id", "allow_sending_without_reply"}
                        or not _integer(reply["message_id"], 1, 2**31 - 1)
                        or reply["allow_sending_without_reply"] is not False):
                    raise BotRejected("Invalid reply binding")
        if method == "forwardMessage" and (not _integer(params.get("from_chat_id"), -(2**52) + 1, -1)
                                           or not _integer(params.get("message_id"), 1, 2**31 - 1)):
            raise BotRejected("Invalid forward source")
    try:
        serialized = json.dumps(params, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
        if len(serialized) > MAX_BODY:
            raise ValueError()
        return json.loads(serialized)
    except (TypeError, ValueError, UnicodeError):
        raise BotRejected("Invalid Bot API payload") from None


class BotHTTPTransport:
    """No retries; live requests occur only when request/helper is called.

    A token is supplied by trusted runtime code, never looked up here. The
    origin is fixed even if a caller supplies an api_origin argument. Operator
    metadata helpers are narrow; this class never changes bot/webhook settings.
    """
    def __init__(self, token: str, *, api_origin: str = TELEGRAM_ORIGIN,
                 connect_timeout: float = 5, request_timeout: float = 10,
                 max_response_bytes: int = 2 * 1024 * 1024):
        if type(token) is not str or not _TOKEN.fullmatch(token):
            raise ValueError("Invalid supplied bot credential")
        if api_origin != TELEGRAM_ORIGIN:
            raise ValueError("Telegram API origin is fixed")
        self._token = token
        self.connect_timeout = _seconds(connect_timeout, "connect timeout")
        self.request_timeout = _seconds(request_timeout, "request timeout")
        self.max_response_bytes = _size(max_response_bytes, 1, 8 * 1024 * 1024)

    def __repr__(self) -> str:
        return "BotHTTPTransport(origin='https://api.telegram.org', credential=<redacted>)"

    async def _resolve_target(self, deadline: float) -> CallbackTarget:
        addresses = await _resolve_with_deadline(resolve_public, "api.telegram.org", deadline)
        return validate_callback(TELEGRAM_ORIGIN + "/", lambda _: addresses)

    def _connection(self, target: CallbackTarget, deadline: float):
        return _PinnedHTTPSConnection(target.hostname, target.port, target.addresses[0],
                                      deadline=deadline, connect_timeout=self.connect_timeout)

    def _exchange(self, target: CallbackTarget, path: str, body: bytes, deadline: float):
        connection = self._connection(target, deadline)
        headers = {"Content-Type": "application/json", "Accept": "application/json",
                   "Accept-Encoding": "identity", "Connection": "close", "Host": "api.telegram.org"}
        return _bounded_post(connection, path, body, headers, deadline, self.max_response_bytes)

    async def request(self, method: str, params: Mapping[str, Any]) -> dict:
        params = _validate_bot_params(method, params)
        # Long polling gets a 10-second network margin; all other requests keep
        # the configured short timeout. DNS and HTTP share the same deadline.
        budget = max(self.request_timeout, params["timeout"] + 10) if method == "getUpdates" else self.request_timeout
        deadline = time.monotonic() + budget
        body = json.dumps(params, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
        sending = method in _WRITE_METHODS
        try:
            target = await self._resolve_target(deadline)
        except asyncio.CancelledError:
            raise
        except Exception:
            # No HTTP worker has started, so this is a definite non-send.
            if sending:
                raise BotRejected("Bot destination resolution failed before send") from None
            raise BotUnavailable("Bot destination unavailable") from None
        try:
            status, raw = await _finish_worker_on_cancel(self._exchange, target, "/bot" + self._token + "/" + method, body, deadline)
            response = _json_object(raw)
            if (status == 200 or 400 <= status < 500) and response.get("ok") is False:
                parameters = response.get("parameters", {})
                retry_after = parameters.get("retry_after") if type(parameters) is dict else None
                if not _integer(retry_after, 1, 86400):
                    retry_after = None
                api_error_code = response.get("error_code")
                if not _integer(api_error_code, 400, 599):
                    api_error_code = status if _integer(status, 400, 599) else None
                raise BotRejected("Telegram explicitly rejected request", retry_after=retry_after,
                                  api_error_code=api_error_code)
            if status != 200 or response.get("ok") is not True or "result" not in response:
                raise NetworkFailure("Unverified Telegram response")
            return response
        except BotRejected:
            raise
        except asyncio.CancelledError:
            raise  # BotApiAdapter records uncertain sends after this cancellation.
        except Exception:
            if sending:
                raise DeliveryUncertain("Bot send outcome is unknown; do not retry automatically") from None
            raise BotUnavailable("Bot request unavailable") from None

    async def get_me(self) -> dict:
        return await self.request("getMe", {})

    async def get_webhook_info(self) -> dict:
        return await self.request("getWebhookInfo", {})

    async def get_chat(self, chat_id: int) -> dict:
        return await self.request("getChat", {"chat_id": chat_id})

    async def get_chat_member(self, chat_id: int, user_id: int) -> dict:
        return await self.request("getChatMember", {"chat_id": chat_id, "user_id": user_id})


def _webhook_headers(headers: Mapping[str, str], hostname: str) -> dict[str, str]:
    names = {"content-type": "Content-Type", "webhook-id": "webhook-id",
             "webhook-timestamp": "webhook-timestamp", "webhook-signature": "webhook-signature",
             "x-mcp-subscription-id": "X-MCP-Subscription-Id"}
    if type(headers) is not dict or len(headers) != len(names):
        raise NetworkFailure("Unexpected webhook headers")
    result = {}
    for name, value in headers.items():
        if type(name) is not str or name.lower() not in names or names[name.lower()] in result:
            raise NetworkFailure("Unexpected webhook headers")
        if type(value) is not str or not 1 <= len(value) <= 2048 or any(ord(c) < 32 or ord(c) > 126 for c in value):
            raise NetworkFailure("Invalid webhook header")
        result[names[name.lower()]] = value
    if result["Content-Type"] != "application/json":
        raise NetworkFailure("Unsupported webhook content type")
    result.update({"Host": "[" + hostname + "]" if ":" in hostname else hostname,
                   "Accept-Encoding": "identity", "Connection": "close"})
    return result


class PinnedWebhookSender:
    """Callable EventHub sender: validated HTTPS to pinned public addresses."""
    def __init__(self, *, resolver=resolve_public, timeout: float = 8,
                 connect_timeout: float = 5, max_response_bytes: int = 64 * 1024):
        if not callable(resolver):
            raise ValueError("Callback resolver required")
        self.resolver = resolver
        self.timeout = _seconds(timeout, "webhook timeout")
        self.connect_timeout = _seconds(connect_timeout, "connect timeout")
        self.max_response_bytes = _size(max_response_bytes, 1, MAX_BODY)

    def _connection(self, target: CallbackTarget, deadline: float):
        return _PinnedHTTPSConnection(target.hostname, target.port, target.addresses[0],
                                      deadline=deadline, connect_timeout=self.connect_timeout)

    def _exchange(self, target: CallbackTarget, body: bytes, headers: dict, deadline: float) -> WebhookResponse:
        parts = urlsplit(target.url)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        status, response = _bounded_post(self._connection(target, deadline), path, body, headers, deadline, self.max_response_bytes)
        return WebhookResponse(status, response)

    async def __call__(self, target: CallbackTarget, body: bytes, headers: dict[str, str]) -> WebhookResponse:
        try:
            if type(target) is not CallbackTarget or target.follow_redirects is not False:
                raise NetworkFailure("Invalid callback target")
            supplied = validate_callback(target.url, lambda _: list(target.addresses))
            if (supplied.url, supplied.hostname, supplied.port, supplied.addresses) != (
                    target.url, target.hostname, target.port, target.addresses):
                raise NetworkFailure("Callback target mismatch")
            if type(body) is not bytes or len(body) > MAX_BODY:
                raise NetworkFailure("Webhook body size rejected")
            safe_headers = _webhook_headers(headers, target.hostname)
            deadline = time.monotonic() + self.timeout
            addresses = await _resolve_with_deadline(self.resolver, target.hostname, deadline)
            fresh = validate_callback(target.url, lambda _: addresses)
            intersection = tuple(address for address in fresh.addresses if address in target.addresses)
            if not intersection:
                raise NetworkFailure("Callback resolution changed; retry requires new validation")
            # Never fall back to hostname dialing or unvalidated alternate IPs.
            pinned = CallbackTarget(fresh.url, fresh.hostname, fresh.port, intersection)
            return await _finish_worker_on_cancel(self._exchange, pinned, body, safe_headers, deadline)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise EventError("Verified webhook transport failed", -32015) from None
