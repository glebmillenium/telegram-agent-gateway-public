"""Authenticated MCP 2 HTTP binding. No listener or network starts on import.

The runtime chooses a loopback bind. This module never reads credentials,
configuration or Telegram sessions. OAuth metadata is public; /mcp is not.
"""
from __future__ import annotations

import asyncio
import base64
import copy
import json
import re
from urllib.parse import urlsplit

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import ClientDisconnect, Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from .auth import AuthenticationDenied, VerifiedPrincipal
from .protocol import MAX_REQUEST_BYTES, ProtocolError, error_response, parse_jsonrpc
from .runtime_auth import www_authenticate

VERSION = "2026-07-28"
VERSION_KEY = "io.modelcontextprotocol/protocolVersion"
_VERSION = re.compile(r"\d{4}-\d{2}-\d{2}\Z")
_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_METADATA_PATHS = {"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"}
_CORS_HEADERS = {"authorization", "content-type", "accept", "mcp-protocol-version", "mcp-method", "mcp-name"}


def _authority(value: str) -> tuple[str, int | None]:
    if not isinstance(value, str) or not value or len(value) > 255 or any(ord(c) <= 32 or ord(c) >= 127 for c in value):
        raise ValueError("Invalid HTTP boundary configuration")
    parsed = urlsplit("//" + value)
    if not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.path or parsed.query or parsed.fragment:
        raise ValueError("Invalid HTTP boundary configuration")
    host, port = parsed.hostname.lower(), parsed.port
    if any(c in host for c in "*\\%") or host.endswith(".") or (port is not None and not 1 <= port <= 65535):
        raise ValueError("Invalid HTTP boundary configuration")
    return host, port


def _origin(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Invalid HTTP boundary configuration")
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or parsed.path or parsed.query or parsed.fragment:
        raise ValueError("Invalid HTTP boundary configuration")
    _authority(parsed.netloc)
    return value


def _single(headers, name, *, required=True):
    values = headers.getlist(name)
    if len(values) != 1 or len(values[0]) > 16384 or any(not (32 <= ord(c) <= 126 or c == "\t") for c in values[0]):
        if not values and not required:
            return None
        raise ProtocolError(-32020, "Invalid transport headers")
    return values[0]


def _decode_name(value: str) -> str:
    if value.startswith("=?base64?") and value.endswith("?="):
        try:
            return base64.b64decode(value[9:-2], validate=True).decode("utf-8")
        except (ValueError, UnicodeError):
            raise ProtocolError(-32020, "Invalid transport headers") from None
    if not value or value.strip() != value or any(not (32 <= ord(c) <= 126 or c == "\t") for c in value):
        raise ProtocolError(-32020, "Invalid transport headers")
    return value


def _accepts_both(value: str) -> bool:
    accepted = set()
    for item in value.lower().split(","):
        parts = [part.strip() for part in item.split(";")]
        quality = 1.0
        for part in parts[1:]:
            if part.startswith("q="):
                try:
                    quality = float(part[2:])
                except ValueError:
                    return False
                if not 0 <= quality <= 1:
                    return False
        if quality > 0:
            accepted.add(parts[0])
    return {"application/json", "text/event-stream"} <= accepted


def _error(error, request_id=None, *, status=400, headers=None):
    return JSONResponse(error_response(error, request_id), status_code=status, headers=headers)


class _Boundary:
    """Host/Origin checks also cover public metadata and preflight requests."""
    def __init__(self, app, *, hosts, origins):
        self.app, self.hosts, self.origins = app, hosts, origins

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        request = Request(scope)
        origin = None
        try:
            host, port = _authority(_single(request.headers, "host"))
            if not any(host == candidate and (wanted_port is None or wanted_port == port) for candidate, wanted_port in self.hosts):
                raise ValueError()
            origin = _single(request.headers, "origin", required=False)
            if origin is not None and (_origin(origin) not in self.origins):
                raise ValueError()
        except (ValueError, ProtocolError):
            return await Response(status_code=403, headers={"Cache-Control": "no-store"})(scope, receive, send)

        async def secure_send(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.extend([(b"cache-control", b"no-store"), (b"x-content-type-options", b"nosniff")])
                if origin is not None:
                    headers.extend([(b"access-control-allow-origin", origin.encode("ascii")),
                                    (b"access-control-expose-headers", b"WWW-Authenticate"),
                                    (b"vary", b"Origin")])
                message = {**message, "headers": headers}
            await send(message)
        await self.app(scope, receive, secure_send)


def create_app(protocol, authenticator, *, resource_metadata: dict | None,
               metadata_url: str, allowed_hosts: set[str], allowed_origins: set[str], lifecycle=None):
    """Create an inert app; caller explicitly starts/stops its local listener.

    Host entries are exact host[:port] authorities; a bare hostname permits any
    valid port. Origins are exact scheme://authority values. No wildcards.
    lifecycle is a Starlette async-contextmanager lifespan callable when used.
    """
    if not isinstance(allowed_hosts, (set, frozenset)) or not allowed_hosts:
        raise ValueError("Explicit allowed hosts are required")
    if not isinstance(allowed_origins, (set, frozenset)):
        raise ValueError("Explicit allowed origins are required")
    hosts = frozenset(_authority(value) for value in allowed_hosts)
    origins = frozenset(_origin(value) for value in allowed_origins)
    # This validates header interpolation without contacting the metadata URL.
    oauth_challenge = www_authenticate(metadata_url)
    metadata = copy.deepcopy(resource_metadata)
    if metadata is not None:
        if type(metadata) is not dict or len(json.dumps(metadata, allow_nan=False).encode()) > MAX_REQUEST_BYTES:
            raise ValueError("Invalid protected-resource metadata")
        if set(metadata) - {"resource", "authorization_servers", "scopes_supported", "bearer_methods_supported"}:
            raise ValueError("Unexpected protected-resource metadata")
    challenge = oauth_challenge if metadata is not None else "Bearer"

    async def public_metadata(request):
        if metadata is None:
            return Response(status_code=404)
        return JSONResponse(metadata)

    async def mcp(request):
        if request.method == "OPTIONS":
            try:
                if not origins or _single(request.headers, "origin") not in origins:
                    return Response(status_code=403)
                if _single(request.headers, "access-control-request-method") != "POST":
                    return Response(status_code=403)
                value = _single(request.headers, "access-control-request-headers", required=False) or ""
                requested = {item.strip().lower() for item in value.split(",") if item.strip()}
                if not requested <= _CORS_HEADERS or any(not _TOKEN.fullmatch(item) for item in requested):
                    return Response(status_code=403)
                return Response(status_code=204, headers={"Access-Control-Allow-Methods": "POST",
                    "Access-Control-Allow-Headers": ", ".join(sorted(_CORS_HEADERS))})
            except ProtocolError:
                return Response(status_code=403)
        if request.method != "POST":
            return Response(status_code=405, headers={"Allow": "POST"})
        # Authentication precedes body parsing or protocol discovery. Nothing
        # supplied in JSON/query/cookie/forwarded headers can choose identity.
        try:
            authorization = _single(request.headers, "authorization", required=False)
            principal = authenticator.authenticate(authorization)
            if type(principal) is not VerifiedPrincipal or not principal.authenticated:
                raise AuthenticationDenied("Authentication required")
        except (AuthenticationDenied, ProtocolError):
            return _error(ProtocolError(-33001, "Authentication required"), status=401,
                          headers={"WWW-Authenticate": challenge})
        except Exception:
            return _error(ProtocolError(-32603, "Internal error"), status=500)
        request_id = None
        try:
            content_type = _single(request.headers, "content-type")
            parts = [part.strip().lower() for part in content_type.split(";")]
            if parts[0] != "application/json" or any(part not in {"charset=utf-8", 'charset="utf-8"'} for part in parts[1:]):
                return _error(ProtocolError(-32020, "JSON content type required"), status=415)
            if not _accepts_both(_single(request.headers, "accept")):
                return _error(ProtocolError(-32020, "JSON and SSE acceptance required"), status=406)
            encoding = _single(request.headers, "content-encoding", required=False)
            if encoding is not None and encoding.lower() != "identity":
                return _error(ProtocolError(-32020, "Content encoding unsupported"), status=415)
            length = _single(request.headers, "content-length", required=False)
            if length is not None and (not length.isascii() or not length.isdigit() or len(length) > 20):
                raise ProtocolError(-32020, "Invalid transport headers")
            if length is not None and int(length) > MAX_REQUEST_BYTES:
                return _error(ProtocolError(-32600, "Request too large"), status=413)
            raw = bytearray()
            async with asyncio.timeout(10):
                async for chunk in request.stream():
                    if len(raw) + len(chunk) > MAX_REQUEST_BYTES:
                        return _error(ProtocolError(-32600, "Request too large"), status=413)
                    raw.extend(chunk)
            if length is not None and len(raw) != int(length):
                raise ProtocolError(-32020, "Invalid transport headers")
            payload = parse_jsonrpc(bytes(raw))
            if type(payload) is not dict:
                raise ProtocolError(-32600, "Invalid request")
            if payload.get("jsonrpc") != "2.0" or type(payload.get("method")) is not str or set(payload) - {"jsonrpc", "id", "method", "params"}:
                raise ProtocolError(-32600, "Invalid request")
            # HTTP MCP2 defines no accepted client notifications. Do not invoke
            # methods or emit a response with an invented JSON-RPC request ID.
            if "id" not in payload and payload.get("jsonrpc") == "2.0" and isinstance(payload.get("method"), str):
                return Response(status_code=400)
            candidate_id = payload.get("id")
            if type(candidate_id) not in (int, str):
                raise ProtocolError(-32600, "Invalid request ID")
            if type(candidate_id) is int or (type(candidate_id) is str and len(candidate_id) <= 256):
                request_id = candidate_id
            method = payload.get("method")
            params = payload.get("params", {})
            meta = params.get("_meta", {}) if type(params) is dict else {}
            body_version = meta.get(VERSION_KEY) if type(meta) is dict else None
            version = _single(request.headers, "mcp-protocol-version")
            if not _VERSION.fullmatch(version) or version != body_version:
                raise ProtocolError(-32020, "Invalid transport headers")
            if version != VERSION:
                raise ProtocolError(-32022, "Unsupported protocol version", {"supported": [VERSION], "requested": version})
            if _single(request.headers, "mcp-method") != method:
                raise ProtocolError(-32020, "Invalid transport headers")
            if method in {"tools/call", "resources/read", "prompts/get"}:
                source = params.get("uri" if method == "resources/read" else "name") if type(params) is dict else None
                if _decode_name(_single(request.headers, "mcp-name")) != source:
                    raise ProtocolError(-32020, "Invalid transport headers")
            elif request.headers.getlist("mcp-name"):
                # There is no mirrored name on these methods. Extra routing
                # names could disagree with an intermediary's policy.
                raise ProtocolError(-32020, "Invalid transport headers")
            result = await protocol.request_authenticated(payload, principal)
            if result is None:
                return Response(status_code=400)
            code = result.get("error", {}).get("code") if type(result) is dict else None
            status = {-32700: 400, -32600: 400, -32601: 404, -32602: 400,
                      -32020: 400, -32022: 400, -33001: 403, -32603: 500}.get(code, 200)
            return JSONResponse(result, status_code=status)
        except ProtocolError as error:
            return _error(error, request_id)
        except (TimeoutError, ClientDisconnect):
            return _error(ProtocolError(-32600, "Request incomplete"), status=400)
        except Exception:
            return _error(ProtocolError(-32603, "Internal error"), request_id, status=500)

    routes = [Route("/mcp", mcp, methods=["POST", "GET", "DELETE", "PUT", "PATCH", "HEAD", "OPTIONS"])]
    routes += [Route(path, public_metadata, methods=["GET", "HEAD"]) for path in sorted(_METADATA_PATHS)]
    return Starlette(routes=routes, middleware=[Middleware(_Boundary, hosts=hosts, origins=origins)], lifespan=lifecycle)
