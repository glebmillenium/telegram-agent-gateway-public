"""One-way Grok Routine webhook outbox; no listener or automatic activation.

Grok's documented contract is JSON POST + Bearer, with HTTP 200 acknowledging
that a run started, not that it completed. This is NOT an MCP Events callback.
There is no documented remote idempotency guarantee: ambiguous attempts are
terminal ``unknown`` and never replayed automatically. All I/O is injected.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import hashlib
import inspect
import json
import math
import re
import sqlite3
import time
from urllib.parse import urlsplit

from .auth import VerifiedPrincipal, _principal_id
from .events import (
    CallbackTarget, EVENT_NAME, WebhookResponse, _DeliveryProcessLock,
    _callback_url, _external_path, _payload, validate_callback,
)
from .local_secrets import validate_bot_name

MAX_QUEUE = 1000
MAX_BODY = 64 * 1024
ATTEMPT_TIMEOUT = 10
STATES = ("queued", "sending", "accepted", "unknown", "rejected", "expired", "revoked")
_IDENTIFIER = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_EVENT_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
_BEARER = re.compile(r"[A-Za-z0-9._~+/=-]{1,4096}\Z")


class GrokRoutineError(ValueError):
    """Sanitized diagnostic: never include URL, body, reference or credentials."""


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _ref_identity(reference):
    if reference is None:
        return None
    if type(reference) is str and _IDENTIFIER.fullmatch(reference):
        return ["fixture_reference", reference]
    # Only inspect the typed reference; never read its file, environment or key.
    from .runtime_config import SecretRef
    if type(reference) is SecretRef and reference.kind in {"env", "file", "dpapi_file", "local_webhook"} and type(reference.value) is str:
        return [reference.kind, reference.value]
    raise GrokRoutineError("Routine credential reference rejected")


@dataclass(frozen=True, slots=True)
class Route:
    route_id: str
    principal_id: str
    bot_reference: str
    url: str = field(repr=False)
    bearer_ref: object | None = field(default=None, repr=False)
    addressing: str = "mentions_or_replies"

    def __post_init__(self):
        try:
            if type(self.route_id) is not str or not _IDENTIFIER.fullmatch(self.route_id):
                raise ValueError()
            if type(self.addressing) is not str or self.addressing != "mentions_or_replies":
                raise ValueError()
            _principal_id(self.principal_id)
            if validate_bot_name(self.bot_reference) != self.bot_reference:
                raise ValueError()
            canonical, _, _ = _callback_url(self.url)
            _ref_identity(self.bearer_ref)
            object.__setattr__(self, "url", canonical)
        except Exception:
            raise GrokRoutineError("Routine route rejected") from None

    def fingerprint(self):
        return hashlib.sha256(_json([self.route_id, self.principal_id, self.bot_reference,
                                    self.url, _ref_identity(self.bearer_ref), self.addressing]).encode()).hexdigest()


class _BearerHeaders(dict):
    def __repr__(self):
        return "<Grok routine headers: credentials redacted>"

    __str__ = __repr__


def authorization_headers(value):
    if (type(value) is not str or not 1 <= len(value) <= 4096
            or value != value.strip() or any(not 32 <= ord(c) <= 126 for c in value)):
        raise GrokRoutineError("Routine credential rejected")
    return _BearerHeaders({"Content-Type": "application/json", "Authorization": value})


def bearer_headers(value):
    if type(value) is not str or not _BEARER.fullmatch(value):
        raise GrokRoutineError("Routine credential rejected")
    return authorization_headers("Bearer " + value)


def _headers(headers, hostname):
    if not isinstance(headers, dict) or set(headers) != {"Content-Type", "Authorization"}:
        raise GrokRoutineError("Routine headers rejected")
    value = headers["Authorization"]
    if headers["Content-Type"] != "application/json":
        raise GrokRoutineError("Routine headers rejected")
    result = authorization_headers(value)
    result.update({"Host": "[" + hostname + "]" if ":" in hostname else hostname,
                   "Accept-Encoding": "identity", "Connection": "close"})
    return result


class PinnedGrokRoutineSender:
    """Concrete HTTPS sender, inert until explicitly injected and called.

    The sink resolves/validates every attempt, then rechecks authorization.
    Dial only that literal public address with original-host TLS verification;
    no second DNS lookup, proxies, redirects, fallback addresses or retries.
    """

    def __init__(self, *, timeout=8, connect_timeout=5, max_response_bytes=8192):
        from .network import _seconds, _size
        self.timeout = _seconds(timeout, "routine timeout")
        self.connect_timeout = _seconds(connect_timeout, "routine connect timeout")
        self.max_response_bytes = _size(max_response_bytes, 1, MAX_BODY)

    def _connection(self, target, deadline):
        from .network import _PinnedHTTPSConnection
        return _PinnedHTTPSConnection(target.hostname, target.port, target.addresses[0],
                                      deadline=deadline, connect_timeout=self.connect_timeout)

    def _exchange(self, target, body, headers, deadline):
        from .network import _bounded_post
        parts = urlsplit(target.url)
        path = (parts.path or "/") + ("?" + parts.query if parts.query else "")
        status, _ = _bounded_post(self._connection(target, deadline), path, body, headers,
                                 deadline, self.max_response_bytes)
        return WebhookResponse(status)

    async def __call__(self, target, body, headers):
        from .network import _finish_worker_on_cancel
        try:
            if type(target) is not CallbackTarget or target.follow_redirects is not False:
                raise ValueError()
            checked = validate_callback(target.url, lambda _: list(target.addresses))
            if checked != target or type(body) is not bytes or len(body) > MAX_BODY:
                raise ValueError()
            safe_headers = _headers(headers, target.hostname)
            deadline = time.monotonic() + self.timeout
            return await _finish_worker_on_cancel(self._exchange, target, body, safe_headers, deadline)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise GrokRoutineError("Routine HTTPS delivery failed") from None


class GrokRoutineSink:
    def __init__(self, db_path, route: Route, authorizer, secret_loader, sender=None, resolver=None,
                 clock=time.time, *, max_age_seconds=3600, event_filter=None):
        if type(route) is not Route or not callable(authorizer) or not callable(secret_loader):
            raise GrokRoutineError("Routine dependencies rejected")
        if type(max_age_seconds) is not int or not 60 <= max_age_seconds <= 3600:
            raise GrokRoutineError("Routine expiry rejected")
        if sender is not None and not callable(sender) or resolver is not None and not callable(resolver):
            raise GrokRoutineError("Routine transport rejected")
        if event_filter is not None and not callable(event_filter):
            raise GrokRoutineError("Routine event filter rejected")
        self.path = _external_path(db_path)
        self.route, self.authorizer, self.secret_loader = route, authorizer, secret_loader
        self.sender, self.resolver, self.clock = sender, resolver, clock
        self.max_age_seconds = max_age_seconds
        self.event_filter = event_filter
        self._lock = asyncio.Lock()
        self.db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        try:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.executescript("""
                CREATE TABLE IF NOT EXISTS grok_routes (
                    route_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS grok_outbox (
                    route_id TEXT NOT NULL, event_id TEXT NOT NULL, payload_hash TEXT NOT NULL,
                    body BLOB NOT NULL, created REAL NOT NULL, expires REAL NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('queued','sending','accepted','unknown','rejected','expired','revoked')),
                    claimed REAL, http_status INTEGER,
                    PRIMARY KEY(route_id,event_id)
                );
                CREATE INDEX IF NOT EXISTS grok_queued ON grok_outbox(route_id,status,created);
            """)
            with _DeliveryProcessLock(self._lock_path()) as acquired:
                if not acquired:
                    raise GrokRoutineError("Routine outbox is in use")
                self.db.execute("BEGIN IMMEDIATE")
                try:
                    old = self.db.execute("SELECT fingerprint FROM grok_routes WHERE route_id=?", (route.route_id,)).fetchone()
                    if old is not None and old[0] != route.fingerprint():
                        raise GrokRoutineError("Routine state belongs to another route")
                    self.db.execute("INSERT OR IGNORE INTO grok_routes VALUES(?,?)", (route.route_id, route.fingerprint()))
                    # No receipt was durable. A run might already exist remotely.
                    self.db.execute("UPDATE grok_outbox SET status='unknown',body=X'' WHERE route_id=? AND status='sending'", (route.route_id,))
                    self.db.execute("COMMIT")
                except BaseException:
                    self.db.execute("ROLLBACK")
                    raise
        except BaseException:
            self.db.close()
            raise

    def _lock_path(self):
        return self.path.with_name(self.path.name + ".routine-consumer.lock")

    def close(self):
        if self._lock.locked():
            raise GrokRoutineError("Routine dispatch must stop before closing")
        self.db.close()

    def _identity(self, principal, bot_reference):
        if (type(principal) is not VerifiedPrincipal or not principal.authenticated
                or principal.id != self.route.principal_id or bot_reference != self.route.bot_reference):
            raise GrokRoutineError("Routine access denied")

    def _authorize(self, principal, bot_reference, data):
        self._identity(principal, bot_reference)
        try:
            actual = {"chat_id": data["chat_id"], "topic_id": data.get("topic_id")}
            normalized = _payload(actual, data)
            result = self.authorizer(principal, EVENT_NAME, actual)
            if result is not None:
                if inspect.iscoroutine(result):
                    result.close()
                raise ValueError()
            if self.event_filter is not None:
                accepted = self.event_filter(normalized)
                if accepted is not True:
                    if inspect.iscoroutine(accepted):
                        accepted.close()
                    raise ValueError()
            return normalized
        except Exception:
            raise GrokRoutineError("Routine event access denied") from None

    def enqueue(self, principal, event_id, payloadscope, *, bot_reference, occurred_at=None):
        data = self._authorize(principal, bot_reference, payloadscope)
        if type(event_id) is not str or not _EVENT_ID.fullmatch(event_id):
            raise GrokRoutineError("Routine event ID rejected")
        try:
            body = _json({"eventId": event_id, "type": EVENT_NAME, "data": data}).encode("utf-8")
        except (ValueError, UnicodeError, TypeError):
            raise GrokRoutineError("Routine event rejected") from None
        if len(body) > MAX_BODY:
            raise GrokRoutineError("Routine event size rejected")
        now = self.clock()
        when = now if occurred_at is None else occurred_at
        if type(when) not in (float, int) or (type(when) is float and not math.isfinite(when)):
            raise GrokRoutineError("Routine event timestamp rejected")
        expires = min(now, when) + self.max_age_seconds
        digest = hashlib.sha256(body).hexdigest()
        self.db.execute("BEGIN IMMEDIATE")
        try:
            existing = self.db.execute("SELECT payload_hash FROM grok_outbox WHERE route_id=? AND event_id=?", (self.route.route_id, event_id)).fetchone()
            if existing is not None:
                if existing[0] != digest:
                    raise GrokRoutineError("Routine event ID already has another payload")
                self.db.execute("COMMIT")
                return False
            self.db.execute("UPDATE grok_outbox SET status='expired',body=X'' WHERE route_id=? AND status='queued' AND expires<=?", (self.route.route_id, now))
            outstanding = self.db.execute("SELECT COUNT(*) FROM grok_outbox WHERE route_id=? AND status IN ('queued','sending','unknown')", (self.route.route_id,)).fetchone()[0]
            if outstanding >= MAX_QUEUE:
                raise GrokRoutineError("Routine queue capacity reached")
            status = "queued" if expires > now else "expired"
            self.db.execute("INSERT INTO grok_outbox VALUES(?,?,?,?,?,?,?,NULL,NULL)",
                            (self.route.route_id, event_id, digest, body if status == "queued" else b"", now, expires, status))
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
        return True

    def _finish(self, row, state, http_status=None):
        self.db.execute("UPDATE grok_outbox SET status=?,body=X'',http_status=? WHERE route_id=? AND event_id=? AND status IN ('queued','sending')",
                        (state, http_status, self.route.route_id, row["event_id"]))

    def _guard(self, principal, bot_reference, row, data):
        try:
            self._authorize(principal, bot_reference, data)
        except Exception:
            self._finish(row, "revoked")
            raise GrokRoutineError("Routine event authorization changed") from None
        latest = self.db.execute("SELECT status,expires FROM grok_outbox WHERE route_id=? AND event_id=?", (self.route.route_id, row["event_id"])).fetchone()
        if latest is None or latest["status"] != "sending":
            raise GrokRoutineError("Routine event is no longer dispatchable")
        if latest["expires"] <= self.clock():
            self._finish(row, "expired")
            raise GrokRoutineError("Routine event expired")

    async def dispatch_once(self, principal, *, bot_reference):
        self._identity(principal, bot_reference)
        if self.sender is None:
            return {"status": "unavailable", "run_completed": False}
        async with self._lock:
            with _DeliveryProcessLock(self._lock_path()) as acquired:
                if not acquired:
                    return {"status": "busy", "run_completed": False}
                row = self.db.execute("SELECT * FROM grok_outbox WHERE route_id=? AND status='queued' ORDER BY created,event_id LIMIT 1", (self.route.route_id,)).fetchone()
                if row is None:
                    return {"status": "idle", "run_completed": False}
                if row["expires"] <= self.clock():
                    self._finish(row, "expired")
                    return {"status": "expired", "run_completed": False}
                try:
                    envelope = json.loads(row["body"])
                    if (set(envelope) != {"eventId", "type", "data"} or envelope["eventId"] != row["event_id"]
                            or envelope["type"] != EVENT_NAME or hashlib.sha256(row["body"]).hexdigest() != row["payload_hash"]):
                        raise ValueError()
                    data = self._authorize(principal, bot_reference, envelope["data"])
                except Exception:
                    self._finish(row, "revoked")
                    return {"status": "revoked", "run_completed": False}
                # Durable claim precedes DNS, secret loading and all external I/O.
                claimed = self.db.execute("UPDATE grok_outbox SET status='sending',claimed=? WHERE route_id=? AND event_id=? AND status='queued'",
                                          (self.clock(), self.route.route_id, row["event_id"])).rowcount
                if claimed != 1:
                    return {"status": "busy", "run_completed": False}
                started_http = False

                async def attempt():
                    nonlocal started_http
                    target = await asyncio.to_thread(validate_callback, self.route.url, self.resolver)
                    try:
                        self._guard(principal, bot_reference, row, data)
                    except Exception:
                        self._finish(row, "revoked")
                        raise GrokRoutineError("Routine event authorization changed") from None
                    credential = self.secret_loader(self.route.bearer_ref)
                    if inspect.isawaitable(credential):
                        if inspect.iscoroutine(credential):
                            credential.close()
                        raise GrokRoutineError("Routine credential loader must be synchronous")
                    headers = (authorization_headers(credential)
                               if getattr(self.route.bearer_ref, "kind", None) == "local_webhook"
                               else bearer_headers(credential))
                    self._guard(principal, bot_reference, row, data)
                    started_http = True
                    response = await self.sender(target, row["body"], headers)
                    if type(response) is not WebhookResponse or type(response.status) is not int or not 100 <= response.status <= 599:
                        raise GrokRoutineError("Routine response rejected")
                    return response.status

                try:
                    http_status = await asyncio.wait_for(attempt(), timeout=ATTEMPT_TIMEOUT)
                    # A server failure can follow server-side work even without
                    # a success receipt; never claim it proves no run occurred.
                    outcome = "accepted" if http_status == 200 else "unknown" if http_status >= 500 else "rejected"
                    self._finish(row, outcome, http_status)
                except asyncio.CancelledError:
                    self._finish(row, "unknown")
                    raise
                except Exception:
                    self._finish(row, "unknown" if started_http else "rejected")
                latest = self.db.execute("SELECT status FROM grok_outbox WHERE route_id=? AND event_id=?", (self.route.route_id, row["event_id"])).fetchone()
                return {"status": latest["status"], "run_completed": False}

    def status(self, principal, *, bot_reference):
        self._identity(principal, bot_reference)
        counts = dict.fromkeys(STATES, 0)
        for row in self.db.execute("SELECT status,COUNT(*) AS n FROM grok_outbox WHERE route_id=? GROUP BY status", (self.route.route_id,)):
            counts[row["status"]] = row["n"]
        return {"queue": counts, "run_completion_verified": False}

    def revoke(self, principal, *, bot_reference):
        self._identity(principal, bot_reference)
        # An in-flight request may already have started a remote run. Mark it
        # unknown; queued rows can be revoked with certainty.
        self.db.execute("UPDATE grok_outbox SET status=CASE WHEN status='sending' THEN 'unknown' ELSE 'revoked' END,body=X'' WHERE route_id=? AND status IN ('queued','sending')", (self.route.route_id,))
