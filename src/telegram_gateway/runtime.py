"""Foreground gateway runtime. Live I/O requires explicit configuration AND CLI opt-in."""
from __future__ import annotations

import argparse
import asyncio
from contextlib import asynccontextmanager
import json
import re
import sqlite3
from pathlib import Path
import time

from .auth import FakeAuthenticator, OwnerApprovalVerifier, PrincipalAuthority
from .bot_api import BotApiAdapter, FakeBotTransport, BotRejected, BotUnavailable
from .events import EventHub, SQLiteSecretStore, WebhookResponse
from .policy import GatewayDenied, Scope
from .protocol import Protocol, parse_jsonrpc
from .runtime_auth import OAuthAuthenticator, StaticBearerAuthenticator
from .runtime_config import RuntimeConfig, load_secret
from .service import Gateway, ProcessLock, StateStore, ConsumerBusy


class RuntimeBlocked(ValueError):
    """Safe operator diagnostic, never raw credentials or request data."""


def configuration_status(cfg):
    return {"mode": cfg.mode, "configured_principals": len(cfg.principals),
            "network_enabled": cfg.network_enabled, "outbound_enabled": cfg.outbound_enabled,
            "authentication": cfg.auth_mode, "secrets_read": False,
            "telegram_checked": False, "dot_wakeup_verified": False,
            "ready_to_start": cfg.mode == "fake" or (cfg.mode == "live" and cfg.network_enabled)}


def make_authenticator(cfg):
    if cfg.auth_mode == "fake" and cfg.mode == "fake":
        return FakeAuthenticator(cfg.auth["credentials"])
    if cfg.auth_mode == "static":
        return StaticBearerAuthenticator(cfg.auth["token_digests"])
    if cfg.auth_mode == "oauth":
        # Public JWKS only. There is no token acquisition or online key discovery.
        path = cfg.auth["jwks_file"]
        if path.stat().st_size > 256 * 1024:
            raise RuntimeBlocked("Public JWKS file exceeds limit")
        jwks = parse_jsonrpc(path.read_bytes())
        return OAuthAuthenticator(**{key: value for key, value in cfg.auth.items()
                                    if key not in {"mode", "jwks_file"}}, jwks=jwks)
    raise RuntimeBlocked("Runtime authentication is not configured")


async def verify_bot_identity(cfg, transport):
    """Read-only preflight; no webhook deletion, chats discovery, or identity guessing."""
    def result(value):
        if type(value) is not dict or value.get("ok") is not True or type(value.get("result")) is not dict:
            raise RuntimeBlocked("Bot identity preflight failed")
        return value["result"]
    me = result(await transport.get_me())
    if type(me.get("id")) is not int or me.get("id") != cfg.expected_bot_id or me.get("is_bot") is not True:
        raise RuntimeBlocked("Bot identity does not match approved configuration")
    if cfg.bot_reference is not None:
        from .local_secrets import LocalSecretsError, validate_bot_name
        try:
            matches = validate_bot_name(me.get("username")) == cfg.bot_reference
        except LocalSecretsError:
            matches = False
        if not matches:
            raise RuntimeBlocked("Bot identity does not match approved configuration")
    webhook = result(await transport.get_webhook_info())
    if webhook.get("url") != "":
        raise RuntimeBlocked("Existing webhook prevents exclusive polling; no webhook was changed")
    for expected in cfg.approved_groups:
        chat = result(await transport.get_chat(expected["chat_id"]))
        if (type(chat.get("id")) is not int or chat.get("id") != expected["chat_id"] or chat.get("type") != expected["type"]
                or chat.get("title") != expected["title"] or chat.get("username")
                or chat.get("active_usernames")):
            raise RuntimeBlocked("Group identity does not match approved private group")
        own_member = result(await transport.get_chat_member(expected["chat_id"], cfg.expected_bot_id))
        own_user = own_member.get("user")
        if (type(own_user) is not dict or type(own_user.get("id")) is not int
                or own_user.get("id") != cfg.expected_bot_id
                or own_member.get("status") not in {"member", "administrator", "creator"}):
            raise RuntimeBlocked("Bot is not a member of an approved group")
    if cfg.review_scope is not None:
        for owner_id in cfg.owner_ids:
            member = result(await transport.get_chat_member(cfg.review_scope.chat_id, owner_id))
            owner_user = member.get("user")
            if (type(owner_user) is not dict or type(owner_user.get("id")) is not int
                    or owner_user.get("id") != owner_id or owner_user.get("is_bot") is not False
                    or member.get("status") not in {"member", "administrator", "creator"}):
                raise RuntimeBlocked("Approval owner identity could not be verified")


class RuntimeGateway(Gateway):
    def __init__(self, *args, mode, outbound_enabled, **kwargs):
        super().__init__(*args, **kwargs)
        self.mode, self.outbound_enabled = mode, outbound_enabled
        self.last_poll_at = None
        self.poll_state = "starting"
        self.status_write_state = "ok"

    def _health(self):
        if self.status_write_state != "ok" or self.poll_state == "retrying":
            return "degraded"
        return "ok" if self.poll_state == "ok" else "starting"

    def ping(self, p):
        result = super().ping(p)
        result.update(backend="bot-api" if self.mode == "live" else "fake", mode=self.mode,
                      telegram_connected=self.mode == "live" and self.poll_state == "ok",
                      health=self._health())
        return result

    def status(self, p):
        result = super().status(p)
        result.update(mode=self.mode, live_transport_configured=self.mode == "live",
                      outbound_enabled=self.outbound_enabled, poll_state=self.poll_state,
                      last_poll_at=self.last_poll_at,
                      health=self._health(), status_write_state=self.status_write_state)
        return result

    async def send_draft(self, p, draft_id):
        if not self.outbound_enabled:
            raise GatewayDenied("Outbound delivery is disabled by runtime configuration")
        return await super().send_draft(p, draft_id)


class Runtime:
    def __init__(self, cfg, *, allow_live=False, transport=None, sender=None, resolver=None, authenticator=None,
                 routine_sender=None, routine_resolver=None, routine_secret_loader=None):
        if cfg.mode == "disabled":
            raise RuntimeBlocked("Runtime is disabled")
        if cfg.mode == "live" and not (allow_live and cfg.network_enabled):
            raise RuntimeBlocked("Live mode needs approved configuration and --allow-live-network")
        if cfg.review_scope is not None and cfg.review_scope.all_topics:
            raise RuntimeBlocked("Approval review scope must be exact")
        self.cfg, self.transport, self.sender, self.resolver = cfg, transport, sender, resolver
        self.auth = make_authenticator(cfg) if authenticator is None else authenticator
        self.principals = tuple(PrincipalAuthority().restore(name) for name in cfg.principals)
        self.store = self.hub = self.secrets = self.gateway = self.lock = None
        self.tasks = []
        self.fake_callbacks = []
        self.stopping = False
        self.routine_sender, self.routine_resolver = routine_sender, routine_resolver
        self.routine_secret_loader = routine_secret_loader
        self.routine_sinks, self.routine_status = {}, {}
        # Written only to the local operator status file, not agent MCP results.
        self.poll_diagnostics = {
            "started_at": time.time(), "successful_polls": 0, "failed_polls": 0,
            "updates_received": 0, "messages_accepted": 0,
            "message_rows_stored": 0, "event_rows_created": 0,
            "allowed_updates": ["message"], "last_batch": None, "last_error": None,
        }

    async def start(self):
        cfg = self.cfg
        cfg.state_dir.mkdir(parents=True, exist_ok=True)
        self.lock = ProcessLock(cfg.state_dir / "runtime.lock")
        self.lock.__enter__()
        try:
            if cfg.mode == "live":
                from .network import BotHTTPTransport, PinnedWebhookSender, resolve_public
                if self.transport is None:
                    token = load_secret(cfg.bot_token_ref, secrets_dir=cfg.secrets_dir, live_mode=True)
                    self.transport = BotHTTPTransport(token)
                await verify_bot_identity(cfg, self.transport)
                self.sender = self.sender or PinnedWebhookSender()
                self.resolver = self.resolver or resolve_public
                # Pre-existing, separately protected directory. No ACLs or OS identity changes.
                if not cfg.secrets_dir.is_dir():
                    raise RuntimeBlocked("Protected secrets directory must exist before live startup")
                secret_path = cfg.secrets_dir / "callback-secrets.sqlite"
            else:
                self.transport = self.transport or FakeBotTransport()
                secret_path = cfg.state_dir / "fake-callback-secrets.sqlite"
                self.sender = self.sender or self._fake_receiver
                self.resolver = self.resolver or (lambda _: ["8.8.8.8"])
            grants = {scope for principal in self.principals
                      for action in ("history", "events", "draft", "send", "forward")
                      for scope in cfg.policy.allowed_scopes(principal, action)}
            scopes = {(scope.chat_id, scope.topic_id) for scope in grants if not scope.all_topics}
            all_topic_chats = {scope.chat_id for scope in grants if scope.all_topics}
            if cfg.review_scope is not None:
                scopes.add((cfg.review_scope.chat_id, cfg.review_scope.topic_id))
            bot = BotApiAdapter(self.transport, allowed_scopes=scopes,
                                allowed_all_topic_chats=all_topic_chats)
            owner = OwnerApprovalVerifier(cfg.owner_ids, [cfg.review_scope]) if cfg.review_scope is not None else None
            self.store = StateStore(cfg.state_dir / "gateway.sqlite")
            identity = {"mode": cfg.mode, "bot_id": cfg.expected_bot_id if cfg.mode == "live" else None}
            if cfg.bot_reference is not None:
                identity["bot_reference"] = cfg.bot_reference
            namespace = json.dumps(identity, sort_keys=True)
            with self.store.transaction() as db:
                previous = db.execute("SELECT value FROM gw_meta WHERE key='runtime_namespace'").fetchone()
                if previous is None:
                    occupied = any(db.execute("SELECT COUNT(*) FROM " + table).fetchone()[0]
                                   for table in ("gw_messages", "gw_events", "gw_drafts"))
                    if occupied:
                        raise RuntimeBlocked("Existing state requires an explicit migration; fake drafts cannot become live")
                    db.execute("INSERT INTO gw_meta VALUES('runtime_namespace',?)", (namespace,))
                elif previous[0] != namespace:
                    raise RuntimeBlocked("State belongs to another backend or bot")
            self.gateway = RuntimeGateway(self.store, cfg.policy, self.principals, bot, owner_verifier=owner,
                                          mode=cfg.mode, outbound_enabled=cfg.outbound_enabled,
                                          bot_reference=cfg.bot_reference,bot_id=cfg.expected_bot_id,
                                          standing_send=self._standing_policy())
            self.gateway.recover_uncertain()
            self.secrets = SQLiteSecretStore(secret_path)
            self.hub = EventHub(cfg.state_dir / "events.sqlite", self._event_authorize,
                                sender=self.sender, resolver=self.resolver, secret_store=self.secrets,
                                principal_factory=PrincipalAuthority().restore,
                                catalog_authorizer=lambda p: bool(cfg.policy.allowed_scopes(p, "events")),
                                callback_authorizer=self._callback_authorize)
            self.protocol = Protocol(self.auth, self.gateway, self.hub)
            self._setup_routines()
            self._write_status("running")
        except BaseException:
            await self.close()
            raise

    def _routine_path(self, fingerprint):
        if type(fingerprint) is not str or len(fingerprint) != 64 or any(c not in "0123456789abcdef" for c in fingerprint):
            raise RuntimeBlocked("Routine state identity is invalid")
        return self.cfg.state_dir / ("routine-" + fingerprint + ".sqlite")

    def _retire_routine(self, row):
        # The root/child runtime lock excludes another process. Retire old
        # queued work before a route is removed, rotated or re-enabled.
        path = self._routine_path(row["fingerprint"])
        if path.is_file():
            db = sqlite3.connect(path, isolation_level=None)
            try:
                db.execute("UPDATE grok_outbox SET status=CASE WHEN status='sending' THEN 'unknown' ELSE 'revoked' END,body=X'' WHERE route_id=? AND status IN ('queued','sending')", (row["route_id"],))
            finally:
                db.close()
        self.store.db.execute("UPDATE gw_routine_exports SET enabled=0 WHERE route_id=?", (row["route_id"],))

    def _setup_routines(self):
        from .grok_routine import Route, GrokRoutineSink
        configured = self.cfg.routine_routes
        exists = self.store.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='gw_routine_exports'").fetchone()
        if not configured and not exists:
            return
        self.store.db.execute("""CREATE TABLE IF NOT EXISTS gw_routine_exports(
            route_id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, bot_reference TEXT NOT NULL,
            fingerprint TEXT NOT NULL, cursor INTEGER NOT NULL, enabled INTEGER NOT NULL)""")
        old_rows = self.store.db.execute("SELECT * FROM gw_routine_exports").fetchall()
        for row in old_rows:
            current = configured.get(row["route_id"])
            try:
                if current is None or Route(**current).fingerprint() != row["fingerprint"]:
                    self._retire_routine(row)
            except Exception:
                # No fallback to old route/secret. Its authorizer also denies
                # changed configuration even when retirement storage failed.
                self.routine_status[row["route_id"]] = "unavailable"
        if not configured:
            return
        sender, resolver, loader = self.routine_sender, self.routine_resolver, self.routine_secret_loader
        if self.cfg.mode == "live":
            from .grok_routine import PinnedGrokRoutineSender
            from .network import resolve_public
            sender = sender or PinnedGrokRoutineSender()
            resolver = resolver or resolve_public
        elif not all(callable(value) for value in (sender, resolver, loader)):
            # Fake mode never falls back to DNS, environment/files or HTTP.
            sender, resolver, loader = None, (lambda _: []), self._routine_secret_unavailable
        for route_id, fields in configured.items():
            try:
                route = Route(**fields)
                if (route_id != route.route_id or route.bot_reference != self.cfg.bot_reference
                        or self.cfg.agent_bindings.get(route.principal_id) != route.bot_reference
                        or route.principal_id not in self.cfg.principals):
                    raise RuntimeBlocked("Routine binding is unavailable")
                previous = self.store.db.execute("SELECT * FROM gw_routine_exports WHERE route_id=?", (route_id,)).fetchone()
                if previous is None or not previous["enabled"] or previous["fingerprint"] != route.fingerprint():
                    if previous is not None:
                        self._retire_routine(previous)
                    # First enable/reenable is future-only. A restart of the
                    # same active route keeps its existing durable cursor.
                    cursor = self.store.db.execute("SELECT COALESCE(MAX(id),0) FROM gw_events WHERE owner=?", (route.principal_id,)).fetchone()[0]
                    self.store.db.execute("INSERT OR REPLACE INTO gw_routine_exports VALUES(?,?,?,?,?,1)",
                        (route_id, route.principal_id, route.bot_reference, route.fingerprint(), cursor))
                authorizer = lambda p, name, args, route=route: self._routine_authorize(route, p, name, args)
                route_loader = loader
                if self.cfg.mode == "live" and route_loader is None:
                    route_loader = lambda ref, url=route.url: load_secret(
                        ref, secrets_dir=self.cfg.secrets_dir, live_mode=True, expected_url=url)
                sink = GrokRoutineSink(self._routine_path(route.fingerprint()), route, authorizer, route_loader,
                                       sender=sender, resolver=resolver,
                                       event_filter=lambda data, route=route: self._routine_addressed(route, data))
                self.routine_sinks[route_id] = sink
                self.routine_status[route_id] = "ready" if sender is not None else "unavailable"
            except Exception:
                self.routine_status[route_id] = "unavailable"

    @staticmethod
    def _routine_secret_unavailable(_):
        raise RuntimeBlocked("Routine credential loader is unavailable")

    def _routine_authorize(self, route, principal, name, arguments):
        from .grok_routine import Route
        current = self.cfg.routine_routes.get(route.route_id)
        row = self.store.db.execute("SELECT * FROM gw_routine_exports WHERE route_id=?", (route.route_id,)).fetchone()
        if (current is None or Route(**current).fingerprint() != route.fingerprint()
                or row is None or not row["enabled"] or row["fingerprint"] != route.fingerprint()
                or row["principal_id"] != route.principal_id or row["bot_reference"] != route.bot_reference
                or self.cfg.agent_bindings.get(principal.id) != route.bot_reference
                or principal.id != route.principal_id or self.cfg.bot_reference != route.bot_reference):
            raise GatewayDenied("Routine route is unavailable")
        self._event_authorize(principal, name, arguments)

    def _routine_addressed(self, route, data):
        """Select a recipient, never grant authority from text or display names."""
        sender = data.get("sender_id")
        if (route.addressing != "mentions_or_replies"
                or data.get("provenance") not in {"human", "bot"}
                or type(sender) is not int or not 1 <= sender <= 2**52 - 1
                or sender == self.cfg.expected_bot_id):
            return False
        reply = data.get("reply_to_message_id")
        if type(reply) is int and 1 <= reply <= 2**31 - 1:
            topic = data.get("topic_id")
            own_reply = self.store.db.execute(
                "SELECT 1 FROM gw_outbound_links WHERE owner=? AND chat=? AND topic=? AND mid=?",
                (route.principal_id, data["chat_id"], -1 if topic is None else topic, reply)).fetchone()
            if own_reply is not None:
                return True
        text = data.get("text")
        if type(text) is not str:
            return False
        # ASCII case-insensitive handles; Unicode-aware boundaries prevent a
        # username prefix or an email local part from becoming an addressee.
        prefix = r"(?<![\w.!#$%&'*+/=?^`{|}~@-])"
        mention = r"@(?ai:" + re.escape(route.bot_reference) + r")(?![\w@-]|\.\w)"
        return re.search(prefix + r"(?:" + mention + r"|/[A-Za-z0-9_]{1,32}" + mention + r")", text) is not None

    def export_routine_events(self, route_id, *, limit=100):
        """Independent durable bridge; never consumes MCP Events export state."""
        if type(limit) is not int or not 1 <= limit <= 100 or route_id not in self.routine_sinks:
            raise GatewayDenied("Routine route is unavailable")
        sink = self.routine_sinks[route_id]
        route = sink.route
        principal = next(p for p in self.principals if p.id == route.principal_id)
        saved = self.store.db.execute("SELECT cursor,enabled FROM gw_routine_exports WHERE route_id=?", (route_id,)).fetchone()
        if saved is None or not saved["enabled"]:
            return {"exported": 0}
        rows = self.store.db.execute("SELECT * FROM gw_events WHERE owner=? AND id>? ORDER BY id LIMIT ?",
                                    (principal.id, saved["cursor"], limit)).fetchall()
        count = 0
        for row in rows:
            scope = {"chat_id": row["chat"], "topic_id": None if row["topic"] == -1 else row["topic"]}
            permitted = row["expires"] > time.time()
            if permitted:
                try:
                    self._routine_authorize(route, principal, "telegram.message.created", scope)
                except GatewayDenied:
                    permitted = False
            if permitted:
                body = json.loads(row["body"])
                self.gateway._check_bot(body)
                permitted = self._routine_addressed(route, body)
            if permitted:
                body.pop("bot_reference", None)
                event_id = self.gateway._namespace(f"tg-{row['chat']}-{row['topic']}-{row['mid']}")
                # Outbox dedup closes the crash window before cursor advancement.
                sink.enqueue(principal, event_id, body, bot_reference=route.bot_reference, occurred_at=row["created"])
                count += 1
            self.store.db.execute("UPDATE gw_routine_exports SET cursor=? WHERE route_id=? AND enabled=1 AND fingerprint=?",
                                  (row["id"], route_id, route.fingerprint()))
        return {"exported": count}

    async def routine_once(self, route_id):
        sink = self.routine_sinks[route_id]
        export_deferred = False
        try:
            self.export_routine_events(route_id)
        except Exception:
            # Capacity or a bad new event must not prevent draining the already
            # authorized outbox. Export keeps its cursor before the failed row;
            # dispatch still rechecks route, principal and actual event scope.
            export_deferred = True
        principal = next(p for p in self.principals if p.id == sink.route.principal_id)
        result = await sink.dispatch_once(principal, bot_reference=self.cfg.bot_reference)
        self.routine_status[route_id] = "degraded" if export_deferred else result["status"]
        return dict(result, export_deferred=True) if export_deferred else result

    def revoke_routine(self, route_id):
        """Trusted operator hook, not registered as an MCP tool."""
        sink = self.routine_sinks.get(route_id)
        if sink is None:
            raise GatewayDenied("Routine route is unavailable")
        principal = next(p for p in self.principals if p.id == sink.route.principal_id)
        self.store.db.execute("UPDATE gw_routine_exports SET enabled=0 WHERE route_id=?", (route_id,))
        sink.revoke(principal, bot_reference=self.cfg.bot_reference)
        self.routine_status[route_id] = "revoked"

    async def routine_loop(self, route_id):
        while not self.stopping:
            try:
                await self.routine_once(route_id)
            except asyncio.CancelledError:
                raise
            except Exception:
                self.routine_status[route_id] = "degraded"
            await asyncio.sleep(1)

    def _standing_policy(self):
        if self.cfg.standing_send is None:
            return None
        from .standing import StandingSendPolicy
        return StandingSendPolicy(**self.cfg.standing_send)

    def _event_authorize(self, p, name, arguments):
        if name != "telegram.message.created":
            raise GatewayDenied("Event unavailable")
        self.cfg.policy.require(p, "events", Scope(arguments["chat_id"], arguments.get("topic_id"),
                                                   arguments.get("all_topics", False)))

    def _callback_authorize(self, p, url):
        self.cfg.policy.tools_for(p)
        if url not in self.cfg.allowed_callbacks.get(p.id, ()):
            raise GatewayDenied("Callback is not approved for this principal")

    async def _fake_receiver(self, target, body, headers):
        value = json.loads(body)
        if value.get("type") == "verification":
            return WebhookResponse(200, json.dumps({"challenge": value["challenge"]}).encode())
        self.fake_callbacks.append(value)
        return WebhookResponse(204)

    def _write_status(self, state):
        # No messages, subjects, URLs, token material, callback secrets or chat IDs.
        data = {"state": state, "mode": self.cfg.mode, "timestamp": time.time(),
                "poll_state": self.gateway.poll_state if self.gateway else "not_started",
                "health": self.gateway._health() if self.gateway else "starting",
                "status_write_state": self.gateway.status_write_state if self.gateway else "not_started",
                "dot_wakeup_verified": False, "poll_diagnostics": self.poll_diagnostics}
        path = self.cfg.state_dir / "runtime-status.json"
        tmp = self.cfg.state_dir / "runtime-status.tmp"
        tmp.write_text(json.dumps(data), encoding="utf-8")
        tmp.replace(path)

    async def poll_loop(self):
        backoff = 1
        while not self.stopping:
            delay = self.cfg.poll_interval_seconds
            try:
                await self.gateway.poll_once()
                self.gateway.last_poll_at = time.time()
                self.gateway.poll_state = "ok"
                self.poll_diagnostics["successful_polls"] += 1
                stats = self.gateway.last_poll_stats
                self.poll_diagnostics["last_batch"] = stats
                if stats is not None:
                    for key in ("updates_received", "messages_accepted", "message_rows_stored", "event_rows_created"):
                        self.poll_diagnostics[key] += stats[key]
                backoff = 1
            except asyncio.CancelledError:
                raise
            except Exception as error:
                self.gateway.poll_state = "retrying"
                self.poll_diagnostics["failed_polls"] += 1
                code = getattr(error, "api_error_code", None)
                if type(code) is not int or not 400 <= code <= 599:
                    code = None
                kind = ("consumer_busy" if isinstance(error, ConsumerBusy) else
                        "telegram_conflict" if isinstance(error, BotRejected) and code == 409 else
                        "rate_limited" if isinstance(error, BotRejected) and code == 429 else
                        "rejected_or_invalid_update" if isinstance(error, BotRejected) else
                        "transport_unavailable" if isinstance(error, BotUnavailable) else
                        "storage_error" if isinstance(error, sqlite3.Error) else "internal_error")
                self.poll_diagnostics["last_error"] = {"at": time.time(), "kind": kind, "api_error_code": code}
                backoff = min(60, backoff * 2)
                retry_after = getattr(error, "retry_after", None)
                if type(retry_after) is not int or not 1 <= retry_after <= 86400:
                    retry_after = 0
                # Telegram's validated wait is a lower bound, not subject to
                # our local exponential-backoff cap. This loop retries reads only.
                delay = max(backoff, retry_after)
            try:
                self.gateway.status_write_state = "ok"
                self._write_status("running")
            except Exception:
                # Diagnostics must not terminate polling. Expose only a fixed
                # degraded state through the live MCP health/status response.
                self.gateway.status_write_state = "degraded"
            await asyncio.sleep(delay)

    async def delivery_loop(self):
        while not self.stopping:
            try:
                for principal in self.principals:
                    self.gateway.export_events(principal, self.hub)
                await self.hub.deliver_due()
            except asyncio.CancelledError:
                raise
            except Exception:
                # Queue retains retry/expiry. Never log event or credential values.
                pass
            await asyncio.sleep(1)

    def start_workers(self):
        if not self.tasks:
            self.tasks = [asyncio.create_task(self.poll_loop()), asyncio.create_task(self.delivery_loop())]
            self.tasks.extend(asyncio.create_task(self.routine_loop(route_id)) for route_id in self.routine_sinks)

    async def close(self):
        self.stopping = True
        for task in self.tasks:
            task.cancel()
        if self.tasks:
            await asyncio.gather(*self.tasks, return_exceptions=True)
        self.tasks.clear()
        failed_phase = None
        if self.lock is not None:
            try:
                self._write_status("stopped")
            except Exception:
                failed_phase = "status"
        resources = [("routine", sink) for sink in self.routine_sinks.values()]
        resources.extend((("events", self.hub), ("secrets", self.secrets), ("state", self.store)))
        self.routine_sinks.clear()
        self.hub = self.secrets = self.store = None
        for phase, resource in resources:
            if resource is not None:
                try:
                    resource.close()
                except Exception:
                    failed_phase = failed_phase or phase
        lock, self.lock = self.lock, None
        if lock is not None:
            try:
                lock.__exit__(None, None, None)
            except Exception:
                failed_phase = failed_phase or "lock"
        if failed_phase is not None:
            # Do not expose a callback URL, payload or credential from a driver error.
            raise RuntimeBlocked("Runtime shutdown incomplete: " + failed_phase) from None


def make_runtime(cfg, **kwargs):
    """Select catalog routing without changing the legacy one-bot API."""
    if getattr(cfg, "catalog_mode", False):
        from .multi_runtime import MultiRuntime
        return MultiRuntime(cfg, **kwargs)
    return Runtime(cfg, **kwargs)


async def serve(cfg, *, allow_live=False):
    import uvicorn
    from .http_server import create_app
    runtime = make_runtime(cfg, allow_live=allow_live)
    await runtime.start()
    @asynccontextmanager
    async def lifecycle(app):
        runtime.start_workers()
        try:
            yield
        finally:
            await runtime.close()
    try:
        resource = runtime.auth.protected_resource_metadata() if cfg.auth_mode == "oauth" else None
        host = "[" + cfg.bind_host + "]" if ":" in cfg.bind_host else cfg.bind_host
        base = cfg.public_base_url or f"http://{host}:{cfg.bind_port}"
        metadata_url = base.rstrip("/") + "/.well-known/oauth-protected-resource/mcp"
        app = create_app(runtime.protocol, runtime.auth, resource_metadata=resource, metadata_url=metadata_url,
                         allowed_hosts=set(cfg.allowed_hosts), allowed_origins=set(cfg.allowed_origins), lifecycle=lifecycle)
        server = uvicorn.Server(uvicorn.Config(app, host=cfg.bind_host, port=cfg.bind_port, access_log=False,
                                log_level="critical", proxy_headers=False, timeout_graceful_shutdown=60))
        await server.serve()
    finally:
        if runtime.lock is not None:
            await runtime.close()


async def approval_command(cfg, principal_id, draft_id, *, allow_live=False, confirm_send=False):
    # Exclusive instance: stop the foreground server first. Restarts retain drafts/cursor.
    from .approvals import request_owner_approval
    selected = cfg
    if getattr(cfg, "catalog_mode", False):
        selected = cfg.bot_configs.get(cfg.agent_bindings.get(principal_id))
        if selected is None:
            raise RuntimeBlocked("Principal is not configured")
    if not cfg.outbound_enabled or not selected.outbound_enabled or selected.review_scope is None or not confirm_send:
        raise RuntimeBlocked("Approval prompt delivery needs configured review scope and --confirm-send")
    runtime = make_runtime(cfg, allow_live=allow_live)
    await runtime.start()
    try:
        principal = next((p for p in runtime.principals if p.id == principal_id), None)
        if principal is None:
            raise RuntimeBlocked("Principal is not configured")
        gateway = runtime.child_for(principal).gateway if getattr(cfg, "catalog_mode", False) else runtime.gateway
        return await request_owner_approval(gateway, principal, draft_id, selected.review_scope, allow_send=True)
    finally:
        await runtime.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["check", "serve", "status", "request-approval"])
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--allow-live-network", action="store_true")
    parser.add_argument("--confirm-send", action="store_true")
    parser.add_argument("--principal")
    parser.add_argument("--draft-id")
    args = parser.parse_args()
    try:
        cfg = RuntimeConfig.load(args.config)
        if args.action == "check":
            print(json.dumps(configuration_status(cfg), ensure_ascii=False))
        elif args.action == "status":
            if cfg.state_dir is None:
                raise RuntimeBlocked("State directory is not configured")
            data = json.loads((cfg.state_dir / "runtime-status.json").read_text(encoding="utf-8"))
            print(json.dumps({key: data.get(key) for key in ("state", "mode", "timestamp", "poll_state", "dot_wakeup_verified", "configured_bots", "available_bots", "health", "status_write_state")}))
        elif args.action == "serve":
            asyncio.run(serve(cfg, allow_live=args.allow_live_network))
        else:
            result = asyncio.run(approval_command(cfg, args.principal, args.draft_id,
                                 allow_live=args.allow_live_network, confirm_send=args.confirm_send))
            print(json.dumps({"status": result.get("status"), "reused": result.get("reused", False)}))
    except KeyboardInterrupt:
        pass
    except Exception:
        parser.exit(2, "Gateway action rejected; check configuration, approved identities and local state. No raw errors are logged.\n")


if __name__ == "__main__":
    main()
