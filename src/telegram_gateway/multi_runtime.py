"""One listener, trusted principal routing, independently isolated bot runtimes.

Routing never accepts a bot name from a request. Bot names used by lifecycle
methods belong to trusted operator configuration, not the MCP tool interface.
Child startup failures remain unavailable until an explicit operator restart;
polling retries reads only. No failed or uncertain outbound action is replayed.
"""
from __future__ import annotations

import asyncio
import json
import time

from .auth import PrincipalAuthority
from .policy import GatewayDenied
from .protocol import Protocol
from .runtime import Runtime, RuntimeBlocked, make_authenticator
from .service import ProcessLock


class GatewayRouter:
    """Explicit signatures preserve Protocol's strict, bot-selector-free schema."""

    def __init__(self, runtime):
        self.runtime, self.policy = runtime, runtime.cfg.policy

    def _identity(self, p):
        self.runtime.reference_for(p)
        return p.id

    def ping(self, p):
        reference = self.runtime.reference_for(p)
        child = self.runtime.children.get(reference)
        if child is None:
            return {"status": "unavailable", "bot_reference": reference,
                    "telegram_connected": False, "cloud_delivery_confirmed": None,
                    "cloud_delivery_status": "not_evaluated",
                    "protocol": "2026-07-28"}
        return {**child.gateway.ping(p), "bot_reference": reference}

    def status(self, p):
        reference = self.runtime.reference_for(p)
        child = self.runtime.children.get(reference)
        if child is None:
            return {"principal": p.id, "bot_reference": reference, "state": "unavailable",
                    "telegram_connected": False, "cloud_delivery_confirmed": None,
                    "cloud_delivery_status": "not_evaluated"}
        return {**child.gateway.status(p), "bot_reference": reference}

    def list_allowed_scopes(self, p):
        return self.runtime.child_for(p).gateway.list_allowed_scopes(p)

    def read_history(self, p, chat_id, topic_id=None, limit=20, before_id=None, all_topics=False):
        return self.runtime.child_for(p).gateway.read_history(p, chat_id, topic_id, limit, before_id, all_topics)

    def search_history(self, p, chat_id, query, topic_id=None, limit=20, all_topics=False):
        return self.runtime.child_for(p).gateway.search_history(p, chat_id, query, topic_id, limit, all_topics)

    def next_events(self, p, chat_id, topic_id=None, limit=20, all_topics=False):
        return self.runtime.child_for(p).gateway.next_events(p, chat_id, topic_id, limit, all_topics)

    def ack_event(self, p, event_id):
        return self.runtime.child_for(p).gateway.ack_event(p, event_id)

    def create_draft(self, p, chat_id, text, topic_id=None, attachments=None,
                     reply_to_message_id=None, expires_in=300):
        return self.runtime.child_for(p).gateway.create_draft(
            p, chat_id, text, topic_id, attachments, reply_to_message_id, expires_in)

    def create_forward_draft(self, p, source_chat_id, message_id, chat_id,
                             source_topic_id=None, topic_id=None, expires_in=300):
        return self.runtime.child_for(p).gateway.create_forward_draft(
            p, source_chat_id, message_id, chat_id, source_topic_id, topic_id, expires_in)

    def get_draft_status(self, p, draft_id):
        return self.runtime.child_for(p).gateway.get_draft_status(p, draft_id)

    async def send_draft(self, p, draft_id):
        return await self.runtime.call_for(p, lambda child: child.gateway.send_draft(p, draft_id))


class EventRouter:
    def __init__(self, runtime):
        self.runtime = runtime

    async def handle(self, method, params, principal):
        return await self.runtime.call_for(principal, lambda child: child.hub.handle(method, params, principal))

    def status(self, principal):
        return self.runtime.child_for(principal).hub.status(principal)


class MultiRuntime:
    def __init__(self, cfg, *, allow_live=False, transports=None, senders=None,
                 resolvers=None, runtime_factory=None, startup_timeout=30,
                 routine_senders=None, routine_resolvers=None, routine_secret_loaders=None):
        if not cfg.catalog_mode or cfg.mode == "disabled":
            raise RuntimeBlocked("Runtime catalog is disabled or unavailable")
        if cfg.mode == "live" and not (allow_live and cfg.network_enabled):
            raise RuntimeBlocked("Live mode needs approved configuration and --allow-live-network")
        if not cfg.bot_configs or set(cfg.agent_bindings) != set(cfg.principals):
            raise RuntimeBlocked("Runtime catalog bindings are invalid")
        if not 0 < startup_timeout <= 60:
            raise RuntimeBlocked("Runtime startup limit is invalid")
        self.cfg, self.allow_live = cfg, allow_live
        self.transports, self.senders, self.resolvers = dict(transports or {}), dict(senders or {}), dict(resolvers or {})
        self.routine_senders, self.routine_resolvers = dict(routine_senders or {}), dict(routine_resolvers or {})
        self.routine_secret_loaders = dict(routine_secret_loaders or {})
        for values in (self.transports, self.senders, self.resolvers, self.routine_senders,
                       self.routine_resolvers, self.routine_secret_loaders):
            if not set(values) <= set(cfg.bot_configs):
                raise RuntimeBlocked("Runtime injection targets are invalid")
        # Accidentally sharing one stateful transport would defeat bot isolation.
        injected = [value for value in self.transports.values() if value is not None]
        if len({id(value) for value in injected}) != len(injected):
            raise RuntimeBlocked("Bot transports must be separate")
        for reference, child in cfg.bot_configs.items():
            expected = {p for p, ref in cfg.agent_bindings.items() if ref == reference}
            if (not expected or child.catalog_mode or child.bot_reference != reference
                    or set(child.principals) != expected or child.mode != cfg.mode
                    or child.state_dir != cfg.state_dir / "bots" / reference):
                raise RuntimeBlocked("Runtime catalog isolation is invalid")
            if cfg.secrets_dir is not None and child.secrets_dir != cfg.secrets_dir / "bots" / reference:
                raise RuntimeBlocked("Runtime secret namespaces are invalid")
        if set(cfg.agent_bindings.values()) != set(cfg.bot_configs):
            raise RuntimeBlocked("Runtime catalog bindings are invalid")
        self.auth = make_authenticator(cfg)
        self.principals = tuple(PrincipalAuthority().restore(name) for name in cfg.principals)
        self.children = {}
        self.bot_status = {reference: "not_started" for reference in cfg.bot_configs}
        self.gateway, self.hub = GatewayRouter(self), EventRouter(self)
        self.protocol = Protocol(self.auth, self.gateway, self.hub)
        self.lock = None
        self.started = self.stopping = self.workers_started = False
        self._factory, self._timeout = runtime_factory or Runtime, startup_timeout
        self._operations = {reference: asyncio.Lock() for reference in cfg.bot_configs}
        self._calls = {reference: set() for reference in cfg.bot_configs}
        self._startup_tasks = []
        self._close_task = None

    def reference_for(self, principal):
        # Policy checks exact sealed VerifiedPrincipal, not merely an id string.
        self.cfg.policy.tools_for(principal)
        if not self.started or self.stopping:
            raise GatewayDenied("Bot is unavailable")
        reference = self.cfg.agent_bindings.get(principal.id)
        if reference not in self.cfg.bot_configs:
            raise GatewayDenied("Access denied")
        return reference

    def child_for(self, principal):
        reference = self.reference_for(principal)
        child = self.children.get(reference)
        if child is None or self.bot_status[reference] != "running":
            raise GatewayDenied("Bot is unavailable")
        child.gateway._identity(principal)
        return child

    async def call_for(self, principal, operation):
        child = self.child_for(principal)
        reference = self.reference_for(principal)
        task = asyncio.current_task()
        self._calls[reference].add(task)
        try:
            return await operation(child)
        finally:
            self._calls[reference].discard(task)

    async def start(self):
        if self.started or self.stopping or self.lock is not None:
            raise RuntimeBlocked("Runtime lifecycle has already started")
        self.cfg.state_dir.mkdir(parents=True, exist_ok=True)
        lock = ProcessLock(self.cfg.state_dir / "runtime.lock")
        lock.__enter__()
        self.lock = lock
        try:
            self._startup_tasks = [asyncio.create_task(self._start_one(ref)) for ref in self.cfg.bot_configs]
            await asyncio.gather(*self._startup_tasks)
            self.started = True
            self._write_status("running")
        except BaseException:
            await self.close()
            raise
        finally:
            self._startup_tasks.clear()

    async def _start_one(self, reference):
        async with self._operations[reference]:
            return await self._start_child_locked(reference)

    async def _start_child_locked(self, reference):
        self.bot_status[reference] = "starting"
        child = None
        try:
            child = self._factory(self.cfg.bot_configs[reference], allow_live=self.allow_live,
                                  transport=self.transports.get(reference), sender=self.senders.get(reference),
                                  resolver=self.resolvers.get(reference), authenticator=self.auth,
                                  routine_sender=self.routine_senders.get(reference),
                                  routine_resolver=self.routine_resolvers.get(reference),
                                  routine_secret_loader=self.routine_secret_loaders.get(reference))
            await asyncio.wait_for(child.start(), timeout=self._timeout)
            if self.stopping:
                await child.close()
                self.bot_status[reference] = "stopped"
                return False
            self.children[reference] = child
            self.bot_status[reference] = "running"
            if self.workers_started:
                child.start_workers()
            return True
        except BaseException as error:
            # Runtime.start already closes its partial resources on failure.
            # A constructor/lock failure has no acquired resource to close.
            if child is not None and (getattr(child, "store", None) is not None
                    or getattr(getattr(child, "lock", None), "file", None) is not None):
                await child.close()
            self.children.pop(reference, None)
            self.bot_status[reference] = "unavailable"
            if isinstance(error, (asyncio.CancelledError, KeyboardInterrupt, SystemExit)):
                raise
            return False

    def start_workers(self):
        if not self.started or self.stopping:
            raise RuntimeBlocked("Runtime is unavailable")
        self.workers_started = True
        for child in tuple(self.children.values()):
            child.start_workers()

    async def _stop_child_locked(self, reference):
        drain = asyncio.create_task(self._drain_child(reference))
        try:
            await asyncio.shield(drain)
        except asyncio.CancelledError:
            # An interrupted operator restart must not orphan the removed child.
            await asyncio.shield(drain)
            raise

    async def _drain_child(self, reference):
        self.bot_status[reference] = "unavailable"
        child = self.children.pop(reference, None)
        # Finish cancellation bookkeeping (including marking sends unknown)
        # before the child's databases are closed. No automatic send retries.
        pending = [task for task in self._calls[reference] if task is not asyncio.current_task()]
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        if child is not None:
            await child.close()

    async def restart_bot(self, reference):
        """Trusted operator hook, deliberately absent from MCP tools/events."""
        if type(reference) is not str or reference not in self.cfg.bot_configs or not self.started or self.stopping:
            raise RuntimeBlocked("Bot restart is unavailable")
        async with self._operations[reference]:
            if self.stopping:
                raise RuntimeBlocked("Bot restart is unavailable")
            await self._stop_child_locked(reference)
            result = await self._start_child_locked(reference)
            self._write_status("running")
            return result

    def _write_status(self, state):
        data = {"state": state, "mode": self.cfg.mode, "timestamp": time.time(),
                "poll_state": "per_bot", "dot_wakeup_verified": False,
                "configured_bots": len(self.cfg.bot_configs),
                "available_bots": sum(value == "running" for value in self.bot_status.values())}
        temporary = self.cfg.state_dir / "runtime-status.tmp"
        temporary.write_text(json.dumps(data), encoding="utf-8")
        temporary.replace(self.cfg.state_dir / "runtime-status.json")

    async def _close_all(self):
        try:
            for task in self._startup_tasks:
                if not task.done():
                    task.cancel()
            if self._startup_tasks:
                await asyncio.gather(*self._startup_tasks, return_exceptions=True)
            async def stop(reference):
                async with self._operations[reference]:
                    try:
                        await self._stop_child_locked(reference)
                    finally:
                        self.bot_status[reference] = "stopped"
            await asyncio.gather(*(stop(ref) for ref in self.cfg.bot_configs), return_exceptions=True)
            if self.lock is not None:
                self._write_status("stopped")
        finally:
            self.started = False
            if self.lock is not None:
                self.lock.__exit__(None, None, None)
                self.lock = None

    async def close(self):
        self.stopping = True
        if self._close_task is None:
            self._close_task = asyncio.create_task(self._close_all())
        try:
            await asyncio.shield(self._close_task)
        except asyncio.CancelledError:
            await asyncio.shield(self._close_task)
            raise
