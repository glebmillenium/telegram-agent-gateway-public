"""Lazy, allowlisted Telegram reads. The underlying session is NOT read-only.

Only an explicitly supplied existing session is opened, on the first permitted
read. No authorization, dialog enumeration, entity network lookup or writes are
exposed. This module does not establish OS isolation for the session.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import logging
from pathlib import Path
import sys
from typing import Any

import telethon
from telethon import TelegramClient, utils
from telethon.tl import functions, types

from .core import BackendError, Message, Settings


def validated_session_path(path: Path, *, must_exist: bool) -> Path:
    """Validate the user-selected path; never search for other sessions."""
    path = Path(path)
    if not path.is_absolute() or path.suffix != ".session":
        raise BackendError("Use an absolute external path ending in .session.")
    resolved = path.resolve()
    source_path = Path(__file__).resolve()
    forbidden_roots = {source_path.parents[2]}
    forbidden_roots.update(parent for parent in source_path.parents if (parent / "pyproject.toml").is_file())
    runtime_prefix = Path(sys.prefix).resolve()
    if runtime_prefix.name == ".venv":
        forbidden_roots.add(runtime_prefix.parent)
    if any(resolved.is_relative_to(root) for root in forbidden_roots):
        raise BackendError("Session files must be outside the project directory.")
    if must_exist and not resolved.is_file():
        raise BackendError("An explicitly selected existing session is required.")
    if not must_exist and resolved.exists():
        raise BackendError("Refusing to overwrite or reuse an existing session.")
    if not resolved.parent.is_dir():
        raise BackendError("Prepare the isolated session directory first.")
    return resolved


def quiet_telegram_logger() -> logging.Logger:
    """Do not emit Telegram details, RPC exceptions or message contents."""
    logger = logging.getLogger("telegram_readonly_mcp.telegram")
    if not logger.handlers:
        logger.addHandler(logging.NullHandler())
    logger.propagate = False
    logger.setLevel(logging.CRITICAL + 1)
    return logger


class NoUpdatesTelegramClient(TelegramClient):
    """Pinned Telethon lifecycle: never fetch account-wide updates.

    Telethon 1.45.0's stock connect/sign_in use GetDifference despite
    receive_updates=False. These private overrides are covered by offline tests
    of the REAL Telethon lifecycle and must be reviewed on dependency upgrade.
    """

    def __init__(self, *args, **kwargs):
        if telethon.__version__ != "1.45.0":
            raise BackendError("Unsupported Telethon version; lifecycle safety review required.")
        kwargs["receive_updates"] = False
        kwargs["catch_up"] = False
        super().__init__(*args, **kwargs)

    async def get_me(self, input_peer=False):
        # Suppress implicit self-profile/auth initialization in connect/sign_in.
        # Authorization is verified by the explicitly requested scoped read.
        return None

    async def is_user_authorized(self):
        # Stock implementation issues updates.GetState. Newly created login
        # sessions are unauthorized until the explicit sign_in completes.
        return self._authorized is True

    async def _on_login(self, user):
        self._mb_entity_cache.set_self_user(user.id, user.bot, user.access_hash)
        self._authorized = True
        return user

    async def _update_loop(self):
        # Do not dispatch updates or run the SDK's periodic GetDifference loop.
        return


class RuntimeTelegramClient(NoUpdatesTelegramClient):
    def __init__(self, *args, allowed_chat_ids: frozenset[int], max_messages: int, **kwargs):
        self._permitted_chat_ids = allowed_chat_ids
        self._permitted_max_messages = max_messages
        super().__init__(*args, **kwargs)

    async def _call(self, sender, request, ordered=False, flood_sleep_threshold=None):
        # Guard at the layer used by Telethon's own public helpers as well as
        # __call__. Lists, arbitrary RPCs, auth operations and update reads fail.
        if type(request) not in (functions.messages.GetHistoryRequest, functions.messages.SearchRequest):
            raise BackendError("Telegram RPC is outside the pilot read-only boundary.")
        if type(request.peer) not in (types.InputPeerUser, types.InputPeerChat, types.InputPeerChannel):
            raise BackendError("Telegram RPC must use an explicit cached input peer.")
        if utils.get_peer_id(request.peer) not in self._permitted_chat_ids:
            raise BackendError("Telegram RPC peer is not allowlisted.")
        if type(request.limit) is not int or not 1 <= request.limit <= self._permitted_max_messages:
            raise BackendError("Telegram RPC limit is outside the permitted range.")
        return await super()._call(sender, request, ordered=ordered, flood_sleep_threshold=flood_sleep_threshold)

    async def _switch_dc(self, new_dc):
        # Stock migration resets auth_key and creates a new one. Runtime must
        # stop; any new authorization belongs to separate user-driven setup.
        raise BackendError("Telegram DC migration requires separate user setup.")


class UserLoginTelegramClient(NoUpdatesTelegramClient):
    """Separate, never MCP-exposed authorizer with one optional peer lookup."""

    def __init__(self, *args, peer_username: str | None = None, **kwargs):
        self._selected_username = peer_username
        self._peer_lookup_used = False
        super().__init__(*args, **kwargs)

    async def _call(self, sender, request, ordered=False, flood_sleep_threshold=None):
        auth_requests = (
            functions.auth.SendCodeRequest, functions.auth.ResendCodeRequest,
            functions.auth.SignInRequest, functions.auth.CheckPasswordRequest,
            functions.account.GetPasswordRequest, functions.help.GetConfigRequest,
        )
        if type(request) is functions.contacts.ResolveUsernameRequest:
            if (self._peer_lookup_used or self._selected_username is None
                    or request.username.casefold() != self._selected_username.casefold()):
                raise BackendError("Only the user's explicitly selected peer can be resolved once.")
            self._peer_lookup_used = True
        elif type(request) not in auth_requests:
            raise BackendError("RPC is outside the separate user login boundary.")
        return await super()._call(sender, request, ordered=ordered, flood_sleep_threshold=flood_sleep_threshold)


class TelethonBackend:
    def __init__(self, settings: Settings, session_path: Path, api_id: int, api_hash: str):
        self._settings = settings
        self._session_path = Path(session_path)
        self._api_id = api_id
        self._api_hash = api_hash
        self._allowed_ids = frozenset(chat.id for chat in settings.allowed_chats)
        self._client: TelegramClient | None = None
        self._lock = asyncio.Lock()

    def _validate(self, chat_id: int, limit: int, before_id: int | None) -> None:
        if type(chat_id) is not int or chat_id not in self._allowed_ids:
            raise BackendError("Chat is not allowlisted.")
        if type(limit) is not int or not 1 <= limit <= self._settings.max_messages:
            raise BackendError("Message limit is outside the permitted range.")
        if before_id is not None and (type(before_id) is not int or not 1 <= before_id <= 2**31 - 1):
            raise BackendError("before_id must be a positive message ID.")

    async def _connected_client(self) -> TelegramClient:
        if self._client is not None:
            return self._client
        path = validated_session_path(self._session_path, must_exist=True)
        if type(self._api_id) is not int or self._api_id <= 0 or not isinstance(self._api_hash, str) or not self._api_hash:
            raise BackendError("Explicit Telegram application credentials are required.")
        client = RuntimeTelegramClient(
            str(path), self._api_id, self._api_hash,
            allowed_chat_ids=self._allowed_ids, max_messages=self._settings.max_messages,
            receive_updates=False, catch_up=False,
            request_retries=0, connection_retries=0, auto_reconnect=False,
            flood_sleep_threshold=0, raise_last_call_error=True,
            timeout=self._settings.request_timeout_seconds,
            base_logger=quiet_telegram_logger(),
        )
        # Refuse sessions that would make connect() generate a new authorization
        # key. Only the separate user-driven login program may create one.
        if not client.session.auth_key:
            client.session.close()
            raise BackendError("Session has no authorization key; use the separate user login.")
        client.session.save_entities = False
        self._client = client
        await client.connect()
        return client

    @staticmethod
    def _peer(client: TelegramClient, chat_id: int) -> Any:
        try:
            # Deliberately call the Session cache, NOT client.get_input_entity:
            # the latter may fall back to network-wide dialog/contact discovery.
            peer = client.session.get_input_entity(chat_id)
        except (ValueError, KeyError):
            raise BackendError("Allowed peer is absent from the session cache; resolve only that peer during user setup.") from None
        if type(peer) not in (types.InputPeerUser, types.InputPeerChat, types.InputPeerChannel):
            raise BackendError("Unsupported cached peer.")
        if utils.get_peer_id(peer) != chat_id:
            raise BackendError("Cached peer does not match the allowlisted numeric ID.")
        return peer

    def _messages(self, result: Any, chat_id: int, limit: int, before_id: int | None) -> list[Message]:
        if len(result.messages) > limit:
            raise BackendError("Telegram returned more messages than requested.")
        output = []
        for item in result.messages:
            if isinstance(item, types.MessageEmpty):
                continue
            if utils.get_peer_id(item.peer_id) != chat_id:
                raise BackendError("Telegram returned a message for a different chat.")
            if type(item.id) is not int or item.id <= 0:
                raise BackendError("Telegram returned an invalid message ID.")
            if before_id is not None and item.id >= before_id:
                raise BackendError("Telegram returned a message outside the requested page.")
            if not isinstance(item.date, datetime):
                raise BackendError("Telegram returned an invalid message date.")
            date = item.date
            if date.tzinfo is None:
                date = date.replace(tzinfo=timezone.utc)
            sender = getattr(item, "from_id", None)
            output.append(Message(
                id=item.id,
                chat_id=chat_id,
                date=date.astimezone(timezone.utc).isoformat(),
                sender_id=utils.get_peer_id(sender) if sender is not None else None,
                # The service truncates once and adds text_truncated metadata.
                text=getattr(item, "message", None) or "",
                outgoing=bool(getattr(item, "out", False)),
                has_media=getattr(item, "media", None) is not None,
            ))
        return output

    async def _read(self, chat_id: int, limit: int, before_id: int | None, query: str | None) -> list[Message]:
        self._validate(chat_id, limit, before_id)
        if query is not None and (not isinstance(query, str) or not query.strip() or len(query) > 200):
            raise BackendError("Search requires 1–200 non-blank characters.")
        async with self._lock:
            try:
                async with asyncio.timeout(self._settings.request_timeout_seconds):
                    client = await self._connected_client()
                    peer = self._peer(client, chat_id)
                    if query is None:
                        request = functions.messages.GetHistoryRequest(
                            peer=peer, offset_id=before_id or 0, offset_date=None,
                            add_offset=0, limit=limit, max_id=0, min_id=0, hash=0,
                        )
                    else:
                        request = functions.messages.SearchRequest(
                            peer=peer, q=query, filter=types.InputMessagesFilterEmpty(),
                            min_date=None, max_date=None, offset_id=before_id or 0,
                            add_offset=0, limit=limit, max_id=0, min_id=0, hash=0,
                        )
                    result = await client(request)
                    return self._messages(result, chat_id, limit, before_id)
            except asyncio.CancelledError:
                # ReadService's timeout can cancel this operation before this
                # adapter's own timeout. Release the connection in both cases.
                await self._disconnect_unlocked()
                raise
            except BackendError:
                raise
            except TimeoutError:
                await self._disconnect_unlocked()
                raise BackendError("Telegram request timed out; no automatic retry.") from None
            except Exception:
                await self._disconnect_unlocked()
                # Do not reflect RPC text, phone numbers, session paths or data.
                raise BackendError("Telegram read failed; verify access/session privately. No automatic login or retry.") from None

    async def read_messages(self, chat_id: int, limit: int, before_id: int | None = None) -> list[Message]:
        return await self._read(chat_id, limit, before_id, None)

    async def search_messages(self, chat_id: int, query: str, limit: int, before_id: int | None = None) -> list[Message]:
        return await self._read(chat_id, limit, before_id, query)

    async def _disconnect_unlocked(self) -> None:
        client, self._client = self._client, None
        if client is not None:
            try:
                await asyncio.wait_for(client.disconnect(), timeout=self._settings.request_timeout_seconds)
            except Exception:
                # Closing must not leak dependency exceptions or session details.
                pass

    async def close(self) -> None:
        async with self._lock:
            await self._disconnect_unlocked()
