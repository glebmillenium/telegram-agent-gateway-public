"""Small fail-closed policy boundary, independent of transport and Telegram."""

from __future__ import annotations

import asyncio
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol

MAX_CHAT_ID = 2**53 - 1  # exact in JSON clients using IEEE-754 numbers


class PolicyError(ValueError):
    pass


class BackendError(RuntimeError):
    pass


def integer(value: object, name: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise PolicyError(f"{name}: integer in [{minimum}, {maximum}] required")
    return value


@dataclass(frozen=True)
class AllowedChat:
    id: int
    label: str


@dataclass(frozen=True)
class Settings:
    allowed_chats: tuple[AllowedChat, ...] = ()
    max_messages: int = 20
    max_text_chars: int = 4000
    request_timeout_seconds: int = 15

    def __post_init__(self) -> None:
        integer(self.max_messages, "max_messages", 1, 100)
        integer(self.max_text_chars, "max_text_chars", 1, 8000)
        integer(self.request_timeout_seconds, "request_timeout_seconds", 1, 60)
        if len(self.allowed_chats) > 1:
            raise PolicyError("This pilot permits at most one configured chat")
        for chat in self.allowed_chats:
            integer(chat.id, "chat id", -MAX_CHAT_ID, MAX_CHAT_ID)
            if chat.id == 0:
                raise PolicyError("chat id must be nonzero")
            if not isinstance(chat.label, str) or not 1 <= len(chat.label.strip()) <= 80:
                raise PolicyError("chat label must contain 1..80 characters")

    @classmethod
    def load(cls, path: Path) -> Settings:
        if path.stat().st_size > 16_384:
            raise PolicyError("Configuration is too large")
        def unique_keys(pairs: list[tuple[str, object]]) -> dict:
            result = {}
            for key, value in pairs:
                if key in result:
                    raise PolicyError("Duplicate configuration key")
                result[key] = value
            return result
        value = json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=unique_keys)
        allowed_keys = {"allowed_chats", "max_messages", "max_text_chars", "request_timeout_seconds"}
        if not isinstance(value, dict) or set(value) - allowed_keys:
            raise PolicyError("Unknown configuration field")
        chats = value.get("allowed_chats", [])
        if not isinstance(chats, list):
            raise PolicyError("allowed_chats must be an array")
        parsed = []
        for chat in chats:
            if not isinstance(chat, dict) or set(chat) != {"id", "label"}:
                raise PolicyError("Each allowed chat requires exactly id and label")
            parsed.append(AllowedChat(**chat))
        return cls(**{**value, "allowed_chats": tuple(parsed)})


@dataclass(frozen=True)
class Message:
    id: int
    chat_id: int
    date: str
    sender_id: int | None
    text: str
    outgoing: bool
    has_media: bool


class Backend(Protocol):
    async def read_messages(self, chat_id: int, limit: int, before_id: int | None) -> list[Message]: ...
    async def search_messages(self, chat_id: int, query: str, limit: int, before_id: int | None) -> list[Message]: ...
    async def close(self) -> None: ...


def validate_request(settings: Settings, chat_id: int, limit: int, before_id: int | None) -> None:
    integer(chat_id, "chat_id", -MAX_CHAT_ID, MAX_CHAT_ID)
    if chat_id not in {chat.id for chat in settings.allowed_chats}:
        raise PolicyError("Chat is not allowed")
    integer(limit, "limit", 1, settings.max_messages)
    if before_id is not None:
        integer(before_id, "before_id", 1, 2**31 - 1)


def validate_query(query: str) -> None:
    if not isinstance(query, str) or not 1 <= len(query.strip()) <= 200 or len(query) > 200:
        raise PolicyError("query must contain 1..200 characters")


class ReadService:
    def __init__(self, settings: Settings, backend: Backend, backend_name: str) -> None:
        self.settings, self.backend, self.backend_name = settings, backend, backend_name
        self._lock = asyncio.Lock()

    def ping(self) -> dict:
        # Deliberately no backend, credentials, filesystem or network access.
        return {"status": "ok", "server": "telegram-readonly-mcp", "version": "0.1.0",
                "backend": self.backend_name, "telegram_connection_checked": False}

    def list_allowed_chats(self) -> dict:
        return {"backend": self.backend_name, "chats": [asdict(c) for c in self.settings.allowed_chats],
                "source": "local allowlist; no Telegram dialog discovery"}

    async def messages(self, chat_id: int, limit: int = 20, before_id: int | None = None,
                       query: str | None = None) -> dict:
        validate_request(self.settings, chat_id, limit, before_id)
        if query is not None:
            validate_query(query)
        try:
            # Bounds both waiting for another request and the backend call.
            async with asyncio.timeout(self.settings.request_timeout_seconds):
                async with self._lock:
                    if query is None:
                        result = await self.backend.read_messages(chat_id, limit, before_id)
                    else:
                        result = await self.backend.search_messages(chat_id, query, limit, before_id)
        except (TimeoutError, BackendError):
            raise BackendError("Backend unavailable; retry manually later") from None
        except Exception:
            raise BackendError("Backend request failed") from None
        # Never emit an out-of-scope message even if an adapter is defective.
        if len(result) > limit or any(m.chat_id != chat_id for m in result):
            raise BackendError("Backend violated the response boundary")
        messages = []
        for message in result:
            integer(message.id, "message id", 1, 2**31 - 1)
            if before_id is not None and message.id >= before_id:
                raise BackendError("Backend violated the pagination boundary")
            row = asdict(message)
            row["text"] = message.text[:self.settings.max_text_chars]
            row["text_truncated"] = len(message.text) > self.settings.max_text_chars
            messages.append(row)
        return {"backend": self.backend_name, "synthetic": self.backend_name == "fake",
                "chat_id": chat_id, "messages": messages,
                "next_before_id": min((m.id for m in result), default=None),
                "content_is_untrusted": True}
