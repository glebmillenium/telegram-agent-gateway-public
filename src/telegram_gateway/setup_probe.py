"""Explicit operator-only read probe for UNVERIFIED Telegram setup candidates.

Run only after separately approving the bot credential and reading up to 100
pending bot updates. This command never sends, grants access, writes config,
acknowledges an update, changes a webhook, or selects among duplicate titles.
The marker and group title are exact operator-supplied public test values.
"""
from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass, field
import json
from pathlib import Path
import re

from .auth import OwnerApprovalVerifier
from .network import BotHTTPTransport
from .runtime_auth import _no_duplicate_members
from .runtime_config import SecretRef, load_secret, _external, _path, _text

_PROJECT = Path(__file__).absolute().parents[2]
_CONFIG_LIMIT = 65536
_FIELDS = frozenset({"version", "secrets_dir", "token_ref", "target_title", "marker_text"})
_USERNAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{4,31}\Z")
_UNVERIFIED = "UNVERIFIED_NOT_GRANTED"


class ProbeBlocked(ValueError):
    """Sanitized setup rejection; contains no credential, update or filename."""


@dataclass(frozen=True, slots=True)
class ProbeConfig:
    secrets_dir: Path = field(repr=False)
    token_ref: SecretRef = field(repr=False)
    target_title: str
    marker_text: str = field(repr=False)

    @classmethod
    def from_dict(cls, data):
        try:
            if type(data) is not dict or set(data) != _FIELDS or type(data["version"]) is not int or data["version"] != 1:
                raise ValueError
            directory = _path(data["secrets_dir"], "setup secrets directory")
            _external(directory, _PROJECT, "setup secrets directory")
            ref = SecretRef.from_dict(data["token_ref"], secrets_dir=directory)
            title = _text(data["target_title"], 128, "setup title")
            marker = _text(data["marker_text"], 256, "setup marker")
            return cls(directory, ref, title, marker)
        except (ValueError, TypeError, KeyError):
            raise ProbeBlocked("Invalid setup probe configuration") from None

    @classmethod
    def load(cls, path):
        """Read only the explicit external config; never search personal paths."""
        try:
            source = _path(str(path), "setup config path")
            _external(source, _PROJECT, "setup config path")
            # Resolve only the path explicitly supplied by the future operator.
            # Reject aliases into the checkout before opening the config file.
            physical = source.resolve(strict=True)
            _external(physical, _PROJECT.resolve(strict=True), "setup config path")
            with physical.open("rb") as stream:
                raw = stream.read(_CONFIG_LIMIT + 1)
            if len(raw) > _CONFIG_LIMIT:
                raise ValueError
            def reject_constant(_):
                raise ValueError
            data = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_members,
                              parse_constant=reject_constant)
            return cls.from_dict(data)
        except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
            raise ProbeBlocked("Unable to read valid external setup configuration") from None


def _result(envelope):
    if type(envelope) is not dict or envelope.get("ok") is not True or "result" not in envelope:
        raise ProbeBlocked("Bot setup response unavailable")
    return envelope["result"]


def _positive_id(value, maximum=2**52 - 1):
    return type(value) is int and 1 <= value <= maximum


def _candidate(update, cfg):
    if set(update) != {"update_id", "message"}:
        return None
    message = update.get("message")
    if type(message) is not dict:
        return None
    chat = message.get("chat")
    # Filter before extracting any identifiers from unrelated conversations.
    if (type(chat) is not dict or chat.get("title") != cfg.target_title
            or message.get("text") != cfg.marker_text
            or chat.get("type") not in {"group", "supergroup"}):
        return None
    if any(key in message for key in OwnerApprovalVerifier._FORBIDDEN):
        return None
    sender = message.get("from")
    if (type(sender) is not dict or sender.get("is_bot") is not False
            or not _positive_id(sender.get("id"))
            or type(chat.get("id")) is not int or not -(2**52 - 1) <= chat["id"] <= -1
            or not _positive_id(message.get("message_id"), 2**31 - 1)):
        return None
    topic = message.get("message_thread_id")
    if topic is not None and not _positive_id(topic, 2**31 - 1):
        return None
    candidate = {"status": _UNVERIFIED,
                 "chat": {"id": chat["id"], "type": chat["type"], "title": chat["title"]},
                 "sender": {"id": sender["id"]}, "message_id": message["message_id"]}
    if topic is not None:
        candidate["message_thread_id"] = topic
    return candidate


async def run_probe(cfg: ProbeConfig, *, allow_live_network: bool = False,
                    confirm_read_updates: bool = False, transport_factory=None):
    """Single bounded read, injected fake transport in tests; no update ACK.

    Both explicit gates precede secret loading and transport construction. The
    configured bot may receive unrelated updates: those remain in transient
    memory only and never appear in output. Stop any other consumer beforehand.
    Candidates identify transport observations, not approved owners or grants.
    """
    if allow_live_network is not True or confirm_read_updates is not True:
        raise ProbeBlocked("Both explicit network and update-read confirmations are required")
    if type(cfg) is not ProbeConfig:
        raise ProbeBlocked("Validated setup configuration is required")
    try:
        token = load_secret(cfg.token_ref, secrets_dir=cfg.secrets_dir, live_mode=True)
        factory = BotHTTPTransport if transport_factory is None else transport_factory
        transport = factory(token)
        del token
        me = _result(await transport.get_me())
        if (type(me) is not dict or me.get("is_bot") is not True or not _positive_id(me.get("id"))
                or type(me.get("username")) is not str or not _USERNAME.fullmatch(me["username"])):
            raise ProbeBlocked("Bot setup identity unavailable")
        webhook = _result(await transport.get_webhook_info())
        if type(webhook) is not dict or type(webhook.get("url")) is not str:
            raise ProbeBlocked("Webhook state unavailable")
        if webhook["url"]:
            raise ProbeBlocked("Existing webhook prevents setup probing; it was not changed")
        # Do not send allowed_updates: Telegram persists that filter. The setup
        # probe preserves it and ignores non-message envelopes locally instead.
        updates = _result(await transport.request("getUpdates", {
            "offset": 0, "limit": 100, "timeout": 0}))
        if type(updates) is not list or len(updates) > 100:
            raise ProbeBlocked("Invalid setup update batch")
        seen = set()
        candidates = []
        for update in updates:
            if (type(update) is not dict or type(update.get("update_id")) is not int
                    or not 0 <= update["update_id"] <= 2**63 - 1 or update["update_id"] in seen):
                raise ProbeBlocked("Invalid setup update batch")
            seen.add(update["update_id"])
            candidate = _candidate(update, cfg)
            if candidate is not None:
                candidates.append(candidate)
        return {"status": _UNVERIFIED, "bot": {"id": me["id"], "username": me["username"]},
                "candidates": candidates, "selected": None,
                "operator_review_required": True, "updates_acknowledged": False,
                "permissions_granted": False}
    except ProbeBlocked:
        raise
    except Exception:
        raise ProbeBlocked("Setup probe unavailable; no configuration or permissions were changed") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path, help="Explicit external non-secret setup JSON")
    parser.add_argument("--allow-live-network", action="store_true", help="Allow Bot API HTTPS for this operator invocation")
    parser.add_argument("--confirm-read-updates", action="store_true",
                        help="Read up to 100 pending bot updates once; show exact marker candidates without acknowledging updates")
    args = parser.parse_args(argv)
    try:
        # CLI also checks before reading even the non-secret config.
        if not args.allow_live_network or not args.confirm_read_updates:
            raise ProbeBlocked("Both setup confirmations are required")
        cfg = ProbeConfig.load(args.config)
        result = asyncio.run(run_probe(cfg, allow_live_network=args.allow_live_network,
                                      confirm_read_updates=args.confirm_read_updates))
        print(json.dumps(result, ensure_ascii=True, sort_keys=True))
        return 0
    except Exception:
        parser.exit(2, "Setup probe rejected. Check the explicit confirmations, external configuration and bot setup. No raw errors or updates are logged.\n")


if __name__ == "__main__":
    raise SystemExit(main())
