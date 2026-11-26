"""Explicit local bot-token and webhook-secret reads; no file access on import or config parsing.

The user-selected plaintext file is excluded from source control and packages.
Status output contains booleans only. Tests always supply disposable fake files.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import json
from pathlib import Path
import re

_PROJECT = Path(__file__).absolute().parents[2]
_MAX_BYTES = 65536
_BOT_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{4,31}\Z")
_WEBHOOK_REF = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_WEBHOOK_HEADER = re.compile(r"[!-~](?:[ -~]{0,4094}[!-~])?\Z")
# Same accepted syntax as network.BotHTTPTransport; this is not verification
# that the credential belongs to the configured bot (getMe performs that later).
_TOKEN = re.compile(r"[0-9]{5,20}:[A-Za-z0-9_-]{20,128}\Z")


class LocalSecretsError(ValueError):
    pass


def validate_bot_name(bot_name: str) -> str:
    """Canonical ASCII Telegram username: remove at most one @, then casefold."""
    if not isinstance(bot_name, str):
        raise LocalSecretsError("Local bot secret is unavailable")
    name = bot_name.removeprefix("@")
    if not _BOT_NAME.fullmatch(name):
        raise LocalSecretsError("Local bot secret is unavailable")
    return name.casefold()



@dataclass(frozen=True, slots=True)
class WebhookSecret:
    url: str = field(repr=False)
    authorization_header: str = field(repr=False)


def validate_webhook_ref(reference: str) -> str:
    if type(reference) is not str or not _WEBHOOK_REF.fullmatch(reference):
        raise LocalSecretsError("Local webhook secret is unavailable")
    return reference

def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError()
        result[key] = value
    return result


def _invalid_number(_):
    raise ValueError()


def _read(path: Path | str | None, *, section: str = "bots") -> dict:
    try:
        source = _PROJECT / "secrets.local.json" if path is None else Path(path)
        if not source.is_absolute() or ".." in source.parts or str(source).startswith(("\\\\", "//")):
            raise ValueError()
        # Never follow an aliased local-secret file into some other credential.
        if source.resolve(strict=True) != source.absolute():
            raise ValueError()
        with source.open("rb") as stream:
            raw = stream.read(_MAX_BYTES + 1)
        if len(raw) > _MAX_BYTES:
            raise ValueError()
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                          parse_constant=_invalid_number)
        if (type(data) is not dict or not {"version", "bots"} <= set(data)
                or set(data) - {"version", "bots", "webhooks"}):
            raise ValueError()
        if type(data["version"]) is not int or data["version"] != 1:
            raise ValueError()
        bots = data["bots"]
        if type(bots) is not dict or len(bots) > 64:
            raise ValueError()
        webhooks = data.get("webhooks", {})
        if type(webhooks) is not dict or len(webhooks) > 64:
            raise ValueError()
        if section == "webhooks":
            for reference in webhooks:
                validate_webhook_ref(reference)
            return webhooks
        if section != "bots":
            raise ValueError()
        normalized = {}
        for name, entry in bots.items():
            name = validate_bot_name(name)
            if name in normalized:
                raise ValueError()
            normalized[name] = entry
        return normalized
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        raise LocalSecretsError("Local bot secret is unavailable") from None


def _selected_token(bots: dict, name: str) -> str:
    """A malformed other-bot entry must not disable this bot's valid secret."""
    entry = bots.get(name)
    if type(entry) is not dict or set(entry) != {"token"}:
        raise LocalSecretsError("Local bot secret is unavailable")
    token = entry["token"]
    if type(token) is not str or token != "" and not _TOKEN.fullmatch(token):
        raise LocalSecretsError("Local bot secret is unavailable")
    return token


def load_bot_token(bot_name: str, *, path: Path | str | None = None) -> str:
    """Read one configured token explicitly; never expose details in failures."""
    name = validate_bot_name(bot_name)
    bots = _read(path)
    token = _selected_token(bots, name)
    if not token:
        raise LocalSecretsError("Local bot secret is unavailable")
    return token



def load_webhook(reference: str, *, path: Path | str | None = None) -> WebhookSecret:
    """Retrieve one URL/full Authorization value; never activate a route."""
    try:
        reference = validate_webhook_ref(reference)
        entry = _read(path, section="webhooks").get(reference)
        if type(entry) is not dict or set(entry) != {"url", "authorization_header"}:
            raise ValueError()
        header, url = entry["authorization_header"], entry["url"]
        if type(header) is not str or not _WEBHOOK_HEADER.fullmatch(header):
            raise ValueError()
        if type(url) is not str or "#" in url:
            raise ValueError()
        # Lazy pure URL normalization: no DNS, connection, grant or activation.
        from .runtime_config import _callback
        return WebhookSecret(_callback(url), header)
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        raise LocalSecretsError("Local webhook secret is unavailable") from None

def status(bot_name: str, *, path: Path | str | None = None) -> dict[str, bool]:
    """Read explicit local configuration and return only coarse boolean status."""
    result = {"valid": False, "bot_present": False, "token_configured": False}
    try:
        name = validate_bot_name(bot_name)
        bots = _read(path)
        token = _selected_token(bots, name) if name in bots else ""
    except LocalSecretsError:
        return result
    result["valid"] = True
    result["bot_present"] = name in bots
    result["token_configured"] = bool(token)
    return result


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's default error echoes unknown arguments, possibly secrets.
        self.exit(2, "Invalid local secrets command\n")


def main(argv=None) -> int:
    parser = _Parser(description="Check local bot configuration without printing secrets.")
    parser.add_argument("command", choices=("check",))
    parser.add_argument("--bot", required=True)
    parser.add_argument("--path", type=Path)
    args = parser.parse_args(argv)
    result = status(args.bot, path=args.path)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["token_configured"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
