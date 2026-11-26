"""Interactive USER-only first login. Never called by the MCP server.

Run only after the user has approved and prepared session isolation. A Telegram
MTProto session has the account's full authority; this is not a read-only key.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
from pathlib import Path
import re
import sys

from telethon import errors, utils
from telethon.tl import functions

from .core import BackendError
from .telethon_backend import UserLoginTelegramClient, quiet_telegram_logger, validated_session_path


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="User-only creation of a NEW full-authority Telegram session outside the repository.")
    result.add_argument("--session", type=Path, required=True, help="Absolute new .session path in an already isolated directory.")
    result.add_argument("--accept-full-account-session-risk", action="store_true", help="Acknowledge full session authority; this flag does not establish isolation.")
    result.add_argument("--peer-username", help="Optional exact username selected by the user; resolve this peer once, without listing dialogs.")
    return result


async def login(args: argparse.Namespace) -> None:
    if not args.accept_full_account_session_risk:
        raise BackendError("Explicit full-account-session risk acknowledgment is required.")
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise BackendError("Login requires the user's own interactive terminal; redirected input/output is refused.")
    path = validated_session_path(args.session, must_exist=False)
    username = args.peer_username
    if username is not None:
        username = username.removeprefix("@")
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{3,31}", username):
            raise BackendError("Supply one exact Telegram username, without URLs or invite links.")
    print("Session has FULL Telegram account authority. Continue only in your isolated user environment.")
    print("Authenticate only the explicitly approved receiving account. Test senders use separate accounts.")
    if input("Type WORK ACCOUNT to confirm the intended receiving account: ").strip() != "WORK ACCOUNT":
        raise BackendError("Login cancelled before connecting.")
    api_id_text = getpass.getpass("Telegram api_id (hidden): ")
    api_hash = getpass.getpass("Telegram api_hash (hidden): ")
    phone = getpass.getpass("WORK account phone with country code (hidden): ")
    if not api_id_text.isdecimal() or int(api_id_text) <= 0 or not re.fullmatch(r"[0-9a-fA-F]{32}", api_hash):
        raise BackendError("Invalid application credentials format.")
    if not re.fullmatch(r"\+[0-9]{7,15}", phone):
        raise BackendError("Use a phone number with +country code.")
    # Exclusive reservation prevents accidental reuse/overwrite between the
    # preflight check and SQLite opening. Do not silently remove failed sessions.
    try:
        with path.open("xb"):
            pass
    except FileExistsError:
        raise BackendError("Session path now exists; refusing to reuse it.") from None
    client = UserLoginTelegramClient(
        str(path), int(api_id_text), api_hash,
        peer_username=username,
        # A first login may require one explicit phone-DC migration. Runtime
        # reads keep request_retries=0 and refuse any migration/new auth key.
        receive_updates=False, catch_up=False, request_retries=1,
        connection_retries=0, auto_reconnect=False, flood_sleep_threshold=0,
        timeout=20, base_logger=quiet_telegram_logger(),
        device_model="Telegram read-only MCP pilot (full-authority session)",
    )
    try:
        async with asyncio.timeout(240):
            await client.connect()
            if await client.is_user_authorized():
                raise BackendError("Unexpected pre-authorized session; refusing to continue.")
            await client.send_code_request(phone)
            code = getpass.getpass("Login code (hidden): ")
            try:
                await client.sign_in(phone=phone, code=code)
            except errors.SessionPasswordNeededError:
                password = getpass.getpass("Telegram 2FA password (hidden): ")
                await client.sign_in(password=password)
            print("New session authorized. Check the account and session in Telegram Settings > Devices.")
            if username is not None:
                # A single explicit account lookup, never get_dialogs(), contacts
                # enumeration or message reading. The resulting entity is cached
                # in this newly created session for later numeric-ID-only use.
                resolved = await client(functions.contacts.ResolveUsernameRequest(username=username))
                peer_id = utils.get_peer_id(resolved.peer)
                print(f"Selected peer numeric ID: {peer_id}")
                print("Verify this peer in Telegram before adding this ID to the allowlist.")
    finally:
        try:
            await asyncio.wait_for(client.disconnect(), timeout=20)
        except Exception:
            pass


def main() -> None:
    args = parser().parse_args()
    try:
        asyncio.run(login(args))
    except BackendError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2) from None
    except (KeyboardInterrupt, EOFError):
        print("Login interrupted. Check Telegram Devices and revoke the pilot session if created.", file=sys.stderr)
        raise SystemExit(130) from None
    except Exception:
        print("Login failed. Check the result privately in Telegram Devices; do not share secrets or session files. A partial session file may exist.", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
