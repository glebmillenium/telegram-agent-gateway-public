"""Manual MCP2 client for an already authorized local gateway.

Reads only the explicitly selected credential file when invoked. Never starts a
server, creates credentials, changes grants, or contacts a configurable address.
send-draft submits only an existing immutable draft ID; server policy decides
whether delivery is authorized. Every invocation makes one request, never an
automatic retry. Repeated create-draft calls can create different drafts.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

import httpx

ENDPOINT = "http://127.0.0.1:8765/mcp"
VERSION = "2026-07-28"
REQUEST_ID = "local-gateway-client"
_BEARER = re.compile(r"[A-Za-z0-9._~+/-]+=*\Z")
_DRAFT_ID = re.compile(r"[0-9a-f]{32}\Z")
_TOOLS = {"ping": "ping", "status": "status", "list-scopes": "list_allowed_scopes", "read-history": "read_history",
          "search-history": "search_history", "next-events": "next_events", "ack-event": "ack_event",
          "create-draft": "create_draft", "send-draft": "send_draft", "draft-status": "get_draft_status"}
_MAX_AUTH_BYTES = 65536
_MAX_RESPONSE_BYTES = 1048576


class LocalClientError(ValueError):
    pass


class GatewayToolError(LocalClientError):
    """A tool error does not determine whether a side effect occurred."""


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError()
        result[key] = value
    return result


def _invalid_number(_):
    raise ValueError()


def _json(raw):
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_invalid_number)


def _load_bearer(path):
    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(_MAX_AUTH_BYTES + 1)
        if len(raw) > _MAX_AUTH_BYTES:
            raise ValueError()
        data = _json(raw)
        if type(data) is not dict or set(data) != {"version", "bearer"}:
            raise ValueError()
        token = data["bearer"]
        if (type(data["version"]) is not int or data["version"] != 1 or type(token) is not str
                or not 1 <= len(token) <= 8192 or not _BEARER.fullmatch(token)):
            raise ValueError()
        return token
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        raise LocalClientError("Local credential is unavailable") from None


def _redact(value, bearer):
    if isinstance(value, str):
        return value.replace(bearer, "[REDACTED]")
    if isinstance(value, list):
        return [_redact(item, bearer) for item in value]
    if isinstance(value, dict):
        return {_redact(key, bearer): _redact(item, bearer) for key, item in value.items()}
    # A numeric bearer can be echoed as a JSON number; booleans/null also have
    # serialized spellings. Replace the entire primitive, preserving valid JSON.
    if bearer in json.dumps(value, ensure_ascii=False, allow_nan=False):
        return "[REDACTED]"
    return value


def _call(tool, arguments, bearer):
    if tool not in _TOOLS.values():
        raise LocalClientError("Local command is unavailable")
    if tool in {"send_draft", "get_draft_status"} and (type(arguments) is not dict or set(arguments) != {"draft_id"}
            or type(arguments["draft_id"]) is not str or not _DRAFT_ID.fullmatch(arguments["draft_id"])):
        raise LocalClientError("Invalid draft reference")
    if tool == "ack_event" and (type(arguments) is not dict or set(arguments) != {"event_id"}
            or type(arguments["event_id"]) is not int or not 1 <= arguments["event_id"] <= 2**63 - 1):
        raise LocalClientError("Invalid event reference")
    payload = {"jsonrpc": "2.0", "id": REQUEST_ID, "method": "tools/call", "params": {
        "name": tool, "arguments": arguments,
        "_meta": {"io.modelcontextprotocol/protocolVersion": VERSION,
                  "io.modelcontextprotocol/clientCapabilities": {},
                  "io.modelcontextprotocol/clientInfo": {"name": "telegram-gateway-local-client", "version": "1"}},
    }}
    headers = {"Authorization": "Bearer " + bearer, "Content-Type": "application/json",
               "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": VERSION,
               "Mcp-Method": "tools/call", "Mcp-Name": tool}
    try:
        # Fixed loopback, one attempt: no DNS, proxies, redirects or retries.
        with httpx.Client(timeout=10, trust_env=False, follow_redirects=False) as client:
            with client.stream("POST", ENDPOINT, json=payload, headers=headers) as response:
                if response.status_code != 200:
                    raise ValueError()
                if response.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
                    raise ValueError()
                raw = bytearray()
                for chunk in response.iter_bytes(chunk_size=8192):
                    if len(raw) + len(chunk) > _MAX_RESPONSE_BYTES:
                        raise ValueError()
                    raw.extend(chunk)
        body = _json(bytes(raw))
        if (type(body) is not dict or set(body) != {"jsonrpc", "id", "result"}
                or body["jsonrpc"] != "2.0" or body["id"] != REQUEST_ID):
            raise ValueError()
        result = body["result"]
        if type(result) is dict and result.get("isError") is True:
            raise GatewayToolError("Gateway tool reported an error")
        if type(result) is not dict or result.get("isError", False) is not False:
            raise ValueError()
        output = result.get("structuredContent", result)
        if type(output) is not dict:
            raise ValueError()
        return _redact(output, bearer)
    except GatewayToolError:
        raise
    except (httpx.HTTPError, OSError, ValueError, TypeError, UnicodeError, RecursionError):
        raise LocalClientError("Gateway request failed") from None


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        # Never echo unknown arguments, which might contain pasted credentials.
        self.exit(2, "Invalid local client command\n")


def _integer(low, high):
    def convert(value):
        try:
            result = int(value)
        except (TypeError, ValueError):
            raise argparse.ArgumentTypeError("Invalid integer") from None
        if not low <= result <= high:
            raise argparse.ArgumentTypeError("Invalid integer")
        return result
    return convert


def _text(value):
    if not 1 <= len(value) <= 4000 or "\x00" in value:
        raise argparse.ArgumentTypeError("Invalid draft text")
    return value


def _draft_id(value):
    if not _DRAFT_ID.fullmatch(value):
        raise argparse.ArgumentTypeError("Invalid draft reference")
    return value


def _query(value):
    if not 1 <= len(value) <= 200 or "\x00" in value:
        raise argparse.ArgumentTypeError("Invalid search query")
    return value


def _scope_options(parser, *, aggregate):
    parser.add_argument("--chat-id", required=True, type=_integer(-(2**52 - 1), -1))
    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument("--topic-id", type=_integer(1, 2**31 - 1))
    scope.add_argument("--unthreaded", action="store_true")
    if aggregate:
        scope.add_argument("--all-topics", action="store_true")


def main(argv=None):
    parser = _Parser(description="Manual client for the fixed local Telegram gateway.")
    parser.add_argument("--auth-file", required=True, type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("ping")
    commands.add_parser("status")
    commands.add_parser("list-scopes")
    for name in ("read-history", "search-history", "next-events"):
        command = commands.add_parser(name)
        _scope_options(command, aggregate=True)
        command.add_argument("--limit", type=_integer(1, 100), default=20)
        if name == "search-history":
            command.add_argument("--query", required=True, type=_query)
    ack = commands.add_parser("ack-event", allow_abbrev=False)
    ack.add_argument("--event-id", required=True, type=_integer(1, 2**63 - 1))
    draft = commands.add_parser("create-draft", description=(
        "Create a new draft. Repeated requests can create different drafts; "
        "do not automatically retry after an uncertain result."))
    _scope_options(draft, aggregate=False)
    draft.add_argument("--text", required=True, type=_text)
    draft.add_argument("--reply-to-message-id", type=_integer(1, 2**31 - 1))
    send = commands.add_parser("send-draft", allow_abbrev=False, description=(
        "Submit one existing draft ID under server policy. "
        "Do not automatically retry an unknown delivery result."))
    send.add_argument("--draft-id", required=True, type=_draft_id)
    draft_status = commands.add_parser("draft-status", allow_abbrev=False, description=(
        "Read metadata for one owned draft ID; does not send, retry or reconcile it."))
    draft_status.add_argument("--draft-id", required=True, type=_draft_id)
    args = parser.parse_args(argv)
    arguments = {}
    if args.command in ("read-history", "search-history", "next-events", "create-draft"):
        arguments = {"chat_id": args.chat_id, "topic_id": args.topic_id}
        if args.command == "create-draft":
            arguments["text"] = args.text
            if args.reply_to_message_id is not None:
                arguments["reply_to_message_id"] = args.reply_to_message_id
        else:
            arguments["limit"] = args.limit
            if args.command == "search-history":
                arguments["query"] = args.query
            if args.all_topics:
                arguments["all_topics"] = True
    elif args.command in ("send-draft", "draft-status"):
        arguments = {"draft_id": args.draft_id}
    elif args.command == "ack-event":
        arguments = {"event_id": args.event_id}
    try:
        bearer = _load_bearer(args.auth_file)
        result = _call(_TOOLS[args.command], arguments, bearer)
        # Windows redirected stdout may use a legacy code page. ASCII JSON
        # preserves Unicode on decode without failing after a successful mutation.
        encoded = json.dumps(result, ensure_ascii=True, allow_nan=False)
        # Guard serializer-generated escape sequences too, without emitting
        # invalid JSON through a final textual replacement.
        print("{}" if bearer in encoded else encoded)
        if args.command == "send-draft" and result.get("status") != "sent":
            if result.get("status") == "failed":
                print("Gateway rejected the draft; no successful delivery was recorded. Do not automatically retry.", file=sys.stderr)
            elif result.get("status") == "unknown":
                print("Draft delivery outcome is unknown; do not automatically retry.", file=sys.stderr)
            else:
                print("Draft delivery is not confirmed; do not automatically retry.", file=sys.stderr)
            return 1
        return 0
    except GatewayToolError:
        print("Gateway tool reported an error", file=sys.stderr)
        if args.command == "send-draft":
            print("Inspect draft-status; do not automatically retry. This does not determine an earlier send outcome.", file=sys.stderr)
        elif args.command == "create-draft":
            print("Do not automatically retry create-draft; repeated requests can create different drafts.", file=sys.stderr)
        return 1
    except (LocalClientError, ValueError, TypeError, UnicodeError, RecursionError):
        print("Local gateway command failed", file=sys.stderr)
        if args.command == "create-draft":
            print("Do not automatically retry create-draft; repeated requests can create different drafts.", file=sys.stderr)
        elif args.command == "send-draft":
            print("Draft delivery may be unknown; do not automatically retry.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
