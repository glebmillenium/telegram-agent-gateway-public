"""Compile non-secret agent profiles into the existing enforced runtime policy.

Profiles are configuration metadata, never authentication claims or instructions
for this process. Importing/compiling performs no filesystem or network access.
"""
from __future__ import annotations

import copy
from pathlib import Path
import re
from types import MappingProxyType

from .auth import AuthenticationDenied, _principal_id
from .local_secrets import LocalSecretsError, validate_bot_name
from .policy import PERMISSIONS

_ROOT_FIELDS = frozenset({
    "version", "mode", "agents", "bind", "state_dir", "secrets_dir", "auth",
    "allowed_callbacks", "routine_routes", "public_base_url", "allowed_hosts",
    "allowed_origins", "network_enabled", "outbound_enabled", "poll_interval_seconds",
})
_AGENT_REQUIRED = frozenset({"id", "name", "purpose", "prompt", "enabled", "telegram_username", "auth_principal", "chats"})
_INTEGRATION_IDENTIFIER = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")


class AgentConfigError(ValueError):
    pass


def _bad():
    raise AgentConfigError("Invalid agent configuration")


def _metadata(value, limit, *, nonempty=False):
    if type(value) is not str or len(value) > limit or nonempty and not value or "\x00" in value:
        _bad()
    return value


def _integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        _bad()
    return value


def _standing_send(raw):
    """Exact, inert declaration; identities are inferred elsewhere, never supplied."""
    if raw is None:
        return None
    if (type(raw) is not dict or not {"purpose", "chat_id"} <= set(raw)
            or set(raw) - {"purpose", "chat_id", "topic_id", "all_topics"}
            or raw["purpose"] != "gateway_technical_test"):
        _bad()
    chat_id = _integer(raw["chat_id"], -(2**52 - 1), -1)
    topic_id = raw.get("topic_id")
    all_topics = raw.get("all_topics", False)
    if type(all_topics) is not bool or all_topics and topic_id is not None:
        _bad()
    if topic_id is not None:
        _integer(topic_id, 1, 2**31 - 1)
    return {"purpose": "gateway_technical_test", "chat_id": chat_id, "topic_id": topic_id,
            **({"all_topics": True} if all_topics else {})}


def _username(value):
    if type(value) is not str:
        _bad()
    try:
        return validate_bot_name(value)
    except LocalSecretsError:
        _bad()


def _identity(value):
    try:
        _principal_id(value)
    except (AuthenticationDenied, TypeError):
        _bad()
    return value


def _integration(raw):
    """Connection metadata; enabled routes are bound separately, never grants."""
    required = {"platform", "inbound", "outbound"}
    if type(raw) is not dict or not required <= set(raw) or set(raw) - required - {"enabled", "status"}:
        _bad()
    platform = raw["platform"]
    if type(platform) is not str or not _INTEGRATION_IDENTIFIER.fullmatch(platform):
        _bad()
    enabled, declared_status = raw.get("enabled", False), raw.get("status", "pending")
    if type(enabled) is not bool or type(declared_status) is not str or declared_status not in {"pending", "configured", "verified"}:
        _bad()
    if declared_status == "verified":
        raise AgentConfigError("Integration verification is unavailable")
    channels = {}
    for direction, modes in (("inbound", {"manual", "mcp_events", "webhook"}),
                             ("outbound", {"remote_mcp", "local_commands"})):
        channel = raw[direction]
        if type(channel) is not dict or "mode" not in channel or set(channel) - {"mode", "ref"}:
            _bad()
        mode = channel["mode"]
        if type(mode) is not str or mode not in modes:
            _bad()
        normalized = {"mode": mode}
        if "ref" in channel:
            reference = channel["ref"]
            if type(reference) is not str or not _INTEGRATION_IDENTIFIER.fullmatch(reference):
                _bad()
            normalized["ref"] = reference
        channels[direction] = MappingProxyType(normalized)
    if enabled and not (platform == "grok_bot"
                        and channels["inbound"]["mode"] == "webhook"
                        and channels["outbound"]["mode"] == "local_commands"
                        and all("ref" in channel for channel in channels.values())):
        raise AgentConfigError("Integration adapter is not connected")
    return MappingProxyType({
        "platform": platform, **channels, "enabled": enabled,
        "status": "configured" if all("ref" in channel for channel in channels.values()) else "pending",
        "reason": "delivery_not_verified" if enabled else "adapter_not_connected",
    })



def _routine_routes(raw, profiles):
    """Bind every route to one explicitly enabled integration and active bot."""
    if type(raw) is not dict or len(raw) > 64:
        _bad()
    routes = {}
    fields = {"principal_id", "bot_reference", "url", "bearer_ref"}
    for route_id, route in raw.items():
        if (type(route_id) is not str or not _INTEGRATION_IDENTIFIER.fullmatch(route_id)
                or type(route) is not dict or not fields <= set(route)
                or set(route) - fields - {"addressing"}):
            _bad()
        addressing = route.get("addressing", "mentions_or_replies")
        if type(addressing) is not str or addressing != "mentions_or_replies":
            _bad()
        routes[route_id] = {**copy.deepcopy(route), "addressing": addressing,
                            "principal_id": _identity(route["principal_id"]),
                            "bot_reference": _username(route["bot_reference"])}
    used = set()
    for profile in profiles:
        integration = profile.get("integration", {})
        if not integration.get("enabled", False):
            continue
        route_id = integration["inbound"]["ref"]
        route = routes.get(route_id)
        if (not profile["enabled"] or route is None or route_id in used
                or route["principal_id"] != profile["auth_principal"]
                or route["bot_reference"] != profile["telegram_username"]):
            _bad()
        used.add(route_id)
    if used != set(routes):
        _bad()
    return routes

def _chat(entry):
    required = {"chat_id", "type", "title", "actions"}
    if type(entry) is not dict or not required <= set(entry) or set(entry) - required - {"topic_id", "all_topics"}:
        _bad()
    chat_id = _integer(entry["chat_id"], -(2**52 - 1), -1)
    if entry["type"] not in ("group", "supergroup"):
        _bad()
    title = _metadata(entry["title"], 256, nonempty=True)
    if any(ord(c) < 32 or ord(c) == 127 for c in title):
        _bad()
    topic = entry.get("topic_id")
    all_topics = entry.get("all_topics", False)
    if type(all_topics) is not bool or all_topics and topic is not None:
        _bad()
    if topic is not None:
        _integer(topic, 1, 2**31 - 1)
        if entry["type"] != "supergroup":
            _bad()
    actions = entry["actions"]
    if type(actions) is not list or any(type(a) is not str or a not in PERMISSIONS for a in actions) or len(set(actions)) != len(actions):
        _bad()
    return {"chat_id": chat_id, "type": entry["type"], "title": title,
            "topic_id": topic, "all_topics": all_topics, "actions": tuple(actions)}


def compile_agent_config(data: dict) -> tuple[dict, dict, tuple, dict]:
    """Return common config, per-bot configs, immutable profiles and bindings.

    Each active bot becomes an independently validated runtime configuration.
    Disabled profiles are excluded from policy, bindings and token references.
    """
    if type(data) is not dict or set(data) - _ROOT_FIELDS or "agents" not in data:
        _bad()
    entries = data["agents"]
    if type(entries) is not list or len(entries) > 64:
        _bad()
    profiles, active = [], []
    ids, principals, usernames = set(), set(), set()
    for entry in entries:
        if type(entry) is not dict or not _AGENT_REQUIRED <= set(entry) or set(entry) - _AGENT_REQUIRED - {"expected_bot_id", "approval", "integration", "standing_send"}:
            _bad()
        identity = _identity(entry["id"])
        if type(entry["enabled"]) is not bool:
            _bad()
        chats = entry["chats"]
        if type(chats) is not list or len(chats) > 128:
            _bad()
        pending = entry["auth_principal"] is None or entry["telegram_username"] is None
        if pending and (entry["enabled"] or chats
                        or {"expected_bot_id", "approval", "standing_send"} & set(entry)):
            _bad()
        principal = None if entry["auth_principal"] is None else _identity(entry["auth_principal"])
        username = None if entry["telegram_username"] is None else _username(entry["telegram_username"])
        if (identity in ids or principal is not None and principal in principals
                or username is not None and username in usernames):
            _bad()
        ids.add(identity)
        if principal is not None:
            principals.add(principal)
        if username is not None:
            usernames.add(username)
        normalized_chats = tuple(_chat(chat) for chat in chats)
        scopes = {(chat["chat_id"], chat["topic_id"], chat["all_topics"]) for chat in normalized_chats}
        if len(scopes) != len(normalized_chats):
            _bad()
        profile = {
            "id": identity, "name": _metadata(entry["name"], 128, nonempty=True),
            "purpose": _metadata(entry["purpose"], 1024),
            "prompt": _metadata(entry["prompt"], 8192),
            "enabled": entry["enabled"], "telegram_username": username,
            "auth_principal": principal,
            "chats": tuple(MappingProxyType(chat) for chat in normalized_chats),
        }
        if "expected_bot_id" in entry:
            profile["expected_bot_id"] = _integer(entry["expected_bot_id"], 1, 2**52 - 1)
        standing = _standing_send(entry.get("standing_send"))
        if standing is not None:
            if not entry["enabled"] or "expected_bot_id" not in profile:
                _bad()
            if not any("send" in chat["actions"]
                       and chat["all_topics"] == standing.get("all_topics", False)
                       and chat["chat_id"] == standing["chat_id"]
                       and (standing.get("all_topics", False) or chat["topic_id"] == standing["topic_id"])
                       for chat in normalized_chats):
                _bad()
            profile["standing_send"] = MappingProxyType(standing)
        if "integration" in entry:
            profile["integration"] = _integration(entry["integration"])
            if pending and profile["integration"]["enabled"]:
                _bad()
        if "approval" in entry:
            approval = entry["approval"]
            if type(approval) is not dict or set(approval) - {"owner_ids", "review_scope"}:
                _bad()
            owners = approval.get("owner_ids", [])
            if type(owners) is not list or len(owners) > 32:
                _bad()
            for owner in owners:
                _integer(owner, 1, 2**52 - 1)
            if len(owners) != len(set(owners)):
                _bad()
            review = approval.get("review_scope")
            if review is not None:
                if type(review) is not dict or "chat_id" not in review or set(review) - {"chat_id", "topic_id"}:
                    _bad()
                _integer(review["chat_id"], -(2**52 - 1), -1)
                if review.get("topic_id") is not None:
                    _integer(review["topic_id"], 1, 2**31 - 1)
            if bool(owners) != (review is not None):
                _bad()
            profile["approval"] = MappingProxyType({
                "owner_ids": tuple(owners),
                **({"review_scope": MappingProxyType(dict(review))} if review is not None else {}),
            })
        profiles.append(MappingProxyType(profile))
        if entry["enabled"]:
            active.append(profile)
    bot_ids = [entry["expected_bot_id"] for entry in active if "expected_bot_id" in entry]
    if data.get("mode", "disabled") == "live" and len(bot_ids) != len(set(bot_ids)):
        _bad()
    routes = _routine_routes(data.get("routine_routes", {}), profiles)
    normalized = {key: value for key, value in data.items() if key not in {"agents", "routine_routes"}}
    normalized["policy"] = {"principals": {}}
    normalized["bot"] = {"approved_groups": []}
    children, bindings, all_groups = {}, {}, {}
    for profile in active:
        reference, principal = profile["telegram_username"], profile["auth_principal"]
        bindings[principal] = reference
        child = {key: copy.deepcopy(value) for key, value in data.items() if key not in {"agents", "routine_routes"}}
        owned_routes = {key: copy.deepcopy(route) for key, route in routes.items()
                        if route["principal_id"] == principal}
        if owned_routes:
            child["routine_routes"] = owned_routes
        groups, grants = {}, []
        for chat in profile["chats"]:
            group = {key: chat[key] for key in ("chat_id", "type", "title")}
            if chat["chat_id"] in all_groups and all_groups[chat["chat_id"]] != group:
                _bad()
            groups[chat["chat_id"]] = group
            all_groups[chat["chat_id"]] = group
            grant = {"chat_id": chat["chat_id"], "topic_id": chat["topic_id"], "permissions": list(chat["actions"])}
            if chat["all_topics"]:
                grant["all_topics"] = True
            grants.append(grant)
        child["policy"] = {"principals": {principal: grants}}
        child["agent_bindings"] = {principal: reference}
        child["bot"] = {"reference": reference, "approved_groups": list(groups.values())}
        normalized["policy"]["principals"][principal] = grants
        if "expected_bot_id" in profile:
            child["bot"]["expected_bot_id"] = profile["expected_bot_id"]
        if data.get("mode", "disabled") == "live":
            child["bot"]["token_ref"] = {"local_bot": reference}
        for field in ("state_dir", "secrets_dir"):
            if field in child:
                if type(child[field]) is not str:
                    _bad()
                child[field] = str(Path(child[field]) / "bots" / reference)
        if "approval" in profile:
            child["approval"] = {"owner_ids": list(profile["approval"]["owner_ids"])}
            if "review_scope" in profile["approval"]:
                child["approval"]["review_scope"] = dict(profile["approval"]["review_scope"])
        if profile.get("standing_send") is not None:
            child["standing_send"] = dict(profile["standing_send"])
        # A read-only sibling does not acquire an outbound gate merely because
        # another bot in the catalog has a reviewed or standing send policy.
        if (child.get("outbound_enabled") is True
                and not any(set(grant["permissions"]) & {"send", "forward"} for grant in grants)
                and not profile.get("approval", {}).get("owner_ids")
                and profile.get("standing_send") is None):
            child["outbound_enabled"] = False
        if "allowed_callbacks" in child:
            callbacks = child["allowed_callbacks"]
            if type(callbacks) is not dict:
                _bad()
            child["allowed_callbacks"] = {principal: callbacks[principal]} if principal in callbacks else {}
        if "auth" in child:
            auth = child["auth"]
            if type(auth) is not dict:
                _bad()
            auth_mode = auth.get("mode")
            if auth_mode in ("fake", "static"):
                field = "credentials" if auth_mode == "fake" else "token_digests"
                entries = auth.get(field)
                if type(entries) is not dict:
                    _bad()
                auth[field] = {key: value for key, value in entries.items() if value == principal}
            elif auth_mode == "oauth":
                subjects = auth.get("subjects")
                if type(subjects) is not list or any(type(subject) is not dict for subject in subjects):
                    _bad()
                auth["subjects"] = [subject for subject in subjects if subject.get("principal") == principal]
        children[reference] = child
    normalized["bot"]["approved_groups"] = list(all_groups.values())
    return normalized, children, tuple(profiles), bindings
