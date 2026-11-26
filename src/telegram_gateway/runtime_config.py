"""Strict, non-secret runtime config parsing; secret reads are explicit/live only.

Parsing performs lexical path validation, never stat/resolve/reads of referenced
state, secrets, JWKS or personal settings. Runtime loads approved secrets through
load_secret only after its separate live/network gates have passed.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
import ipaddress
import json
import math
import os
from pathlib import Path
import re
from types import MappingProxyType
from urllib.parse import urlsplit

from .auth import AuthenticationDenied, FakeAuthenticator
from .policy import GatewayDenied, Policy, Scope
from .events import EventError, _callback_url
from .runtime_auth import StaticBearerAuthenticator, _url as _auth_url

_DEFAULT_PROJECT = Path(__file__).absolute().parents[2]
_ENV = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
_SCOPE = re.compile(r"[A-Za-z][A-Za-z0-9:._/-]{0,127}\Z")
_MODES = frozenset({"disabled", "fake", "live"})
_ROOT_FIELDS = frozenset({"version", "mode", "bind", "state_dir", "secrets_dir", "policy", "agent_bindings", "auth", "bot", "approval", "standing_send", "allowed_callbacks", "public_base_url", "allowed_hosts", "allowed_origins", "network_enabled", "outbound_enabled", "poll_interval_seconds"})


class RuntimeConfigError(ValueError):
    pass


class SecretUnavailable(RuntimeConfigError):
    pass


def _bad(field: str = "configuration"):
    raise RuntimeConfigError(f"Invalid runtime {field}")


def _object(value, allowed: set | frozenset, *, required=(), field="configuration") -> dict:
    if type(value) is not dict or set(value) - allowed or not set(required) <= set(value):
        _bad(field)
    return value


def _integer(value, lo, hi, field):
    if type(value) is not int or not lo <= value <= hi:
        _bad(field)
    return value


def _boolean(value, field):
    if type(value) is not bool:
        _bad(field)
    return value


def _finite(value, lo, hi, field):
    try:
        if type(value) not in (int, float) or not math.isfinite(value) or not lo <= value <= hi:
            _bad(field)
    except OverflowError:
        _bad(field)
    return float(value)


def _text(value, limit, field):
    if not isinstance(value, str) or not 1 <= len(value) <= limit or any(ord(c) < 32 or ord(c) == 127 for c in value):
        _bad(field)
    return value


def _path(value, field) -> Path:
    _text(value, 4096, field)
    path = Path(value)
    # Avoid traversing filesystem aliases while parsing. Physical containment is
    # checked at the later explicit live secret-read boundary.
    if not path.is_absolute() or ".." in path.parts or str(path).startswith(("\\\\", "//")):
        _bad(field)
    return Path(os.path.normpath(str(path)))


def _within(path: Path, root: Path) -> bool:
    return path == root or path.is_relative_to(root)


def _external(path: Path, project: Path, field):
    if _within(path, project) or _within(project, path):
        _bad(field)


def _origin(value, *, https_only=False) -> str:
    try:
        _auth_url(value, issuer=https_only)
        parsed = urlsplit(value)
        if parsed.path not in ("", "/"):
            _bad("origin")
    except (AuthenticationDenied, TypeError, ValueError):
        _bad("origin")
    return value.rstrip("/")


def _callback(value) -> str:
    _text(value, 2048, "callback")
    try:
        if any(ord(c) <= 32 or ord(c) >= 127 for c in value) or any(c in value for c in ('"', "\\", "<", ">")):
            _bad("callback")
        # Shared pure normalization matches EventHub's subscription identity and
        # callback authorizer. This helper does not resolve DNS or open sockets.
        canonical, hostname, _ = _callback_url(value)
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            address = None
        if address is not None and not address.is_global:
            _bad("callback")
    except (EventError, ValueError, TypeError):
        _bad("callback")
    # DNS checks/pinning occur on every real delivery, not during config parsing.
    return canonical


def _host(value):
    _text(value, 300, "allowed host")
    if any(c in value for c in ("*", "/", "\\", "@", "?", "#", " ", '"')):
        _bad("allowed host")
    try:
        parsed = urlsplit("https://" + value)
        if not parsed.hostname or parsed.netloc != value or parsed.path or parsed.query or parsed.fragment:
            _bad("allowed host")
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            _bad("allowed host")
    except ValueError:
        _bad("allowed host")
    return value


def _unique_strings(value, parser, field, max_count=128):
    if type(value) is not list or len(value) > max_count:
        _bad(field)
    result = tuple(parser(item) for item in value)
    if len(set(result)) != len(result):
        _bad(field)
    return result


@dataclass(frozen=True, slots=True)
class SecretRef:
    kind: str
    value: str = field(repr=False)

    @classmethod
    def from_dict(cls, value, *, secrets_dir: Path | None):
        if type(value) is not dict or len(value) != 1:
            _bad("secret reference")
        if "env" in value:
            if not isinstance(value["env"], str) or not _ENV.fullmatch(value["env"]):
                _bad("secret reference")
            return cls("env", value["env"])
        if "local_bot" in value:
            from .local_secrets import LocalSecretsError, validate_bot_name
            try:
                name = validate_bot_name(value["local_bot"])
            except LocalSecretsError:
                _bad("secret reference")
            return cls("local_bot", name)
        if "local_webhook" in value:
            from .local_secrets import LocalSecretsError, validate_webhook_ref
            try:
                reference = validate_webhook_ref(value["local_webhook"])
            except LocalSecretsError:
                _bad("secret reference")
            return cls("local_webhook", reference)
        for kind in ("file", "dpapi_file"):
            if kind in value:
                path = _path(value[kind], "secret reference")
                if secrets_dir is None or path == secrets_dir or not _within(path, secrets_dir):
                    _bad("secret reference")
                return cls(kind, str(path))
        _bad("secret reference")


@dataclass(frozen=True, slots=True)
class RuntimeConfig:
    version: int
    mode: str
    bind_host: str
    bind_port: int
    state_dir: Path | None
    secrets_dir: Path | None = field(repr=False)
    policy: Policy = field(repr=False)
    principals: tuple[str, ...]
    auth_mode: str
    auth: Mapping = field(repr=False)
    bot_token_ref: SecretRef | None = field(repr=False)
    expected_bot_id: int | None
    approved_groups: tuple[dict, ...]
    owner_ids: tuple[int, ...]
    review_scope: Scope | None
    allowed_callbacks: Mapping = field(repr=False)
    public_base_url: str | None
    allowed_hosts: tuple[str, ...]
    allowed_origins: tuple[str, ...]
    network_enabled: bool
    outbound_enabled: bool
    poll_interval_seconds: float
    agent_bindings: Mapping[str, str]
    bot_reference: str | None
    agent_profiles: tuple[Mapping, ...]
    catalog_mode: bool
    bot_configs: Mapping[str, RuntimeConfig] = field(repr=False)
    standing_send: Mapping | None = field(default=None, repr=False)
    routine_routes: Mapping = field(default_factory=lambda: MappingProxyType({}), repr=False)

    @classmethod
    def load(cls, path, *, project_root=None):
        def pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    _bad("duplicate JSON key")
                result[key] = value
            return result
        try:
            with Path(path).open("rb") as stream:
                raw = stream.read(262145)
            if len(raw) > 262144:
                _bad("configuration size")
            data = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                              parse_constant=lambda _: _bad("JSON number"))
        except (OSError, UnicodeError, json.JSONDecodeError, RecursionError):
            raise RuntimeConfigError("Unable to read runtime configuration") from None
        return cls.from_dict(data, project_root=project_root)

    @classmethod
    def from_dict(cls, data, *, project_root=None):
        if type(data) is dict and "agents" in data:
            return cls._from_agents(data, project_root=project_root)
        data = _object(data, _ROOT_FIELDS, required=("version",), field="configuration")
        if type(data["version"]) is not int or data["version"] != 1:
            _bad("version")
        mode = data.get("mode", "disabled")
        if not isinstance(mode, str) or mode not in _MODES:
            _bad("mode")
        project = _path(str(project_root or _DEFAULT_PROJECT), "project root")
        bind = _object(data.get("bind", {}), {"host", "port"}, field="bind")
        bind_host = bind.get("host", "127.0.0.1")
        if bind_host not in ("127.0.0.1", "::1"):
            _bad("bind host")
        bind_port = _integer(bind.get("port", 8765), 1024, 65535, "bind port")
        state_dir = _path(data["state_dir"], "state directory") if "state_dir" in data else None
        secrets_dir = _path(data["secrets_dir"], "secrets directory") if "secrets_dir" in data else None
        if mode != "disabled" and state_dir is None:
            _bad("state directory")
        if mode == "live" and secrets_dir is None:
            _bad("secrets directory")
        for directory, label in ((state_dir, "state directory"), (secrets_dir, "secrets directory")):
            if directory is not None:
                _external(directory, project, label)
        if state_dir is not None and secrets_dir is not None and (_within(state_dir, secrets_dir) or _within(secrets_dir, state_dir)):
            _bad("state/secrets separation")
        policy_data = data.get("policy", {"principals": {}})
        try:
            policy = Policy.from_dict(policy_data)
        except (GatewayDenied, AuthenticationDenied, TypeError):
            _bad("policy")
        principals = tuple(sorted(policy_data["principals"]))
        if len(principals) > 64:
            _bad("principal limit")
        network_enabled = _boolean(data.get("network_enabled", False), "network flag")
        outbound_enabled = _boolean(data.get("outbound_enabled", False), "outbound flag")
        if mode != "live" and network_enabled:
            _bad("fake/disabled network flag")
        if mode == "disabled" and outbound_enabled:
            _bad("disabled outbound flag")
        poll_interval = _finite(data.get("poll_interval_seconds", 1), 0.1, 300, "poll interval")
        public_base = _origin(data["public_base_url"]) if "public_base_url" in data else None
        auth = cls._parse_auth(data.get("auth"), mode, principals, project, state_dir, secrets_dir, public_base)
        auth_mode = auth.get("mode", "disabled")
        bot = _object(data.get("bot", {}), {"reference", "token_ref", "expected_bot_id", "approved_groups"}, field="bot")
        bot_token = SecretRef.from_dict(bot["token_ref"], secrets_dir=secrets_dir) if "token_ref" in bot else None
        if bot_token is not None and bot_token.kind == "local_webhook":
            _bad("bot secret reference")
        has_bindings, has_reference = "agent_bindings" in data, "reference" in bot
        if has_bindings != has_reference or mode == "live" and not has_bindings:
            _bad("agent bot bindings")
        bot_reference = None
        agent_bindings = {}
        if has_reference:
            from .local_secrets import LocalSecretsError, validate_bot_name
            try:
                bot_reference = validate_bot_name(bot["reference"])
            except LocalSecretsError:
                _bad("bot reference")
            raw_bindings = data["agent_bindings"]
            # One adapter per process. Bind every known principal explicitly to
            # that adapter; the policy still independently controls all grants.
            if type(raw_bindings) is not dict or set(raw_bindings) != set(principals):
                _bad("agent bot bindings")
            if any(type(value) is not str or value != bot_reference for value in raw_bindings.values()):
                _bad("agent bot bindings")
            agent_bindings = dict(raw_bindings)
        if bot_token is not None and bot_token.kind == "local_bot" and bot_token.value != bot_reference:
            _bad("bot secret reference")
        bot_id = _integer(bot["expected_bot_id"], 1, 2**52 - 1, "bot ID") if "expected_bot_id" in bot else None
        raw_groups = bot.get("approved_groups", [])
        if type(raw_groups) is not list or len(raw_groups) > 128:
            _bad("approved groups")
        groups, group_types = [], {}
        for item in raw_groups:
            item = _object(item, {"chat_id", "type", "title"}, required=("chat_id", "type", "title"), field="approved group")
            chat_id = _integer(item["chat_id"], -(2**52 - 1), -1, "approved group ID")
            if item["type"] not in ("group", "supergroup") or chat_id in group_types:
                _bad("approved group")
            title = _text(item["title"], 256, "approved group title")
            groups.append({"chat_id": chat_id, "type": item["type"], "title": title})
            group_types[chat_id] = item["type"]
        for grants in policy_data["principals"].values():
            for grant in grants:
                if grant["chat_id"] not in group_types or grant.get("topic_id") is not None and group_types[grant["chat_id"]] != "supergroup":
                    _bad("policy/group scope")
        if mode == "live" and (bot_token is None or bot_id is None or not groups):
            _bad("live bot configuration")
        if mode == "fake" and bot_token is not None:
            _bad("fake bot secret reference")
        approval = _object(data.get("approval", {}), {"owner_ids", "review_scope"}, field="approval")
        owners = approval.get("owner_ids", [])
        if type(owners) is not list or len(owners) > 32:
            _bad("owner IDs")
        owners = tuple(_integer(owner, 1, 2**52 - 1, "owner ID") for owner in owners)
        if len(set(owners)) != len(owners):
            _bad("duplicate owner ID")
        review = None
        if "review_scope" in approval:
            raw_review = _object(approval["review_scope"], {"chat_id", "topic_id"}, required=("chat_id",), field="review scope")
            try:
                review = Scope(raw_review["chat_id"], raw_review.get("topic_id"))
            except GatewayDenied:
                _bad("review scope")
            if review.chat_id not in group_types or review.topic_id is not None and group_types[review.chat_id] != "supergroup":
                _bad("review/group scope")
        standing = cls._parse_standing(data.get("standing_send"), principals=principals,
                                       bot_reference=bot_reference, bot_id=bot_id,
                                       bindings=agent_bindings, policy_data=policy_data)
        if bool(owners) != (review is not None):
            _bad("owner/review configuration")
        if outbound_enabled and not owners:
            if standing is None:
                _bad("owner/review configuration")
            # A standing exception cannot authorize any uncovered send or
            # forwarding grant when there is no separate owner-review channel.
            for principal, grants in policy_data["principals"].items():
                for grant in grants:
                    permissions = grant["permissions"]
                    covered = (principal == standing["principal_id"]
                               and grant["chat_id"] == standing["chat_id"]
                               and (standing.get("all_topics", False)
                                    or not grant.get("all_topics", False)
                                    and grant.get("topic_id") == standing["topic_id"]))
                    if "forward" in permissions or "send" in permissions and not covered:
                        _bad("unreviewed outbound scope")
        raw_callbacks = data.get("allowed_callbacks", {})
        if type(raw_callbacks) is not dict or set(raw_callbacks) - set(principals):
            _bad("callback owner")
        callbacks = {principal: _unique_strings(urls, _callback, "callbacks", 16) for principal, urls in raw_callbacks.items()}
        bind_authority = f"[{bind_host}]:{bind_port}" if ":" in bind_host else f"{bind_host}:{bind_port}"
        default_hosts = [bind_authority]
        if public_base and urlsplit(public_base).netloc not in default_hosts:
            default_hosts.append(urlsplit(public_base).netloc)
        hosts = _unique_strings(data.get("allowed_hosts", default_hosts), _host, "allowed hosts")
        if not hosts:
            _bad("allowed hosts")
        origins = _unique_strings(data.get("allowed_origins", []), _origin, "allowed origins")
        return cls(1, mode, bind_host, bind_port, state_dir, secrets_dir, policy, principals,
                   auth_mode, MappingProxyType(auth), bot_token, bot_id, tuple(groups), owners,
                   review, MappingProxyType(callbacks), public_base, hosts, origins,
                   network_enabled, outbound_enabled, poll_interval,
                   MappingProxyType(agent_bindings), bot_reference, (), False, MappingProxyType({}), standing)

    @staticmethod
    def _parse_standing(raw, *, principals, bot_reference, bot_id, bindings, policy_data):
        from .agent_config import AgentConfigError, _standing_send
        try:
            rule = _standing_send(raw)
        except AgentConfigError:
            _bad("standing send configuration")
        if rule is None:
            return None
        if (len(principals) != 1 or bot_reference is None or bot_id is None
                or bindings.get(principals[0]) != bot_reference):
            _bad("standing send identity")
        principal = principals[0]
        exact = any("send" in grant["permissions"]
                    and grant.get("all_topics", False) == rule.get("all_topics", False)
                    and grant["chat_id"] == rule["chat_id"]
                    and (rule.get("all_topics", False) or grant.get("topic_id") == rule["topic_id"])
                    for grant in policy_data["principals"][principal])
        if not exact:
            _bad("standing send exact grant")
        return MappingProxyType({**rule, "principal_id": principal,
                                 "bot_reference": bot_reference, "expected_bot_id": bot_id})

    @classmethod
    def _from_agents(cls, data, *, project_root=None):
        from .agent_config import AgentConfigError, compile_agent_config
        try:
            common, raw_children, profiles, bindings = compile_agent_config(data)
        except AgentConfigError:
            _bad("agent profiles")
        mode = data.get("mode", "disabled")
        if not isinstance(mode, str) or mode not in _MODES:
            _bad("mode")
        if mode != "disabled" and not raw_children:
            _bad("active agents")
        network = _boolean(data.get("network_enabled", False), "network flag")
        outbound = _boolean(data.get("outbound_enabled", False), "outbound flag")
        if mode != "live" and network or mode == "disabled" and outbound:
            _bad("catalog network/outbound flags")
        # Validate root paths, scopes, callbacks, host/origin and common bounds
        # through the existing inert parser. Never create a global bot adapter.
        base_data = dict(common)
        base_data.pop("auth", None)
        base_data.pop("approval", None)
        base_data.update(mode="disabled", network_enabled=False, outbound_enabled=False)
        base = cls.from_dict(base_data, project_root=project_root)
        project = _path(str(project_root or _DEFAULT_PROJECT), "project root")
        auth = cls._parse_auth(data.get("auth"), mode, base.principals, project,
                               base.state_dir, base.secrets_dir, base.public_base_url)
        children, routine_routes = {}, {}
        for reference, raw_child in raw_children.items():
            child_data = dict(raw_child)
            raw_routes = child_data.pop("routine_routes", {})
            child = cls.from_dict(child_data, project_root=project_root)
            parsed_routes = cls._parse_routine_routes(raw_routes, child=child)
            children[reference] = replace(child, routine_routes=parsed_routes)
            routine_routes.update(parsed_routes)
        return replace(base, mode=mode, auth_mode=auth.get("mode", "disabled"),
                       auth=MappingProxyType(auth), network_enabled=network,
                       outbound_enabled=outbound, agent_bindings=MappingProxyType(bindings),
                       agent_profiles=profiles, catalog_mode=True,
                       bot_configs=MappingProxyType(children),
                       routine_routes=MappingProxyType(routine_routes))

    @staticmethod
    def _parse_routine_routes(raw, *, child):
        # Only catalog compilation calls this: a standalone low-level config
        # cannot skip the enabled integration / route-reference checks.
        result = {}
        for route_id, route in raw.items():
            if (route["principal_id"] not in child.principals
                    or route["bot_reference"] != child.bot_reference
                    or child.agent_bindings.get(route["principal_id"]) != child.bot_reference):
                _bad("routine route owner")
            bearer = SecretRef.from_dict(route["bearer_ref"], secrets_dir=child.secrets_dir)
            # local_bot and the existing DPAPI store both contain Telegram
            # token syntax, which cannot be used as a Grok bearer.
            if bearer.kind not in {"env", "file", "local_webhook"}:
                _bad("routine bearer reference")
            if bearer.kind == "local_webhook" and bearer.value != route_id:
                _bad("routine bearer reference")
            result[route_id] = MappingProxyType({
                "route_id": route_id, "principal_id": route["principal_id"],
                "bot_reference": child.bot_reference, "url": _callback(route["url"]),
                "bearer_ref": bearer, "addressing": route["addressing"],
            })
        return MappingProxyType(result)

    @staticmethod
    def _parse_auth(raw, mode, principals, project, state_dir, secrets_dir, public_base):
        if raw is None:
            if mode != "disabled":
                _bad("authentication")
            return {"mode": "disabled"}
        if type(raw) is not dict or "mode" not in raw:
            _bad("authentication")
        auth_mode = raw["mode"]
        if auth_mode == "fake":
            _object(raw, {"mode", "credentials"}, required=("credentials",), field="fake authentication")
            if mode != "fake":
                _bad("fake authentication mode")
            try:
                FakeAuthenticator(raw["credentials"])
            except (AuthenticationDenied, TypeError):
                _bad("fake authentication")
            if set(raw["credentials"].values()) - set(principals):
                _bad("authentication principal")
            return {"mode": "fake", "credentials": MappingProxyType(dict(raw["credentials"]))}
        if auth_mode == "static":
            _object(raw, {"mode", "token_digests"}, required=("token_digests",), field="static authentication")
            try:
                StaticBearerAuthenticator(raw["token_digests"])
            except (AuthenticationDenied, TypeError):
                _bad("static authentication")
            if set(raw["token_digests"].values()) - set(principals):
                _bad("authentication principal")
            return {"mode": "static", "token_digests": MappingProxyType(dict(raw["token_digests"]))}
        if auth_mode != "oauth":
            _bad("authentication mode")
        _object(raw, {"mode", "issuer", "audience", "jwks_file", "subjects", "required_scope", "leeway_seconds", "max_token_age_seconds", "max_token_lifetime_seconds"}, required=("issuer", "audience", "jwks_file", "subjects"), field="OAuth authentication")
        try:
            issuer = _auth_url(raw["issuer"], issuer=True)
            audience = _auth_url(raw["audience"])
        except AuthenticationDenied:
            _bad("OAuth URLs")
        if public_base is None or audience != public_base + "/mcp":
            _bad("OAuth resource URL")
        if mode == "live" and urlsplit(public_base).scheme != "https":
            _bad("live OAuth HTTPS")
        jwks_file = _path(raw["jwks_file"], "public JWKS file")
        _external(jwks_file, project, "public JWKS file")
        if any(directory is not None and _within(jwks_file, directory) for directory in (state_dir, secrets_dir)):
            _bad("public JWKS separation")
        subjects = raw["subjects"]
        if type(subjects) is not list or not 1 <= len(subjects) <= 128:
            _bad("OAuth subject mappings")
        mappings = {}
        for entry in subjects:
            entry = _object(entry, {"issuer", "sub", "principal"}, required=("issuer", "sub", "principal"), field="OAuth subject mapping")
            subject = _text(entry["sub"], 256, "OAuth subject")
            if entry["issuer"] != issuer or entry["principal"] not in principals or (issuer, subject) in mappings:
                _bad("OAuth subject mapping")
            mappings[(issuer, subject)] = entry["principal"]
        required_scope = raw.get("required_scope", "mcp:gateway")
        if not isinstance(required_scope, str) or not _SCOPE.fullmatch(required_scope):
            _bad("OAuth scope")
        return {"mode": "oauth", "issuer": issuer, "audience": audience, "jwks_file": jwks_file,
                "subject_principals": MappingProxyType(mappings), "required_scope": required_scope,
                "leeway_seconds": _finite(raw.get("leeway_seconds", 0), 0, 300, "OAuth leeway"),
                "max_token_age_seconds": _finite(raw.get("max_token_age_seconds", 3600), 1, 86400, "OAuth max age"),
                "max_token_lifetime_seconds": _finite(raw.get("max_token_lifetime_seconds", 3600), 1, 86400, "OAuth max lifetime")}


def load_secret(ref: SecretRef, *, secrets_dir: Path | None = None, live_mode: bool = False,
                project_root: Path | None = None, environ: Mapping[str, str] | None = None,
                expected_url: str | None = None) -> str:
    """Explicit runtime-only bounded secret read. Never call from check/status.

    Test code passes disposable synthetic files/environment mappings. No path,
    variable name, value or underlying OS exception appears in error messages.
    """
    if live_mode is not True:
        raise SecretUnavailable("Secret loading requires explicit live runtime")
    try:
        if type(ref) is not SecretRef:
            raise ValueError()
        if ref.kind == "env":
            if not _ENV.fullmatch(ref.value):
                raise ValueError()
            value = (os.environ if environ is None else environ).get(ref.value)
        elif ref.kind == "local_bot":
            from . import local_secrets
            local_secrets.validate_bot_name(ref.value)
            # User-approved exception for exactly this project file. Generic
            # file/dpapi_file references still cannot point inside the checkout.
            project = _path(str(project_root or _DEFAULT_PROJECT), "project root").resolve(strict=True)
            source = project / "secrets.local.json"
            if source.resolve(strict=True) != source:
                raise ValueError()
            value = local_secrets.load_bot_token(ref.value, path=source)
        elif ref.kind == "local_webhook":
            from . import local_secrets
            local_secrets.validate_webhook_ref(ref.value)
            # URL binding is mandatory before reading this separate credential.
            canonical_url = _callback(expected_url)
            project = _path(str(project_root or _DEFAULT_PROJECT), "project root").resolve(strict=True)
            source = project / "secrets.local.json"
            if source.resolve(strict=True) != source:
                raise ValueError()
            webhook = local_secrets.load_webhook(ref.value, path=source)
            if webhook.url != canonical_url:
                raise ValueError()
            # Validated full header value: preserve its scheme and spaces.
            return webhook.authorization_header
        elif ref.kind in ("file", "dpapi_file"):
            if secrets_dir is None:
                raise ValueError()
            source = _path(ref.value, "secret reference")
            base = _path(str(secrets_dir), "secrets directory")
            if source == base or not _within(source, base):
                raise ValueError()
            physical_base, physical_source = base.resolve(strict=True), source.resolve(strict=True)
            project = Path(project_root or _DEFAULT_PROJECT).resolve(strict=True)
            if not _within(physical_source, physical_base) or physical_source == physical_base or _within(physical_source, project) or _within(physical_base, project) or _within(project, physical_base):
                raise ValueError()
            if ref.kind == "dpapi_file":
                # Import and decrypt only after the explicit live gate and both
                # lexical/physical containment checks. There is no plaintext
                # fallback if DPAPI fails or the file is not a protected blob.
                from . import dpapi_store
                value = dpapi_store.load_token(physical_source)
            else:
                with physical_source.open("rb") as stream:
                    data = stream.read(8193)
                if len(data) > 8192:
                    raise ValueError()
                value = data.decode("utf-8")
        else:
            raise ValueError()
        if not isinstance(value, str):
            raise ValueError()
        value = value.rstrip("\r\n")
        if not 1 <= len(value) <= 8192 or any(ord(c) < 33 or ord(c) > 126 for c in value):
            raise ValueError()
        return value
    except (OSError, ValueError, TypeError, UnicodeError, RuntimeConfigError):
        raise SecretUnavailable("Secret is unavailable") from None
