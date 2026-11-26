"""Principal/chat/topic authorization with explicit whole-group grants only."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from .auth import VerifiedPrincipal, AuthenticationDenied, _principal_id

PERMISSIONS = frozenset({"history", "events", "draft", "send", "forward"})
TOOL_PERMISSIONS = MappingProxyType({
    "ping": None, "status": None, "list_allowed_scopes": None,
    "read_history": "history", "search_history": "history", "next_events": "events", "ack_event": "events",
    "create_draft": "draft", "send_draft": "send", "create_forward_draft": "forward",
    "get_draft_status": "send",
})


class GatewayDenied(ValueError):
    """Denial message deliberately excludes IDs, arguments and credentials."""


@dataclass(frozen=True, slots=True, order=False)
class Scope:
    chat_id: int
    topic_id: int | None = None
    all_topics: bool = False

    def __post_init__(self):
        if type(self.chat_id) is not int or not -(2**52 - 1) <= self.chat_id <= 2**52 - 1 or self.chat_id == 0:
            raise GatewayDenied("Invalid scope")
        if self.topic_id is not None and (type(self.topic_id) is not int or not 1 <= self.topic_id <= 2**31 - 1):
            raise GatewayDenied("Invalid scope")
        if type(self.all_topics) is not bool or self.all_topics and (self.chat_id >= 0 or self.topic_id is not None):
            raise GatewayDenied("Invalid scope")


class Policy:
    def __init__(self, grants: Mapping[str, Mapping[Scope, frozenset[str]]]):
        self._grants = MappingProxyType({principal: MappingProxyType(dict(scopes)) for principal, scopes in grants.items()})

    @classmethod
    def from_dict(cls, data: dict) -> Policy:
        if type(data) is not dict or set(data) != {"principals"} or type(data["principals"]) is not dict:
            raise GatewayDenied("Invalid policy configuration")
        result = {}
        for principal_id, grants in data["principals"].items():
            try:
                _principal_id(principal_id)
            except AuthenticationDenied:
                raise GatewayDenied("Invalid policy configuration") from None
            if type(grants) is not list:
                raise GatewayDenied("Invalid policy configuration")
            scopes = {}
            for grant in grants:
                if type(grant) is not dict or not {"chat_id", "permissions"} <= set(grant) or set(grant) - {"chat_id", "topic_id", "all_topics", "permissions"}:
                    raise GatewayDenied("Invalid policy configuration")
                scope = Scope(grant["chat_id"], grant.get("topic_id"), grant.get("all_topics", False))
                permissions = grant["permissions"]
                if type(permissions) is not list or any(type(p) is not str or p not in PERMISSIONS for p in permissions):
                    raise GatewayDenied("Invalid policy configuration")
                if len(permissions) != len(set(permissions)) or scope in scopes:
                    raise GatewayDenied("Duplicate policy grant")
                scopes[scope] = frozenset(permissions)
            result[principal_id] = scopes
        return cls(result)

    def _principal(self, principal: VerifiedPrincipal) -> str:
        if type(principal) is not VerifiedPrincipal or not principal.authenticated or principal.id not in self._grants:
            raise GatewayDenied("Access denied")
        return principal.id

    def require(self, principal: VerifiedPrincipal, permission: str, scope: Scope) -> None:
        principal_id = self._principal(principal)
        if type(scope) is not Scope or type(permission) is not str or permission not in PERMISSIONS:
            raise GatewayDenied("Access denied")
        grants = self._grants[principal_id]
        if permission in grants.get(scope, frozenset()):
            return
        # A concrete message or destination retains its actual topic. Only an
        # explicit grant for this whole group covers arbitrary/new topics;
        # finite topic grants never authorize a whole-group request.
        if not scope.all_topics and scope.chat_id < 0:
            whole_group = Scope(scope.chat_id, all_topics=True)
            if permission in grants.get(whole_group, frozenset()):
                return
        raise GatewayDenied("Access denied")

    def allowed_scopes(self, principal: VerifiedPrincipal, permission: str) -> tuple[Scope, ...]:
        principal_id = self._principal(principal)
        if type(permission) is not str or permission not in PERMISSIONS:
            raise GatewayDenied("Access denied")
        scopes = (scope for scope, permissions in self._grants[principal_id].items() if permission in permissions)
        return tuple(sorted(scopes, key=lambda s: (s.chat_id, -1 if s.topic_id is None else s.topic_id, s.all_topics)))

    def tools_for(self, principal: VerifiedPrincipal) -> list[str]:
        principal_id = self._principal(principal)
        granted = frozenset(permission for permissions in self._grants[principal_id].values() for permission in permissions)
        tools = [tool for tool, permission in TOOL_PERMISSIONS.items() if permission is None or permission in granted]
        # Metadata requires both rights on an overlapping scope, not merely
        # unrelated draft and send grants somewhere in the principal's catalog.
        if "get_draft_status" in tools and not any(
                draft.chat_id == send.chat_id and (draft.all_topics or send.all_topics or draft.topic_id == send.topic_id)
                for draft in self.allowed_scopes(principal, "draft")
                for send in self.allowed_scopes(principal, "send")):
            tools.remove("get_draft_status")
        return tools
