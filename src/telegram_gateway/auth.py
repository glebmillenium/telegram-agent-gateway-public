"""Trusted identity boundaries, with synthetic credentials for the offline pilot.

These objects are server-side capabilities, not signatures against hostile Python
code in the same process. Only the authenticated transport and trusted persistence
may construct them. Never expose the restoration/message factories as MCP tools.
There is deliberately no production credential loader or Telegram login here.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
import copy
import hmac
import math
import re
import time
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from .policy import Scope

_PRINCIPAL_PROOF = object()
_MESSAGE_PROOF = object()
_DECISION_PROOF = object()
_ID = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}\Z")
_DRAFT_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class AuthenticationDenied(ValueError):
    """Sanitized authentication/approval rejection."""


def _principal_id(value: Any) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise AuthenticationDenied("Invalid principal")
    return value


@dataclass(frozen=True, slots=True)
class VerifiedPrincipal:
    id: str
    _proof: object = field(default=None, repr=False, compare=False)

    @property
    def authenticated(self) -> bool:
        return self._proof is _PRINCIPAL_PROOF and isinstance(self.id, str) and bool(_ID.fullmatch(self.id))


class PrincipalAuthority:
    """Internal authority for a previously authenticated persisted owner ID.

    The caller must obtain IDs from its own protected subscription store, never
    request arguments, and recheck the current policy after restoration.
    """
    def restore(self, principal_id: str) -> VerifiedPrincipal:
        return VerifiedPrincipal(_principal_id(principal_id), _PRINCIPAL_PROOF)


class FakeAuthenticator:
    """Fixed synthetic fixture credentials only; NOT production authentication.

    Instances must only be wired into the explicitly fake transport. No fallback
    to request agent_id, principal, owner, query parameters or anonymous identity.
    """
    def __init__(self, credentials: Mapping[str, str]):
        if not isinstance(credentials, Mapping) or not credentials:
            raise AuthenticationDenied("Fake credential map is required")
        checked: dict[str, str] = {}
        for credential, principal_id in credentials.items():
            if not isinstance(credential, str) or not 1 <= len(credential) <= 256 or any(c.isspace() for c in credential):
                raise AuthenticationDenied("Invalid fake credential configuration")
            checked[credential] = _principal_id(principal_id)
        self._credentials = MappingProxyType(checked)

    def authenticate(self, authorization: str | None) -> VerifiedPrincipal:
        if not isinstance(authorization, str) or not authorization.startswith("Bearer "):
            raise AuthenticationDenied("Authentication required")
        supplied = authorization[7:]
        if not supplied or len(supplied) > 256 or any(c.isspace() for c in supplied):
            raise AuthenticationDenied("Authentication required")
        match = None
        for credential, principal_id in self._credentials.items():
            if hmac.compare_digest(supplied.encode("utf-8"), credential.encode("utf-8")):
                match = principal_id
        if match is None:
            raise AuthenticationDenied("Authentication required")
        return PrincipalAuthority().restore(match)


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, (str, int, float, bool, type(None))):
        return value
    raise AuthenticationDenied("Invalid message envelope")


@dataclass(frozen=True, slots=True)
class TrustedBotMessage:
    envelope: Mapping[str, Any]
    _proof: object = field(default=None, repr=False, compare=False)


def trusted_bot_message_from_transport(envelope: Mapping[str, Any]) -> TrustedBotMessage:
    """Call ONLY after Bot API transport provenance is verified (or in fake tests).

    This is an internal capability boundary, not proof that arbitrary JSON came
    from Telegram. A model-facing request must never reach this factory.
    """
    if not isinstance(envelope, Mapping):
        raise AuthenticationDenied("Invalid message envelope")
    return TrustedBotMessage(_freeze(copy.deepcopy(dict(envelope))), _MESSAGE_PROOF)


@dataclass(frozen=True, slots=True)
class ApprovalChallenge:
    principal_id: str
    draft_id: str
    digest: str
    chat_id: int
    topic_id: int | None
    challenge_message_id: int
    expires_at: float


@dataclass(frozen=True, slots=True)
class OwnerDecision:
    principal_id: str
    draft_id: str
    digest: str
    approved: bool
    owner_id: int
    source_message_id: int
    challenge_message_id: int
    scope: Scope
    _proof: object = field(default=None, repr=False, compare=False)

    @property
    def verified(self) -> bool:
        return self._proof is _DECISION_PROOF


class OwnerApprovalVerifier:
    """Owner evidence from a fresh direct human reply to a recorded challenge.

    Service must additionally match the immutable draft digest, atomically
    consume its approval, enforce expiry/permissions again and prevent reuse.
    """
    _FORBIDDEN = frozenset({
        "sender_chat", "forward_origin", "forward_from", "forward_from_chat",
        "forward_from_message_id", "forward_signature", "forward_sender_name",
        "forward_date", "is_automatic_forward", "via_bot", "sender_business_bot",
        "business_connection_id", "via_business_connection", "via_business_bot",
        "is_from_offline", "guest_bot", "guest_query_id", "guest_bot_caller_user",
        "guest_bot_caller_chat", "sender_guest_bot", "via_guest_bot",
        "external_reply", "paid_star_count", "is_paid_post",
    })

    def __init__(self, owner_ids, approval_scopes, *, clock: Callable[[], float] = time.time):
        from .policy import Scope
        if not isinstance(owner_ids, (list, tuple, set, frozenset)) or not owner_ids:
            raise AuthenticationDenied("Owner allowlist is required")
        if any(type(owner) is not int or not 1 <= owner <= 2**52 - 1 for owner in owner_ids):
            raise AuthenticationDenied("Invalid owner allowlist")
        scopes = tuple(approval_scopes)
        if not scopes or any(type(scope) is not Scope or scope.all_topics for scope in scopes):
            raise AuthenticationDenied("Approval scope allowlist is required")
        self._owner_ids = frozenset(owner_ids)
        self._approval_scopes = frozenset(scopes)
        self._clock = clock

    def verify(self, message: TrustedBotMessage, challenge: ApprovalChallenge) -> OwnerDecision:
        from .policy import Scope
        deny = AuthenticationDenied("Owner approval rejected")
        if type(message) is not TrustedBotMessage or message._proof is not _MESSAGE_PROOF:
            raise deny
        if type(challenge) is not ApprovalChallenge:
            raise deny
        try:
            _principal_id(challenge.principal_id)
            if not isinstance(challenge.draft_id, str) or not _DRAFT_ID.fullmatch(challenge.draft_id):
                raise deny
            if not isinstance(challenge.digest, str) or not _DIGEST.fullmatch(challenge.digest):
                raise deny
            if type(challenge.expires_at) not in (int, float) or not math.isfinite(challenge.expires_at) or not self._clock() < challenge.expires_at:
                raise deny
            if type(challenge.challenge_message_id) is not int or not 1 <= challenge.challenge_message_id <= 2**31 - 1:
                raise deny
            scope = Scope(challenge.chat_id, challenge.topic_id)
            if scope not in self._approval_scopes:
                raise deny
            body = message.envelope
            if any(key in body for key in self._FORBIDDEN):
                raise deny
            sender, chat, reply = body.get("from"), body.get("chat"), body.get("reply_to_message")
            if not isinstance(sender, Mapping) or not isinstance(chat, Mapping) or not isinstance(reply, Mapping):
                raise deny
            owner = sender.get("id")
            if type(owner) is not int or owner not in self._owner_ids or sender.get("is_bot") is not False:
                raise deny
            if chat.get("type") not in ("group", "supergroup") or type(chat.get("id")) is not int:
                raise deny
            if Scope(chat["id"], body.get("message_thread_id")) != scope:
                raise deny
            if type(reply.get("message_id")) is not int or reply["message_id"] != challenge.challenge_message_id:
                raise deny
            source_id = body.get("message_id")
            if type(source_id) is not int or not 1 <= source_id <= 2**31 - 1 or source_id == challenge.challenge_message_id:
                raise deny
            expected_suffix = f" {challenge.draft_id} {challenge.digest}"
            if body.get("text") == "approve" + expected_suffix:
                approved = True
            elif body.get("text") == "reject" + expected_suffix:
                approved = False
            else:
                raise deny
        except (KeyError, TypeError, ValueError):
            raise deny from None
        return OwnerDecision(challenge.principal_id, challenge.draft_id, challenge.digest,
                             approved, owner, source_id, challenge.challenge_message_id,
                             scope, _DECISION_PROOF)
