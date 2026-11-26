"""Pure, exact standing permission for an explicitly approved technical exchange.

No default grant, I/O, token loading, approval mutation or text classifier lives
here. The caller must load an immutable persisted draft and independently apply
current grants, expiry, conversation/rate limits and the durable circuit breaker.
The purpose label records the operator's scope; it cannot prove text semantics.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import math
import re

from .auth import AuthenticationDenied, VerifiedPrincipal, _principal_id
from .local_secrets import LocalSecretsError, validate_bot_name
from .policy import GatewayDenied, Scope

PURPOSE = "gateway_technical_test"
_PROOF = object()
_DRAFT_ID = re.compile(r"[0-9a-f]{32}\Z")
_BODY_FIELDS = frozenset({"draft_id", "principal_id", "bot_reference", "operation", "chat_id", "topic_id",
                          "text", "attachments", "source", "task_id", "reply_to_message_id",
                          "chain_depth", "started", "expires_at"})


class StandingDenied(GatewayDenied):
    """Sanitized standing-policy rejection."""


def _deny():
    raise StandingDenied("Standing send is not permitted")


def _canonical(value):
    # Must match service.canonical exactly, including Unicode and float spelling.
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


@dataclass(frozen=True, slots=True)
class StandingAuthorization:
    policy_fingerprint: str
    payload_digest: str
    _proof: object = field(default=None, repr=False, compare=False)

    @property
    def authorized(self):
        return self._proof is _PROOF


@dataclass(frozen=True, slots=True)
class StandingSendPolicy:
    purpose: str
    principal_id: str
    bot_reference: str
    expected_bot_id: int
    chat_id: int
    topic_id: int | None = None
    max_text_chars: int = 4000
    all_topics: bool = False

    def __post_init__(self):
        try:
            if self.purpose != PURPOSE or type(self.purpose) is not str:
                _deny()
            _principal_id(self.principal_id)
            reference = validate_bot_name(self.bot_reference)
            if (type(self.expected_bot_id) is not int or not 1 <= self.expected_bot_id <= 2**52 - 1
                    or type(self.chat_id) is not int or not -(2**52 - 1) <= self.chat_id < 0
                    or type(self.max_text_chars) is not int or not 1 <= self.max_text_chars <= 4000
                    or type(self.all_topics) is not bool or self.all_topics and self.topic_id is not None):
                _deny()
            Scope(self.chat_id, self.topic_id)
            object.__setattr__(self, "bot_reference", reference)
        except (AuthenticationDenied, LocalSecretsError, GatewayDenied, TypeError, ValueError):
            _deny()

    @property
    def fingerprint(self):
        definition = {"schema": "standing_send_v1", "purpose": self.purpose,
                      "principal_id": self.principal_id, "bot_reference": self.bot_reference,
                      "expected_bot_id": self.expected_bot_id, "chat_id": self.chat_id,
                      "topic_id": self.topic_id, "max_text_chars": self.max_text_chars,
                      "all_topics": self.all_topics}
        return hashlib.sha256(_canonical(definition).encode("utf-8")).hexdigest()

    @property
    def policy_fingerprint(self):
        return self.fingerprint

    def authorize(self, principal, *, bot_reference, bot_id, body):
        """Validate server identity and the complete persisted draft snapshot.

        Returned hashes bind the standing policy to every immutable draft field.
        This is an authorization decision only; it never marks a draft approved.
        """
        if (type(principal) is not VerifiedPrincipal or not principal.authenticated
                or principal.id != self.principal_id or type(bot_reference) is not str
                or bot_reference != self.bot_reference or type(bot_id) is not int
                or bot_id != self.expected_bot_id or type(body) is not dict):
            _deny()
        try:
            canonical = _canonical(body)
            if len(canonical.encode("utf-8")) > 16384:
                _deny()
            snapshot = json.loads(canonical)
            if set(snapshot) != _BODY_FIELDS:
                _deny()
            if (snapshot["principal_id"] != principal.id or snapshot["bot_reference"] != self.bot_reference
                    or snapshot["operation"] != "send" or snapshot["source"] is not None
                    or type(snapshot["attachments"]) is not list or snapshot["attachments"]):
                _deny()
            scope = Scope(snapshot["chat_id"], snapshot["topic_id"])
            if scope.chat_id != self.chat_id or not self.all_topics and scope.topic_id != self.topic_id:
                _deny()
            text = snapshot["text"]
            if (type(text) is not str or not 1 <= len(text) <= self.max_text_chars
                    or any(ord(char) < 32 and char not in "\n\r\t" or ord(char) == 127 for char in text)):
                _deny()
            if type(snapshot["draft_id"]) is not str or not _DRAFT_ID.fullmatch(snapshot["draft_id"]):
                _deny()
            task = snapshot["task_id"]
            if type(task) is not str or not 1 <= len(task) <= 512 or any(ord(char) < 32 or ord(char) == 127 for char in task):
                _deny()
            reply, depth = snapshot["reply_to_message_id"], snapshot["chain_depth"]
            if reply is not None and (type(reply) is not int or not 1 <= reply <= 2**31 - 1):
                _deny()
            if type(depth) is not int or not 0 <= depth <= 2**31 - 1:
                _deny()
            started, expires = snapshot["started"], snapshot["expires_at"]
            if (type(started) not in (int, float) or type(expires) not in (int, float)
                    or not math.isfinite(started) or not math.isfinite(expires) or started < 0 or expires <= started):
                _deny()
            return StandingAuthorization(self.fingerprint,
                hashlib.sha256(canonical.encode("utf-8")).hexdigest(), _PROOF)
        except (GatewayDenied, KeyError, TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
            _deny()
