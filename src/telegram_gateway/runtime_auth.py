"""Offline-verifiable runtime authentication; no token issuing or discovery.

OAuth signing keys and subject mappings are explicitly trusted server config.
Only public JWKS material is accepted. Caller supplies Authorization headers,
never an agent ID or roles to select a principal. No network/filesystem access.
Static bearer mode is separate and intended only for approved local agents.
"""
from __future__ import annotations

import base64
from collections.abc import Mapping
import hashlib
import hmac
import json
import math
import re
import time
from types import MappingProxyType
from urllib.parse import urlsplit

import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from .auth import AuthenticationDenied, PrincipalAuthority, VerifiedPrincipal, _principal_id

_CONFIG_ERROR = "Invalid authentication configuration"
_DENIED = "Authentication required"
_SCOPE = re.compile(r"[A-Za-z][A-Za-z0-9:._/-]{0,127}\Z")
_B64URL = re.compile(r"[A-Za-z0-9_-]+\Z")
_BEARER = re.compile(r"[A-Za-z0-9._~+/-]+=*\Z")
_DIGEST = re.compile(r"[0-9a-fA-F]{64}\Z")
_KID = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")


def _scope(value: str) -> str:
    if not isinstance(value, str) or not _SCOPE.fullmatch(value):
        raise AuthenticationDenied(_CONFIG_ERROR)
    return value


def _url(value: str, *, issuer: bool = False) -> str:
    try:
        if not isinstance(value, str) or not 1 <= len(value) <= 2048 or any(ord(c) <= 32 or ord(c) >= 127 for c in value):
            raise ValueError()
        parsed = urlsplit(value)
        if not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
            raise ValueError()
        if parsed.scheme != "https":
            if issuer or parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
                raise ValueError()
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError()
        # Quotes/backslashes must never enter HTTP challenge header values.
        if any(c in value for c in ('"', "\\", "<", ">")):
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise AuthenticationDenied(_CONFIG_ERROR) from None
    return value


def _number(value, *, minimum=0, maximum=2**53 - 1) -> float:
    if type(value) not in (int, float) or not math.isfinite(value) or not minimum <= value <= maximum:
        raise AuthenticationDenied(_DENIED)
    return float(value)


def _bearer(header: str | None, *, minimum: int = 1, maximum: int = 16384) -> str:
    if not isinstance(header, str) or not header.startswith("Bearer "):
        raise AuthenticationDenied(_DENIED)
    token = header[7:]
    if not minimum <= len(token) <= maximum or not _BEARER.fullmatch(token):
        raise AuthenticationDenied(_DENIED)
    return token


def _no_duplicate_members(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("Duplicate JSON member")
        result[name] = value
    return result


def _jwt_object(segment: str) -> dict:
    if not _B64URL.fullmatch(segment):
        raise AuthenticationDenied(_DENIED)
    try:
        decoded = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
        obj = json.loads(decoded.decode("utf-8"), object_pairs_hook=_no_duplicate_members,
                         parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if type(obj) is not dict:
            raise ValueError()
        return obj
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise AuthenticationDenied(_DENIED) from None


class OAuthAuthenticator:
    """RS256 resource-server verifier with pinned local JWKS, no HTTP fetches.

    JWKS rotation/revocation is an explicit configuration reload. Scope is an
    OAuth entry gate; chat/topic/action permissions remain enforced by Policy.
    Bearer tokens are reusable during validity; this is not sender-constrained
    DPoP authentication and does not claim one-time JWT semantics.
    """
    def __init__(self, *, issuer: str, audience: str, jwks: dict,
                 subject_principals: Mapping[tuple[str, str], str],
                 required_scope: str = "mcp:gateway", clock=time.time,
                 leeway_seconds: float = 0, max_token_age_seconds: float = 3600,
                 max_token_lifetime_seconds: float = 3600):
        self.issuer = _url(issuer, issuer=True)
        self.audience = _url(audience)
        self.required_scope = _scope(required_scope)
        if not callable(clock):
            raise AuthenticationDenied(_CONFIG_ERROR)
        self._clock = clock
        try:
            self._leeway = _number(leeway_seconds, maximum=300)
            self._max_age = _number(max_token_age_seconds, minimum=1, maximum=86400)
            self._max_lifetime = _number(max_token_lifetime_seconds, minimum=1, maximum=86400)
        except AuthenticationDenied:
            raise AuthenticationDenied(_CONFIG_ERROR) from None
        if not isinstance(subject_principals, Mapping) or not subject_principals:
            raise AuthenticationDenied(_CONFIG_ERROR)
        subjects = {}
        for identity, principal_id in subject_principals.items():
            if type(identity) is not tuple or len(identity) != 2 or identity[0] != issuer or not isinstance(identity[1], str) or not 1 <= len(identity[1]) <= 256 or any(ord(c) < 32 for c in identity[1]):
                raise AuthenticationDenied(_CONFIG_ERROR)
            subjects[identity] = _principal_id(principal_id)
        self._subjects = MappingProxyType(subjects)
        self._keys = MappingProxyType(self._load_keys(jwks))

    @staticmethod
    def _load_keys(jwks: dict) -> dict:
        if type(jwks) is not dict or set(jwks) != {"keys"} or type(jwks["keys"]) is not list or not 1 <= len(jwks["keys"]) <= 16:
            raise AuthenticationDenied(_CONFIG_ERROR)
        result = {}
        for key in jwks["keys"]:
            try:
                if type(key) is not dict or not {"kty", "kid", "n", "e"} <= set(key) or set(key) - {"kty", "kid", "n", "e", "alg", "use", "key_ops"}:
                    raise ValueError()
                if key["kty"] != "RSA" or key.get("alg", "RS256") != "RS256" or key.get("use", "sig") != "sig":
                    raise ValueError()
                if "key_ops" in key and key["key_ops"] != ["verify"]:
                    raise ValueError()
                kid = key["kid"]
                if not isinstance(kid, str) or not _KID.fullmatch(kid) or kid in result:
                    raise ValueError()
                if any(not isinstance(key[k], str) or not _B64URL.fullmatch(key[k]) for k in ("n", "e")):
                    raise ValueError()
                if len(key["n"]) > 1400 or len(key["e"]) > 12:
                    raise ValueError()
                public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
                if not isinstance(public_key, RSAPublicKey) or not 2048 <= public_key.key_size <= 8192:
                    raise ValueError()
                exponent = public_key.public_numbers().e
                if exponent < 3 or exponent % 2 == 0 or exponent > 2**32 - 1:
                    raise ValueError()
                result[kid] = public_key
            except (ValueError, TypeError, KeyError, jwt.PyJWTError):
                raise AuthenticationDenied(_CONFIG_ERROR) from None
        return result

    def authenticate(self, authorization: str | None) -> VerifiedPrincipal:
        try:
            token = _bearer(authorization)
            parts = token.split(".")
            if len(parts) != 3 or not parts[2]:
                raise AuthenticationDenied(_DENIED)
            header, claims = _jwt_object(parts[0]), _jwt_object(parts[1])
            if set(header) - {"alg", "kid", "typ"} or header.get("alg") != "RS256":
                raise AuthenticationDenied(_DENIED)
            if "typ" in header and header["typ"] not in ("JWT", "at+jwt"):
                raise AuthenticationDenied(_DENIED)
            kid = header.get("kid")
            if not isinstance(kid, str) or kid not in self._keys:
                raise AuthenticationDenied(_DENIED)
            verified = jwt.decode(token, key=self._keys[kid], algorithms=["RS256"], options={
                "verify_signature": True, "verify_exp": False, "verify_nbf": False,
                "verify_iat": False, "verify_aud": False, "verify_iss": False,
                "verify_sub": False, "verify_jti": False,
                "require": ["iss", "sub", "aud", "exp", "iat", "scope"],
            })
            # Reject any parsing disagreement; validation below uses the
            # duplicate-free object whose signature was just verified.
            if verified != claims or claims.get("iss") != self.issuer:
                raise AuthenticationDenied(_DENIED)
            audience = claims.get("aud")
            if isinstance(audience, str):
                allowed_audience = audience == self.audience
            elif type(audience) is list and 1 <= len(audience) <= 8 and all(isinstance(a, str) and 1 <= len(a) <= 2048 for a in audience):
                allowed_audience = self.audience in audience
            else:
                allowed_audience = False
            if not allowed_audience:
                raise AuthenticationDenied(_DENIED)
            subject = claims.get("sub")
            if not isinstance(subject, str) or (self.issuer, subject) not in self._subjects:
                raise AuthenticationDenied(_DENIED)
            scope = claims.get("scope")
            if not isinstance(scope, str) or len(scope) > 2048 or self.required_scope not in scope.split(" "):
                raise AuthenticationDenied(_DENIED)
            now = _number(self._clock())
            issued, expires = _number(claims.get("iat")), _number(claims.get("exp"))
            if issued > now + self._leeway or expires <= now - self._leeway or expires <= issued:
                raise AuthenticationDenied(_DENIED)
            if now - issued > self._max_age + self._leeway or expires - issued > self._max_lifetime:
                raise AuthenticationDenied(_DENIED)
            if "nbf" in claims:
                not_before = _number(claims["nbf"])
                if not_before > now + self._leeway or not_before >= expires:
                    raise AuthenticationDenied(_DENIED)
            return PrincipalAuthority().restore(self._subjects[(self.issuer, subject)])
        except (AuthenticationDenied, jwt.PyJWTError, ValueError, TypeError, KeyError, UnicodeError, OverflowError):
            raise AuthenticationDenied(_DENIED) from None

    def protected_resource_metadata(self) -> dict:
        return protected_resource_metadata(self.audience, self.issuer, required_scope=self.required_scope)


class StaticBearerAuthenticator:
    """Local machine-agent mode with configured SHA256 digests, no token issuing.

    Do not combine with OAuth as a fallback after a failed OAuth JWT. The runtime
    selects one approved authentication mode. Stored digests are never returned.
    """
    def __init__(self, token_digests: Mapping[str, str]):
        if not isinstance(token_digests, Mapping) or not token_digests or len(token_digests) > 128:
            raise AuthenticationDenied(_CONFIG_ERROR)
        values = {}
        for digest, principal_id in token_digests.items():
            if not isinstance(digest, str) or not _DIGEST.fullmatch(digest) or digest.lower() in values:
                raise AuthenticationDenied(_CONFIG_ERROR)
            values[digest.lower()] = _principal_id(principal_id)
        self._digests = MappingProxyType(values)

    def authenticate(self, authorization: str | None) -> VerifiedPrincipal:
        supplied = _bearer(authorization, minimum=32, maximum=4096)
        digest = hashlib.sha256(supplied.encode("ascii")).hexdigest()
        match = None
        for configured, principal_id in self._digests.items():
            if hmac.compare_digest(digest, configured):
                match = principal_id
        if match is None:
            raise AuthenticationDenied(_DENIED)
        return PrincipalAuthority().restore(match)


def protected_resource_metadata(resource: str, issuer: str, *, required_scope: str = "mcp:gateway") -> dict:
    return {"resource": _url(resource), "authorization_servers": [_url(issuer, issuer=True)],
            "scopes_supported": [_scope(required_scope)], "bearer_methods_supported": ["header"]}


def www_authenticate(metadata_url: str, *, required_scope: str = "mcp:gateway") -> str:
    return f'Bearer resource_metadata="{_url(metadata_url)}", scope="{_scope(required_scope)}"'
