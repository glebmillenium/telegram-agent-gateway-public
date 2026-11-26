"""All token/key material here is PUBLIC, fixed, synthetic test data only.

RSA fixture copied from RFC 7515 Appendix A.2.1. Never use this publicly known
private key as a credential. No keypairs or real account tokens are generated.
https://www.rfc-editor.org/rfc/rfc7515#appendix-A.2.1
"""
import base64
import copy
import hashlib
import json
import socket

import jwt
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from telegram_gateway.auth import AuthenticationDenied
from telegram_gateway.runtime_auth import (
    OAuthAuthenticator, StaticBearerAuthenticator, protected_resource_metadata, www_authenticate,
)

ISSUER = "https://issuer.test.example"
RESOURCE = "https://gateway.test.example/mcp"
NOW = 2_000_000_000
# The fixed, globally public RFC demonstration key is deliberately embedded only
# in this test module. Runtime JWKS validation rejects private RSA parameters.
RFC_KEY = {
    "kty": "RSA", "kid": "rfc7515-test", "alg": "RS256", "use": "sig",
    "n": "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx"
         "HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs"
         "D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH"
         "SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV"
         "MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8"
         "NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
    "e": "AQAB",
    "d": "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I"
         "jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0"
         "BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn"
         "439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT"
         "CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh"
         "BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",
    "p": "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdi"
         "YrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPG"
         "BY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc",
    "q": "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxa"
         "ewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA"
         "-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc",
    "dp": "BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3Q"
          "CLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb"
          "34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0",
    "dq": "h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa"
          "7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-ky"
          "NlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU",
    "qi": "IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2o"
          "y26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLU"
          "W0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U",
}


@pytest.fixture(scope="module")
def private_key():
    return jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(RFC_KEY))


@pytest.fixture
def jwks():
    return {"keys": [{k: v for k, v in RFC_KEY.items() if k in {"kty", "kid", "n", "e", "alg", "use"}}]}


@pytest.fixture
def claims():
    return {"iss": ISSUER, "sub": "subject-zeta", "aud": RESOURCE, "iat": NOW - 5,
            "exp": NOW + 120, "scope": "mcp:gateway"}


def make_auth(jwks, **changes):
    config = dict(issuer=ISSUER, audience=RESOURCE, jwks=jwks,
                  subject_principals={(ISSUER, "subject-zeta"): "zeta", (ISSUER, "subject-support"): "support"},
                  clock=lambda: NOW)
    config.update(changes)
    return OAuthAuthenticator(**config)


def signed(private_key, claims, headers=None):
    return "Bearer " + jwt.encode(claims, private_key, algorithm="RS256",
                                  headers={"kid": "rfc7515-test", **(headers or {})})


def test_valid_subjects_map_only_to_server_config(jwks, private_key, claims):
    auth = make_auth(jwks)
    claims.update(agent_id="support", roles=["administrator"], principal="support")
    principal = auth.authenticate(signed(private_key, claims))
    assert principal.authenticated and principal.id == "zeta"
    claims["sub"] = "subject-support"
    assert auth.authenticate(signed(private_key, claims)).id == "support"


def test_valid_nbf_optional_and_multiple_audiences(jwks, private_key, claims):
    auth = make_auth(jwks)
    assert auth.authenticate(signed(private_key, claims)).id == "zeta"
    claims.update(nbf=NOW - 1, aud=["https://another.test.example/api", RESOURCE])
    assert auth.authenticate(signed(private_key, claims)).id == "zeta"


@pytest.mark.parametrize("missing", ["iss", "sub", "aud", "iat", "exp", "scope"])
def test_required_claims(jwks, private_key, claims, missing):
    claims.pop(missing)
    with pytest.raises(AuthenticationDenied, match="^Authentication required$"):
        make_auth(jwks).authenticate(signed(private_key, claims))


@pytest.mark.parametrize("updates", [
    {"iss": ISSUER + "/"}, {"iss": "https://other.test.example"}, {"sub": "outsider"},
    {"sub": 42}, {"aud": RESOURCE + "/"}, {"aud": ["wrong"]}, {"aud": [RESOURCE, 42]},
    {"aud": [RESOURCE] * 9}, {"aud": None}, {"scope": "read"}, {"scope": ["mcp:gateway"]},
    {"scope": "prefixmcp:gateway"}, {"exp": NOW}, {"exp": NOW - 1}, {"exp": "later"},
    {"exp": True}, {"iat": True}, {"iat": NOW + 1}, {"iat": NOW - 3601},
    {"exp": NOW + 3600}, {"nbf": NOW + 1}, {"nbf": "now"}, {"nbf": True},
    {"nbf": NOW + 200, "exp": NOW + 100}, {"iat": float("nan")}, {"exp": float("inf")},
])
def test_bad_claims_fail_closed(jwks, private_key, claims, updates):
    claims.update(updates)
    with pytest.raises(AuthenticationDenied, match="^Authentication required$"):
        make_auth(jwks).authenticate(signed(private_key, claims))


@pytest.mark.parametrize("headers", [
    {"kid": "unknown"}, {"kid": ""}, {"jku": "https://evil.test/jwks"},
    {"x5u": "https://evil.test/cert"}, {"jwk": {"kty": "RSA"}}, {"x5c": ["fake"]},
    {"crit": ["custom"]}, {"b64": False}, {"typ": "something-else"},
])
def test_untrusted_header_never_changes_key_source(jwks, private_key, claims, headers):
    with pytest.raises(AuthenticationDenied):
        make_auth(jwks).authenticate(signed(private_key, claims, headers))


def test_alg_none_hmac_and_bad_signature_rejected(jwks, private_key, claims):
    auth = make_auth(jwks)
    tokens = [
        "Bearer " + jwt.encode(claims, "", algorithm="none", headers={"kid": "rfc7515-test"}),
        "Bearer " + jwt.encode(claims, "PUBLIC-TEST-HMAC-ONLY-NOT-A-CREDENTIAL-1234", algorithm="HS256", headers={"kid": "rfc7515-test"}),
    ]
    valid = signed(private_key, claims)
    tokens.append(valid[:-12] + ("A" * 12))
    for token in tokens:
        with pytest.raises(AuthenticationDenied):
            auth.authenticate(token)


def test_duplicate_json_claims_rejected_even_with_valid_signature(jwks, private_key, claims):
    def enc(data):
        return base64.urlsafe_b64encode(data).rstrip(b"=")
    header = enc(b'{"alg":"RS256","kid":"rfc7515-test"}')
    payload = enc((json.dumps(claims)[:-1] + ',"sub":"subject-support"}').encode())
    signing_input = header + b"." + payload
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    token = (signing_input + b"." + enc(signature)).decode()
    with pytest.raises(AuthenticationDenied):
        make_auth(jwks).authenticate("Bearer " + token)


@pytest.mark.parametrize("headers", [None, "", "Basic x", "Bearer short", {"agent_id": "zeta"}, "Bearer " + "x" * 17000])
def test_malformed_authorization_is_generic(jwks, headers):
    with pytest.raises(AuthenticationDenied, match="^Authentication required$"):
        make_auth(jwks).authenticate(headers)


def test_no_network_or_secret_loader(jwks, private_key, claims, monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("network must not be used")
    monkeypatch.setattr(socket, "socket", denied)
    assert make_auth(jwks).authenticate(signed(private_key, claims)).id == "zeta"


@pytest.mark.parametrize("field,value", [
    ("d", "publicly-known-test-value"), ("kty", "oct"), ("alg", "HS256"), ("use", "enc"),
    ("key_ops", ["sign"]), ("x5u", "https://evil.test/key"), ("kid", "../file"), ("n", "AQAB"),
])
def test_untrusted_or_private_jwks_rejected(jwks, field, value):
    jwks["keys"][0][field] = value
    with pytest.raises(AuthenticationDenied):
        make_auth(jwks)


def test_duplicate_kid_and_empty_jwks_rejected(jwks):
    jwks["keys"].append(copy.deepcopy(jwks["keys"][0]))
    for invalid in (jwks, {"keys": []}, {"keys": [], "url": "https://evil.test"}):
        with pytest.raises(AuthenticationDenied):
            make_auth(invalid)


@pytest.mark.parametrize("change", [
    {"issuer": "http://issuer.test.example"}, {"issuer": "https://user:pass@issuer.test.example"},
    {"issuer": ISSUER + "#fragment"}, {"audience": "http://gateway.test.example/mcp"},
    {"subject_principals": {(ISSUER + "/", "subject-zeta"): "zeta"}},
    {"subject_principals": {}}, {"leeway_seconds": 301}, {"max_token_lifetime_seconds": 0},
])
def test_bad_trust_config(jwks, change):
    with pytest.raises(AuthenticationDenied):
        make_auth(jwks, **change)


def test_clock_leeway_and_configurable_ttl(jwks, private_key, claims):
    claims.update(iat=NOW - 5, exp=NOW - 1)
    assert make_auth(jwks, leeway_seconds=2).authenticate(signed(private_key, claims)).id == "zeta"
    claims.update(iat=NOW - 10, exp=NOW + 4000)
    assert make_auth(jwks, max_token_lifetime_seconds=5000).authenticate(signed(private_key, claims)).id == "zeta"


FIXED_LOCAL_TOKEN = "PUBLIC_SYNTHETIC_LOCAL_AGENT_TOKEN_0001"
FIXED_OTHER_TOKEN = "PUBLIC_SYNTHETIC_LOCAL_AGENT_TOKEN_0002"


def test_static_digest_auth_and_identity_mapping():
    digest = hashlib.sha256(FIXED_LOCAL_TOKEN.encode()).hexdigest()
    auth = StaticBearerAuthenticator({digest: "zeta"})
    assert auth.authenticate("Bearer " + FIXED_LOCAL_TOKEN).id == "zeta"
    assert FIXED_LOCAL_TOKEN not in repr(auth.__dict__)
    with pytest.raises(AuthenticationDenied):
        auth.authenticate("Bearer " + FIXED_OTHER_TOKEN)


@pytest.mark.parametrize("value", [None, "", "Bearer short", "Basic " + FIXED_LOCAL_TOKEN, {"principal": "zeta"}, "Bearer " + "x" * 4097, "Bearer " + "x" * 32 + "\n"])
def test_static_bad_token_generic(value):
    auth = StaticBearerAuthenticator({hashlib.sha256(FIXED_LOCAL_TOKEN.encode()).hexdigest(): "zeta"})
    with pytest.raises(AuthenticationDenied, match="^Authentication required$"):
        auth.authenticate(value)


@pytest.mark.parametrize("mapping", [{}, {"raw-token": "zeta"}, {"a" * 64: "*"}, {"a" * 64: "zeta", "A" * 64: "support"}])
def test_static_config_no_raw_tokens_or_ambiguous_digest(mapping):
    with pytest.raises(AuthenticationDenied):
        StaticBearerAuthenticator(mapping)


def test_resource_metadata_and_header_helpers(jwks):
    expected = {"resource": RESOURCE, "authorization_servers": [ISSUER],
                "scopes_supported": ["mcp:gateway"], "bearer_methods_supported": ["header"]}
    assert make_auth(jwks).protected_resource_metadata() == expected
    assert protected_resource_metadata(RESOURCE, ISSUER) == expected
    assert protected_resource_metadata("http://127.0.0.1:8765/mcp", ISSUER)["resource"].startswith("http://127.0.0.1")
    assert www_authenticate("https://gateway.test.example/.well-known/oauth-protected-resource") == 'Bearer resource_metadata="https://gateway.test.example/.well-known/oauth-protected-resource", scope="mcp:gateway"'
    for bad in ("https://gateway.test.example/\r\nInjected: bad", "https://gateway.test.example/\"", "http://other.example/meta"):
        with pytest.raises(AuthenticationDenied):
            www_authenticate(bad)
