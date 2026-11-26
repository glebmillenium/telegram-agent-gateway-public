"""No external network: synthetic wire fixtures and ephemeral loopback only."""
import asyncio
import base64
from dataclasses import replace
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import socket
import ssl
import threading
import time

import pytest

from telegram_gateway import network
from telegram_gateway.bot_api import BotApiAdapter, BotRejected, BotUnavailable, DeliveryUncertain
from telegram_gateway.auth import PrincipalAuthority
from telegram_gateway.events import CallbackTarget, EventError, EventHub, MemorySecretStore, WebhookResponse, verify_signature
from telegram_gateway.network import BotHTTPTransport, PinnedWebhookSender, NetworkFailure, resolve_public

TOKEN = "99999:synthetic_fake_token_for_network_tests"
PUBLIC = "93.184.216.34"
OTHER = "1.1.1.1"
TARGET = CallbackTarget("https://receiver.example/mcp?route=fake", "receiver.example", 443, (PUBLIC,))
HEADERS = {"Content-Type": "application/json", "webhook-id": "fake_event_1",
           "webhook-timestamp": "1800000000", "webhook-signature": "v1,FAKE",
           "X-MCP-Subscription-Id": "sub_fake"}


@pytest.fixture(autouse=True)
def deny_external_network(monkeypatch):
    create = socket.create_connection
    lookup = socket.getaddrinfo
    def safe_create(address, *args, **kwargs):
        assert address[0] in {"127.0.0.1", "::1"}, "Unexpected external network attempt"
        return create(address, *args, **kwargs)
    def safe_lookup(host, *args, **kwargs):
        assert host in {"127.0.0.1", "::1"}, "Unexpected external DNS attempt"
        return lookup(host, *args, **kwargs)
    monkeypatch.setattr(socket, "create_connection", safe_create)
    monkeypatch.setattr(socket, "getaddrinfo", safe_lookup)


class FakeSocket:
    def __init__(self, peer=PUBLIC):
        self.peer = peer
        self.timeout = None
        self.closed = False
        self.handshakes = 0

    def getpeername(self):
        return self.peer, 443

    def settimeout(self, value):
        self.timeout = value

    def do_handshake(self):
        self.handshakes += 1

    def shutdown(self, how):
        self.closed = True

    def close(self):
        self.closed = True


class FakeTLSContext:
    check_hostname = True
    verify_mode = ssl.CERT_REQUIRED

    def __init__(self):
        self.wraps = []

    def wrap_socket(self, sock, *, server_hostname, do_handshake_on_connect):
        self.wraps.append((sock, server_hostname, do_handshake_on_connect))
        return sock


def test_pinned_tls_dials_literal_checks_peer_and_preserves_sni(monkeypatch):
    context = FakeTLSContext()
    sock = FakeSocket()
    dials = []
    def connect(address, **kwargs):
        dials.append((address, kwargs))
        return sock
    monkeypatch.setattr(network.ssl, "create_default_context", lambda: context)
    monkeypatch.setattr(network.socket, "create_connection", connect)
    connection = network._PinnedHTTPSConnection("receiver.example", 443, PUBLIC,
        deadline=time.monotonic() + 2, connect_timeout=1)
    connection.connect()
    assert dials[0][0] == (PUBLIC, 443)
    assert context.wraps == [(sock, "receiver.example", False)]
    assert sock.handshakes == 1 and sock.timeout > 0
    connection.close()


@pytest.mark.parametrize("peer", [OTHER, "127.0.0.1", "::ffff:93.184.216.34"])
def test_peer_mismatch_or_private_peer_rejected_before_tls_payload(monkeypatch, peer):
    context = FakeTLSContext()
    sock = FakeSocket(peer)
    monkeypatch.setattr(network.ssl, "create_default_context", lambda: context)
    monkeypatch.setattr(network.socket, "create_connection", lambda *_, **__: sock)
    connection = network._PinnedHTTPSConnection("receiver.example", 443, PUBLIC,
        deadline=time.monotonic() + 2, connect_timeout=1)
    with pytest.raises(NetworkFailure):
        connection.connect()
    assert context.wraps == [] and sock.closed


def test_insecure_tls_context_and_proxy_tunnel_rejected(monkeypatch):
    context = FakeTLSContext()
    context.check_hostname = False
    monkeypatch.setattr(network.ssl, "create_default_context", lambda: context)
    with pytest.raises(NetworkFailure):
        network._PinnedHTTPSConnection("receiver.example", 443, PUBLIC,
                                      deadline=time.monotonic() + 2, connect_timeout=1)
    context.check_hostname = True
    connection = network._PinnedHTTPSConnection("receiver.example", 443, PUBLIC,
        deadline=time.monotonic() + 2, connect_timeout=1)
    connection.set_tunnel("proxy.invalid", 443)
    with pytest.raises(NetworkFailure):
        connection.connect()


@pytest.mark.parametrize("addresses", [[PUBLIC], [PUBLIC, OTHER], ["2606:4700:4700::1111"]])
def test_resolve_public_uses_every_dns_address_and_canonicalizes(monkeypatch, addresses):
    queries = []
    def lookup(host, port, **kwargs):
        queries.append((host, port, kwargs))
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, 443)) for ip in addresses]
    monkeypatch.setattr(network.socket, "getaddrinfo", lookup)
    assert resolve_public("receiver.example") == addresses
    assert queries[0][0:2] == ("receiver.example", 443)
    assert queries[0][2] == {"type": socket.SOCK_STREAM, "proto": socket.IPPROTO_TCP}


@pytest.mark.parametrize("addresses", [[PUBLIC, "127.0.0.1"], ["10.1.2.3"], [],
    ["169.254.169.254"], ["100.64.0.1"], ["::ffff:93.184.216.34"], ["224.0.0.1"]])
def test_resolver_rejects_nonpublic_or_mixed_dns(monkeypatch, addresses):
    monkeypatch.setattr(network.socket, "getaddrinfo", lambda *_, **__: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443)) for ip in addresses])
    with pytest.raises(NetworkFailure):
        resolve_public("receiver.example")


class FakeResponse:
    def __init__(self, status=200, body=b"{}", headers=None):
        self.status, self.body = status, body
        self.headers = {"Content-Length": str(len(body))} if headers is None else headers

    def getheader(self, name):
        return self.headers.get(name)

    def read(self, count):
        result, self.body = self.body[:count], self.body[count:]
        return result


class FakeConnection:
    def __init__(self, response=None, error=None):
        self.response = response or FakeResponse()
        self.error, self.calls = error, []
        self.sock = FakeSocket()
        self.closed = False

    def request(self, method, path, *, body, headers, encode_chunked):
        self.calls.append((method, path, body, headers, encode_chunked))
        if self.error:
            raise self.error

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


async def test_webhook_revalidates_dns_every_time_pins_and_preserves_host(monkeypatch):
    resolutions, targets = [], []
    def resolver(host):
        resolutions.append(host)
        return [PUBLIC]
    connection = FakeConnection(FakeResponse(body=b'{"challenge":"fake"}'))
    sender = PinnedWebhookSender(resolver=resolver)
    def factory(target, deadline):
        targets.append(target)
        return connection
    monkeypatch.setattr(sender, "_connection", factory)
    response = await sender(TARGET, b'{"type":"verification"}', HEADERS)
    assert response == WebhookResponse(200, b'{"challenge":"fake"}')
    assert targets == [TARGET]
    call = connection.calls[0]
    assert call[0:3] == ("POST", "/mcp?route=fake", b'{"type":"verification"}')
    assert call[3]["Host"] == "receiver.example" and call[3]["Accept-Encoding"] == "identity"
    assert call[3]["webhook-signature"] == HEADERS["webhook-signature"]
    assert call[4] is False and connection.closed
    monkeypatch.setattr(sender, "_connection", lambda *_: FakeConnection())
    await sender(TARGET, b"{}", HEADERS)
    assert resolutions == ["receiver.example", "receiver.example"]


@pytest.mark.parametrize("addresses", [["127.0.0.1"], [PUBLIC, "10.0.0.1"], [OTHER]])
async def test_dns_rebinding_and_changed_pin_fail_before_connection(monkeypatch, addresses):
    sender = PinnedWebhookSender(resolver=lambda _: addresses)
    def forbidden(*_):
        pytest.fail("Connection must not start")
    monkeypatch.setattr(sender, "_connection", forbidden)
    with pytest.raises(EventError):
        await sender(TARGET, b"{}", HEADERS)


@pytest.mark.parametrize("target", [replace(TARGET, follow_redirects=True),
    replace(TARGET, hostname="other.example"), replace(TARGET, port=8443),
    replace(TARGET, addresses=("127.0.0.1",)), replace(TARGET, url="http://receiver.example/mcp"),
    replace(TARGET, url="https://receiver.example/mcp\r\nHeader: x")])
async def test_forged_callback_target_rejected_without_dns(monkeypatch, target):
    def forbidden(*_):
        pytest.fail("DNS must not start")
    with pytest.raises(EventError):
        await PinnedWebhookSender(resolver=forbidden)(target, b"{}", HEADERS)


@pytest.mark.parametrize("headers", [{**HEADERS, "Host": "localhost"},
    {**HEADERS, "webhook-id": "fake\r\nInjected: yes"}, {**HEADERS, "Content-Type": "text/plain"},
    {k:v for k,v in HEADERS.items() if k != "webhook-signature"}])
async def test_webhook_header_injection_rejected(headers):
    def forbidden(*_):
        pytest.fail("DNS must not start")
    with pytest.raises(EventError):
        await PinnedWebhookSender(resolver=forbidden)(TARGET, b"{}", headers)


async def test_webhook_never_follows_redirect(monkeypatch):
    connection = FakeConnection(FakeResponse(302, b"", {"Content-Length": "0", "Location": "http://127.0.0.1/secret"}))
    sender = PinnedWebhookSender(resolver=lambda _: [PUBLIC])
    monkeypatch.setattr(sender, "_connection", lambda *_: connection)
    response = await sender(TARGET, b"{}", HEADERS)
    assert response.status == 302 and len(connection.calls) == 1


async def test_webhook_bounds_body_response_and_hides_callback_exception(monkeypatch):
    sender = PinnedWebhookSender(resolver=lambda _: [PUBLIC], max_response_bytes=5)
    monkeypatch.setattr(sender, "_connection", lambda *_: FakeConnection(FakeResponse(body=b"x" * 6)))
    with pytest.raises(EventError):
        await sender(TARGET, b"{}", HEADERS)
    monkeypatch.setattr(sender, "_connection", lambda *_: FakeConnection(error=OSError("SECRET https://private.callback/path")))
    with pytest.raises(EventError) as caught:
        await sender(TARGET, b"{}", HEADERS)
    assert "SECRET" not in str(caught.value) and "private.callback" not in str(caught.value)
    with pytest.raises(EventError):
        await sender(TARGET, b"x" * (256 * 1024 + 1), HEADERS)


class LoopbackServer:
    def __init__(self):
        self.requests, self.responses = [], []
        outer = self
        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            def log_message(self, *args):
                pass  # Never log token-containing request paths.
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                outer.requests.append((self.command, self.path, body, dict(self.headers)))
                item = outer.responses.pop(0) if outer.responses else {}
                time.sleep(item.get("delay", 0))
                response = item.get("body", b'{"ok":true,"result":{"id":123,"is_bot":true}}')
                try:
                    self.send_response(item.get("status", 200))
                    if not item.get("omit_length"):
                        self.send_header("Content-Length", str(item.get("length", len(response))))
                    self.send_header("Connection", "close")
                    for name, value in item.get("headers", {}).items():
                        self.send_header(name, value)
                    self.end_headers()
                    if item.get("chunk_delay"):
                        for byte in response:
                            self.wfile.write(bytes([byte]))
                            self.wfile.flush()
                            time.sleep(item["chunk_delay"])
                    else:
                        self.wfile.write(response)
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


@pytest.fixture
def loopback():
    server = LoopbackServer()
    try:
        yield server
    finally:
        server.close()


class LocalTestBotHTTPTransport(BotHTTPTransport):
    """TEST ONLY: not exported or selectable by runtime configuration."""
    def __init__(self, loopback, **kwargs):
        super().__init__(TOKEN, **kwargs)
        self.loopback = loopback
        self.deadline_budgets = []

    async def _resolve_target(self, deadline):
        self.deadline_budgets.append(deadline - time.monotonic())
        return CallbackTarget("https://api.telegram.org/", "api.telegram.org", 443, (PUBLIC,))

    def _connection(self, target, deadline):
        return http.client.HTTPConnection("127.0.0.1", self.loopback.server.server_port,
                                          timeout=min(self.connect_timeout, network._remaining(deadline)))


def send_params():
    return {"chat_id": -100001, "text": "FAKE approved", "protect_content": True,
            "link_preview_options": {"is_disabled": True}}


async def test_real_loopback_post_body_fixed_method_helpers_and_no_proxy(loopback, monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:1")
    transport = LocalTestBotHTTPTransport(loopback)
    assert (await transport.get_me())["ok"] is True
    await transport.get_chat(-100001)
    await transport.get_chat_member(-100001, 101)
    await transport.get_webhook_info()
    assert [request[1].rsplit("/", 1)[1] for request in loopback.requests] == ["getMe", "getChat", "getChatMember", "getWebhookInfo"]
    assert json.loads(loopback.requests[1][2]) == {"chat_id": -100001}
    assert loopback.requests[0][0] == "POST"
    assert loopback.requests[0][3]["Host"] == "api.telegram.org"
    assert loopback.requests[0][3]["Content-Type"] == "application/json"
    assert TOKEN not in repr(transport)


async def test_long_poll_timeout_margin_and_fixed_allowed_updates(loopback):
    transport = LocalTestBotHTTPTransport(loopback)
    loopback.responses.append({"body": b'{"ok":true,"result":[]}'})
    await transport.request("getUpdates", {"offset": 7, "limit": 100, "timeout": 50, "allowed_updates": ["message"]})
    assert 59 < transport.deadline_budgets[-1] <= 60
    assert json.loads(loopback.requests[-1][2])["allowed_updates"] == ["message"]


@pytest.mark.parametrize("method,params", [("deleteWebhook", {}), ("setWebhook", {}),
    ("sendDocument", {}), ("../getMe", {}), ("getChat", {"chat_id": "@username"}),
    ("getChatMember", {"chat_id": -100001, "user_id": True}),
    ("getUpdates", {"offset": 0, "limit": 101, "timeout": 25, "allowed_updates": ["message"]}),
    ("sendMessage", {**send_params(), "parse_mode": "HTML"}),
    ("sendMessage", {**send_params(), "url": "http://localhost/"}),
    ("sendMessage", {**send_params(), "protect_content": False})])
async def test_narrow_method_and_parameter_allowlist_precedes_network(loopback, method, params):
    transport = LocalTestBotHTTPTransport(loopback)
    with pytest.raises(BotRejected):
        await transport.request(method, params)
    assert loopback.requests == [] and transport.deadline_budgets == []


@pytest.mark.parametrize("origin", ["http://api.telegram.org", "https://api.telegram.org/", "https://127.0.0.1", "https://attacker.example"])
def test_production_origin_cannot_be_reconfigured(origin):
    with pytest.raises(ValueError):
        BotHTTPTransport(TOKEN, api_origin=origin)


async def test_explicit_api_rejection_is_definite_and_not_retried(loopback):
    loopback.responses.append({"status": 429, "body": b'{"ok":false,"description":"SECRET","parameters":{"retry_after":7}}'})
    transport = LocalTestBotHTTPTransport(loopback)
    with pytest.raises(BotRejected) as caught:
        await transport.request("sendMessage", send_params())
    assert caught.value.retry_after == 7 and "SECRET" not in str(caught.value)
    assert len(loopback.requests) == 1


@pytest.mark.parametrize("item", [
    {"status": 500, "body": b'{"ok":false,"description":"SECRET"}'},
    {"status": 302, "body": b'{"ok":true,"result":{}}', "headers": {"Location": "http://127.0.0.1:1/"}},
    {"body": b'not JSON SECRET'}, {"body": b'{"ok":true,"ok":false}'},
    {"body": b'{"ok":NaN,"result":{}}'}, {"body": b'{"ok":true}'},
    {"body": b"x" * 65}, {"body": b"x" * 65, "omit_length": True},
    {"body": b"{}", "length": 20},
    {"body": b"{}", "headers": {"Content-Encoding": "gzip"}},
])
async def test_bad_or_ambiguous_http_send_result_never_retries(loopback, item):
    loopback.responses.append(item)
    transport = LocalTestBotHTTPTransport(loopback, max_response_bytes=64)
    with pytest.raises(DeliveryUncertain) as caught:
        await transport.request("sendMessage", send_params())
    assert TOKEN not in str(caught.value) and "SECRET" not in str(caught.value)
    assert len(loopback.requests) == 1


async def test_real_loopback_socket_deadline_send_uncertain_read_unavailable(loopback):
    transport = LocalTestBotHTTPTransport(loopback, request_timeout=.15, connect_timeout=.1)
    loopback.responses.append({"delay": .5})
    before = time.monotonic()
    with pytest.raises(DeliveryUncertain):
        await transport.request("sendMessage", send_params())
    assert time.monotonic() - before < .45
    loopback.responses.append({"delay": .5})
    with pytest.raises(BotUnavailable):
        await transport.get_me()
    assert len(loopback.requests) == 2


async def test_absolute_deadline_stops_slow_response_even_with_regular_bytes(loopback):
    loopback.responses.append({"chunk_delay": .04})
    transport = LocalTestBotHTTPTransport(loopback, request_timeout=.18, connect_timeout=.1)
    before = time.monotonic()
    with pytest.raises(DeliveryUncertain):
        await transport.request("sendMessage", send_params())
    assert time.monotonic() - before < .5
    assert len(loopback.requests) == 1


async def test_adapter_integrates_real_loopback_wire_receipt(loopback):
    loopback.responses.append({"body": b'{"ok":true,"result":{"message_id":77,"chat":{"id":-100001},"message_thread_id":9}}'})
    transport = LocalTestBotHTTPTransport(loopback)
    adapter = BotApiAdapter(transport, allowed_scopes={(-100001, 9)})
    result = await adapter.send_message(chat_id=-100001, topic_id=9, text="FAKE approved", operation_id="op_fake")
    assert result.message_id == 77 and result.synthetic is False
    assert "operation_id" not in json.loads(loopback.requests[0][2])


async def test_send_resolution_failure_cannot_have_sent(monkeypatch):
    transport = BotHTTPTransport(TOKEN)
    async def no_dns(_):
        raise OSError("SECRET")
    monkeypatch.setattr(transport, "_resolve_target", no_dns)
    with pytest.raises(BotRejected) as caught:
        await transport.request("sendMessage", send_params())
    assert "SECRET" not in str(caught.value)


async def test_cancellation_waits_for_inflight_http_worker_before_releasing_lock(monkeypatch):
    entered, release, completed = threading.Event(), threading.Event(), threading.Event()
    sender = PinnedWebhookSender(resolver=lambda _: [PUBLIC])
    def exchange(*_):
        entered.set()
        assert release.wait(timeout=2)
        completed.set()
        return WebhookResponse(200)
    monkeypatch.setattr(sender, "_exchange", exchange)
    task = asyncio.create_task(sender(TARGET, b"{}", HEADERS))
    await asyncio.wait_for(asyncio.to_thread(entered.wait, 1), timeout=1.2)
    task.cancel()
    await asyncio.sleep(.02)
    assert not task.done() and not completed.is_set()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert completed.is_set()


async def test_eventhub_subscription_and_delivery_use_network_sender_contract(tmp_path, monkeypatch):
    authority = PrincipalAuthority()
    principal = authority.restore("alpha")
    secret = "whsec_" + base64.b64encode(b"synthetic-callback-fixture-key-0001").decode()
    calls = []
    class CallbackConnection(FakeConnection):
        def request(self, method, path, *, body, headers, encode_chunked):
            super().request(method, path, body=body, headers=headers, encode_chunked=encode_chunked)
            verify_signature(secret, body, headers, now=time.time(), replay_ids=set())
            content = json.loads(body)
            if content.get("type") == "verification":
                result = json.dumps({"challenge": content["challenge"]}).encode()
            else:
                assert content["data"]["chat_id"] == -100001
                result = b"{}"
            self.response = FakeResponse(body=result)
            calls.append((path, content, headers))
    sender = PinnedWebhookSender(resolver=lambda _: [PUBLIC])
    monkeypatch.setattr(sender, "_connection", lambda *_: CallbackConnection())
    def authorize(principal, name, arguments):
        if principal.id != "alpha" or arguments != {"chat_id": -100001, "topic_id": None}:
            raise ValueError()
    def callback_authorize(principal, callback):
        if principal.id != "alpha" or callback != TARGET.url:
            raise ValueError()
    hub = EventHub(tmp_path / "events.sqlite", authorize, sender=sender,
                   resolver=lambda _: [PUBLIC], secret_store=MemorySecretStore(),
                   principal_factory=authority.restore, catalog_authorizer=lambda _: True,
                   callback_authorizer=callback_authorize, challenge_factory=lambda: "synthetic-challenge-network-00001")
    try:
        subscription = await hub.subscribe(principal, {"name": "telegram.message.created",
            "arguments": {"chat_id": -100001},
            "delivery": {"mode": "webhook", "url": TARGET.url, "secret": secret}})
        assert subscription["id"].startswith("sub_")
        assert hub.enqueue(principal, "telegram.message.created", {"chat_id": -100001},
            {"chat_id": -100001, "message_id": 7, "text": "FAKE only"}, "evt_fake_7") == 1
        assert (await hub.deliver_due(principal))["delivered"] == 1
        assert len(calls) == 2
        assert calls[0][1]["type"] == "verification"
        assert calls[1][1]["eventId"] == "evt_fake_7"
        assert all(call[2]["Host"] == "receiver.example" for call in calls)
    finally:
        hub.close()


def test_setup_probe_zero_timeout_only_transport_and_negative_denied():
    params = {"offset": 0, "limit": 100, "timeout": 0}
    assert network._validate_bot_params("getUpdates", params) == params
    for invalid in ({**params, "timeout": -1}, {**params, "timeout": 1},
                    {**params, "offset": 1}, {**params, "limit": 101},
                    {**params, "allowed_updates": []}, {"offset": 0, "limit": 100}):
        with pytest.raises(BotRejected):
            network._validate_bot_params("getUpdates", invalid)
    regular = {"offset": 12, "limit": 100, "timeout": 25, "allowed_updates": ["message"]}
    assert network._validate_bot_params("getUpdates", regular) == regular
