"""Local-client tests use temporary synthetic auth files and httpx mocks only."""
import importlib.util
import json
from pathlib import Path

import httpx
import pytest

SCRIPT = Path(__file__).parents[1] / "scripts" / "gateway_local_client.py"
SPEC = importlib.util.spec_from_file_location("gateway_local_client_fixture", SCRIPT)
client_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(client_module)
TOKEN = "PUBLIC_FIXED_SYNTHETIC_LOCAL_BEARER_FOR_TESTS"


@pytest.fixture
def auth_file(tmp_path):
    path = tmp_path / "fake-auth.json"
    path.write_text(json.dumps({"version": 1, "bearer": TOKEN}), encoding="utf-8")
    return path


def mock_client(monkeypatch, handler):
    original = httpx.Client
    options = []
    def factory(**kwargs):
        options.append(kwargs)
        assert kwargs["trust_env"] is False and kwargs["follow_redirects"] is False
        assert 0 < kwargs["timeout"] <= 10
        return original(transport=httpx.MockTransport(handler), **kwargs)
    monkeypatch.setattr(client_module.httpx, "Client", factory)
    return options


def success(output=None):
    return httpx.Response(200, json={"jsonrpc": "2.0", "id": client_module.REQUEST_ID, "result": {
        "structuredContent": output or {"status": "ok"}, "isError": False,
    }})


@pytest.mark.parametrize("command,tool,arguments", [
    (["ping"], "ping", {}),
    (["list-scopes"], "list_allowed_scopes", {}),
    (["read-history", "--chat-id", "-1001", "--topic-id", "7"], "read_history", {"chat_id": -1001, "topic_id": 7, "limit": 20}),
    (["read-history", "--chat-id", "-1001", "--all-topics", "--limit", "4"], "read_history", {"chat_id": -1001, "topic_id": None, "all_topics": True, "limit": 4}),
    (["next-events", "--chat-id", "-1001", "--unthreaded"], "next_events", {"chat_id": -1001, "topic_id": None, "limit": 20}),
    (["create-draft", "--chat-id", "-1001", "--topic-id", "7", "--text", "Literal $(not-executed); 'text'"], "create_draft", {"chat_id": -1001, "topic_id": 7, "text": "Literal $(not-executed); 'text'"}),
])
def test_supported_commands_fixed_loopback_mcp2_and_header_only_identity(auth_file, monkeypatch, capsys, command, tool, arguments):
    calls = []
    def handler(request):
        calls.append(request)
        assert request.method == "POST" and str(request.url) == "http://127.0.0.1:8765/mcp"
        assert request.headers["Authorization"] == "Bearer " + TOKEN
        assert request.headers["Mcp-Method"] == "tools/call"
        assert request.headers["Mcp-Name"] == tool
        assert request.headers["MCP-Protocol-Version"] == client_module.VERSION
        assert request.headers["Accept"] == "application/json, text/event-stream"
        body = json.loads(request.content)
        assert body["params"]["name"] == tool and body["params"]["arguments"] == arguments
        assert body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] == client_module.VERSION
        assert body["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"] == {}
        assert TOKEN not in request.content.decode()
        return success({"fixture": "result only"})
    options = mock_client(monkeypatch, handler)
    assert client_module.main(["--auth-file", str(auth_file), *command]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {"fixture": "result only"}
    assert captured.err == "" and TOKEN not in captured.out and len(calls) == len(options) == 1


def test_response_redacts_bearer_in_values_keys_and_text_fallback(auth_file, monkeypatch, capsys):
    for body in (
        {"structuredContent": {TOKEN: "Bearer " + TOKEN, "nested": [{"text": TOKEN}]}, "isError": False},
        {"content": [{"type": "text", "text": TOKEN}], "isError": False},
    ):
        mock_client(monkeypatch, lambda request: httpx.Response(200, json={"jsonrpc": "2.0", "id": client_module.REQUEST_ID, "result": body}))
        assert client_module.main(["--auth-file", str(auth_file), "ping"]) == 0
        output = capsys.readouterr()
        assert TOKEN not in output.out + output.err and "[REDACTED]" in output.out
        monkeypatch.undo()


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_redirect_is_never_followed_or_reported(auth_file, monkeypatch, capsys, status):
    requests = []
    def handler(request):
        requests.append(str(request.url))
        return httpx.Response(status, headers={"Location": "https://outside.invalid/" + TOKEN}, text=TOKEN)
    mock_client(monkeypatch, handler)
    assert client_module.main(["--auth-file", str(auth_file), "ping"]) == 1
    output = capsys.readouterr()
    assert requests == [client_module.ENDPOINT]
    assert output.out == "" and output.err == "Local gateway command failed\n"


@pytest.mark.parametrize("status,body", [
    (401, {"error": TOKEN}), (403, {"error": TOKEN}), (500, {"error": TOKEN}),
    (200, {"jsonrpc": "2.0", "id": "local-gateway-client", "error": {"message": TOKEN}}),
    (200, {"jsonrpc": "2.0", "id": "local-gateway-client", "result": {"isError": True, "content": [{"text": TOKEN}]}}),
])
def test_wrong_auth_denied_scope_and_tool_errors_have_no_sensitive_output(auth_file, monkeypatch, capsys, status, body):
    mock_client(monkeypatch, lambda request: httpx.Response(status, json=body))
    assert client_module.main(["--auth-file", str(auth_file), "read-history", "--chat-id", "-9999", "--all-topics"]) == 1
    output = capsys.readouterr()
    expected = "Gateway tool reported an error\n" if body.get("result", {}).get("isError") is True else "Local gateway command failed\n"
    assert output.out == "" and output.err == expected


def test_network_exception_cannot_echo_token_or_request(auth_file, monkeypatch, capsys):
    def handler(request):
        raise httpx.ConnectError(TOKEN + " credential error", request=request)
    mock_client(monkeypatch, handler)
    assert client_module.main(["--auth-file", str(auth_file), "ping"]) == 1
    output = capsys.readouterr()
    assert TOKEN not in output.out + output.err and output.out == ""


@pytest.mark.parametrize("bearer,value", [("12345678901234567890123456789012", 12345678901234567890123456789012),
                                          ("true", True), ("null", None), ("12345", 912345678)])
def test_numeric_boolean_and_null_echoes_cannot_disclose_bearer(tmp_path, monkeypatch, capsys, bearer, value):
    path = tmp_path / "fake-primitive-auth.json"
    path.write_text(json.dumps({"version": 1, "bearer": bearer}), encoding="utf-8")
    mock_client(monkeypatch, lambda request: success({"echo": value}))
    assert client_module.main(["--auth-file", str(path), "ping"]) == 0
    output = capsys.readouterr()
    assert json.loads(output.out) == {"echo": "[REDACTED]"}
    assert bearer not in output.out + output.err


def test_serialization_escape_fallback_remains_valid_json(tmp_path, monkeypatch, capsys):
    path = tmp_path / "fake-escape-auth.json"
    path.write_text(json.dumps({"version": 1, "bearer": "u0000"}), encoding="utf-8")
    mock_client(monkeypatch, lambda request: success({"echo": "\x00"}))
    assert client_module.main(["--auth-file", str(path), "ping"]) == 0
    output = capsys.readouterr()
    assert json.loads(output.out) == {} and "u0000" not in output.out


@pytest.mark.parametrize("extra", [
    ["send", "--text", TOKEN], ["ping", "--principal", TOKEN], ["ping", "--endpoint", "https://outside.invalid"],
    ["read-history", "--chat-id", "-1001"],
    ["read-history", "--chat-id", "1", "--all-topics"],
    ["read-history", "--chat-id", "-1001", "--topic-id", "7", "--all-topics"],
    ["next-events", "--chat-id", "-1001", "--all-topics", "--limit", "101"],
    ["create-draft", "--chat-id", "-1001", "--all-topics", "--text", TOKEN],
    ["create-draft", "--chat-id", "-1001", "--unthreaded", "--text", ""],
])
def test_invalid_cli_and_send_never_read_credential_or_echo_input(monkeypatch, capsys, extra):
    def denied(*args, **kwargs):
        raise AssertionError("invalid CLI must fail before credential read")
    monkeypatch.setattr(client_module, "_load_bearer", denied)
    with pytest.raises(SystemExit) as result:
        client_module.main(["--auth-file", "unused-fake-path", *extra])
    assert result.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == "Invalid local client command\n"


@pytest.mark.parametrize("data", [
    {}, {"version": True, "bearer": TOKEN}, {"version": 2, "bearer": TOKEN},
    {"version": 1, "bearer": TOKEN, "principal": "agent_beta"},
    {"version": 1, "bearer": ""}, {"version": 1, "bearer": "Bearer " + TOKEN},
    {"version": 1, "bearer": TOKEN + "\n"}, {"version": 1, "bearer": None},
])
def test_credential_json_schema_rejects_identity_metadata_and_malformed_bearer(tmp_path, data):
    path = tmp_path / "fake-invalid-auth.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(client_module.LocalClientError, match="^Local credential is unavailable$"):
        client_module._load_bearer(path)


@pytest.mark.parametrize("raw", [b'{"version":1,"bearer":"x","bearer":"y"}', b'{"version":NaN,"bearer":"x"}',
                                    b"\xff", b" " * 65537], ids=["duplicate", "nan", "utf8", "oversized"])
def test_credential_json_strict_and_bounded(tmp_path, raw):
    path = tmp_path / "fake-malformed-auth.json"
    path.write_bytes(raw)
    with pytest.raises(client_module.LocalClientError, match="^Local credential is unavailable$"):
        client_module._load_bearer(path)


@pytest.mark.parametrize("raw", [b'{"jsonrpc":"2.0","id":"wrong","result":{}}',
                                    b'{"jsonrpc":"2.0","id":"local-gateway-client","result":{},"result":{}}',
                                    b"\xff", b" " * 1048577], ids=["wrong-id", "duplicate", "utf8", "oversized"])
def test_bad_gateway_response_fails_without_raw_output(auth_file, monkeypatch, capsys, raw):
    mock_client(monkeypatch, lambda request: httpx.Response(200, content=raw, headers={"Content-Type": "application/json"}))
    assert client_module.main(["--auth-file", str(auth_file), "ping"]) == 1
    output = capsys.readouterr()
    assert output.out == "" and output.err == "Local gateway command failed\n"


DRAFT_ID = "0123456789abcdef0123456789abcdef"


def test_draft_status_is_one_read_request_without_implicit_retry_or_ack(auth_file, monkeypatch, capsys):
    calls = []
    metadata = {"draft_id": DRAFT_ID, "status": "unknown", "expired": True,
                "attempt_started": True, "failure": None, "receipt": None}
    def handler(request):
        calls.append(request)
        body = json.loads(request.content)
        assert request.headers["Mcp-Name"] == "get_draft_status"
        assert body["params"]["arguments"] == {"draft_id": DRAFT_ID}
        return success(metadata)
    mock_client(monkeypatch, handler)
    assert client_module.main(["--auth-file", str(auth_file), "draft-status", "--draft-id", DRAFT_ID]) == 0
    output = capsys.readouterr()
    assert json.loads(output.out) == metadata and output.err == "" and len(calls) == 1


@pytest.mark.parametrize("extra", [["--draft-id", "A" * 32], ["--draft-id", DRAFT_ID, "--principal", TOKEN],
                                    ["--draft-id", DRAFT_ID, "--chat-id", "-1101"], []])
def test_draft_status_bad_id_or_selector_fails_before_auth(monkeypatch, capsys, extra):
    monkeypatch.setattr(client_module, "_load_bearer", lambda *a: pytest.fail("invalid ID read credential"))
    with pytest.raises(SystemExit) as error:
        client_module.main(["--auth-file", "unused", "draft-status", *extra])
    output = capsys.readouterr()
    assert error.value.code == 2 and output.out == "" and output.err == "Invalid local client command\n"


def test_explicit_tool_error_does_not_imply_historical_send_outcome(auth_file, monkeypatch, capsys):
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": client_module.REQUEST_ID, "result": {
            "isError": True, "content": [{"type": "text", "text": "arbitrary private error " + TOKEN}],
            "structuredContent": {"do_not_echo": TOKEN}}})
    mock_client(monkeypatch, handler)
    assert client_module.main(["--auth-file", str(auth_file), "send-draft", "--draft-id", DRAFT_ID]) == 1
    output = capsys.readouterr()
    assert output.out == "" and TOKEN not in output.err and "arbitrary" not in output.err
    assert output.err == ("Gateway tool reported an error\n"
                          "Inspect draft-status; do not automatically retry. This does not determine an earlier send outcome.\n")
    assert len(calls) == 1


def test_send_draft_uses_only_exact_existing_id_and_one_fixed_loopback_request(auth_file, monkeypatch, capsys):
    calls = []
    def handler(request):
        calls.append(request)
        body = json.loads(request.content)
        assert str(request.url) == client_module.ENDPOINT and request.method == "POST"
        assert request.headers["Authorization"] == "Bearer " + TOKEN
        assert request.headers["Mcp-Name"] == "send_draft"
        assert body["method"] == "tools/call" and body["params"]["name"] == "send_draft"
        assert body["params"]["arguments"] == {"draft_id": DRAFT_ID}
        assert TOKEN not in request.content.decode()
        return success({"status": "sent", "receipt": {"message_id": 123, "echo": TOKEN}, "reused": False})
    options = mock_client(monkeypatch, handler)
    assert client_module.main(["--auth-file", str(auth_file), "send-draft", "--draft-id", DRAFT_ID]) == 0
    output = capsys.readouterr()
    assert json.loads(output.out) == {"status": "sent", "receipt": {"message_id": 123, "echo": "[REDACTED]"}, "reused": False}
    assert output.err == "" and len(calls) == len(options) == 1


@pytest.mark.parametrize("draft_id", ["", "a" * 31, "a" * 33, "A" * 32, "g" * 32,
                                     " " + DRAFT_ID, DRAFT_ID + "\n", TOKEN])
def test_bad_send_id_fails_before_auth_read_and_is_not_echoed(monkeypatch, capsys, draft_id):
    monkeypatch.setattr(client_module, "_load_bearer", lambda *a: pytest.fail("invalid ID read credential"))
    with pytest.raises(SystemExit) as error:
        client_module.main(["--auth-file", "unused", "send-draft", "--draft-id", draft_id])
    output = capsys.readouterr()
    assert error.value.code == 2 and output.out == "" and output.err == "Invalid local client command\n"


@pytest.mark.parametrize("extra", [["--text", TOKEN], ["--chat-id", "-1001"], ["--topic-id", "7"],
                                  ["--all-topics"], ["--bot-reference", "another_bot"], ["--principal", "other"]])
def test_send_draft_has_no_content_recipient_or_identity_selectors(monkeypatch, capsys, extra):
    monkeypatch.setattr(client_module, "_load_bearer", lambda *a: pytest.fail("invalid selectors read credential"))
    with pytest.raises(SystemExit) as error:
        client_module.main(["--auth-file", "unused", "send-draft", "--draft-id", DRAFT_ID, *extra])
    output = capsys.readouterr()
    assert error.value.code == 2 and output.out == "" and output.err == "Invalid local client command\n"


@pytest.mark.parametrize("tool,args", [("sendMessage", {"text": "raw send"}), ("messages.send", {}),
    ("send_draft", {"draft_id": DRAFT_ID, "text": "replacement"}),
    ("send_draft", {"draft_id": DRAFT_ID, "chat_id": -1001}),
    ("send_draft", {"draft_id": "A" * 32}), ("send_draft", {"draft_id": True}),
    ("send_draft", {}), ("send_draft", [])])
def test_low_level_client_rejects_arbitrary_rpc_or_send_arguments_before_http(monkeypatch, tool, args):
    monkeypatch.setattr(client_module.httpx, "Client", lambda **k: pytest.fail("invalid request started HTTP"))
    with pytest.raises(client_module.LocalClientError):
        client_module._call(tool, args, TOKEN)


@pytest.mark.parametrize("status", ["unknown", "failed", "sending", "unexpected"])
def test_unconfirmed_send_prints_redacted_result_and_never_retries(auth_file, monkeypatch, capsys, status):
    calls = []
    def handler(request):
        calls.append(request)
        return success({"status": status, "receipt": {"echo": TOKEN}})
    options = mock_client(monkeypatch, handler)
    assert client_module.main(["--auth-file", str(auth_file), "send-draft", "--draft-id", DRAFT_ID]) == 1
    output = capsys.readouterr()
    assert json.loads(output.out) == {"status": status, "receipt": {"echo": "[REDACTED]"}}
    expected = {"failed": "Gateway rejected the draft; no successful delivery was recorded. Do not automatically retry.\n",
                "unknown": "Draft delivery outcome is unknown; do not automatically retry.\n"}.get(status,
                "Draft delivery is not confirmed; do not automatically retry.\n")
    assert output.err == expected
    assert len(calls) == len(options) == 1


@pytest.mark.parametrize("command", ["create-draft", "send-draft"])
def test_uncertain_network_result_has_one_attempt_and_static_no_retry_warning(auth_file, monkeypatch, capsys, command):
    calls = []
    def handler(request):
        calls.append(request)
        raise httpx.ReadTimeout("synthetic uncertain " + TOKEN, request=request)
    options = mock_client(monkeypatch, handler)
    args = ["--draft-id", DRAFT_ID] if command == "send-draft" else ["--chat-id", "-1001", "--unthreaded", "--text", "fake"]
    assert client_module.main(["--auth-file", str(auth_file), command, *args]) == 1
    output = capsys.readouterr()
    assert output.out == "" and TOKEN not in output.err
    assert "do not automatically retry" in output.err.lower()
    if command == "create-draft":
        assert "different drafts" in output.err
    assert len(calls) == len(options) == 1


@pytest.mark.parametrize("reply_id", [1, 2147483647])
def test_create_draft_optional_reply_preserves_exact_message_chain(auth_file, monkeypatch, capsys, reply_id):
    calls = []
    def handler(request):
        calls.append(request)
        params = json.loads(request.content)["params"]
        assert params["name"] == "create_draft"
        assert params["arguments"] == {"chat_id": -1001, "topic_id": 7, "text": "fake reply", "reply_to_message_id": reply_id}
        return success({"status": "pending-owner-approval", "draft": {"draft_id": DRAFT_ID}})
    mock_client(monkeypatch, handler)
    assert client_module.main(["--auth-file", str(auth_file), "create-draft", "--chat-id", "-1001", "--topic-id", "7",
                               "--text", "fake reply", "--reply-to-message-id", str(reply_id)]) == 0
    output = capsys.readouterr()
    assert json.loads(output.out)["status"] == "pending-owner-approval" and output.err == "" and len(calls) == 1


@pytest.mark.parametrize("reply_id", ["0", "-1", "2147483648", "true", "False", "1.0", TOKEN])
def test_bad_reply_id_does_not_read_auth_or_echo_values(monkeypatch, capsys, reply_id):
    monkeypatch.setattr(client_module, "_load_bearer", lambda *a: pytest.fail("invalid reply read credential"))
    with pytest.raises(SystemExit) as error:
        client_module.main(["--auth-file", "unused", "create-draft", "--chat-id", "-1001", "--unthreaded",
                            "--text", "fake", "--reply-to-message-id", reply_id])
    output = capsys.readouterr()
    assert error.value.code == 2 and output.out == "" and output.err == "Invalid local client command\n"


@pytest.mark.parametrize("command,tool,args", [
    (["status"], "status", {}),
    (["search-history", "--chat-id", "-1001", "--unthreaded", "--query", "literal fake"],
     "search_history", {"chat_id": -1001, "topic_id": None, "query": "literal fake", "limit": 20}),
    (["search-history", "--chat-id", "-1001", "--topic-id", "7", "--query", "$(fake); 'literal'", "--limit", "3"],
     "search_history", {"chat_id": -1001, "topic_id": 7, "query": "$(fake); 'literal'", "limit": 3}),
    (["search-history", "--chat-id", "-1001", "--all-topics", "--query", "x" * 200, "--limit", "100"],
     "search_history", {"chat_id": -1001, "topic_id": None, "query": "x" * 200, "limit": 100, "all_topics": True}),
    (["ack-event", "--event-id", "1"], "ack_event", {"event_id": 1}),
    (["ack-event", "--event-id", str(2**63 - 1)], "ack_event", {"event_id": 2**63 - 1}),
])
def test_status_search_and_ack_call_only_existing_server_tools(auth_file, monkeypatch, capsys, command, tool, args):
    requests = []
    def handler(request):
        requests.append(request)
        assert request.method == "POST" and str(request.url) == client_module.ENDPOINT
        assert request.headers["Authorization"] == "Bearer " + TOKEN
        assert request.headers["Mcp-Name"] == tool
        params = json.loads(request.content)["params"]
        assert params["name"] == tool and params["arguments"] == args
        assert TOKEN not in request.content.decode()
        return success({"acknowledged": True, "echo": TOKEN} if tool == "ack_event" else {"fixture": "safe", "echo": TOKEN})
    options = mock_client(monkeypatch, handler)
    assert client_module.main(["--auth-file", str(auth_file), *command]) == 0
    output = capsys.readouterr()
    assert json.loads(output.out)["echo"] == "[REDACTED]" and output.err == ""
    assert len(requests) == len(options) == 1


@pytest.mark.parametrize("command", [
    ["search-history", "--chat-id", "-1001", "--query", "fake"],
    ["search-history", "--chat-id", "-1001", "--unthreaded"],
    ["search-history", "--chat-id", "-1001", "--all-topics", "--query", ""],
    ["search-history", "--chat-id", "-1001", "--all-topics", "--query", "x" * 201],
    ["search-history", "--chat-id", "-1001", "--all-topics", "--query", "\x00"],
    ["search-history", "--chat-id", "-1001", "--all-topics", "--query", "fake", "--limit", "101"],
    ["search-history", "--chat-id", "1", "--unthreaded", "--query", "fake"],
    ["search-history", "--chat-id", "-1001", "--topic-id", "0", "--query", "fake"],
    ["search-history", "--chat-id", "-1001", "--unthreaded", "--all-topics", "--query", "fake"],
    ["ack-event"], ["ack-event", "--event-id", "0"], ["ack-event", "--event-id", "-1"],
    ["ack-event", "--event-id", str(2**63)], ["ack-event", "--event-id", "True"],
    ["ack-event", "--event-id", TOKEN], ["ack-event", "--event-id", "1", "--chat-id", "-1001"],
    ["ack-event", "--event-id", "1", "--principal", TOKEN],
    ["status", "--reset-circuit", TOKEN], ["reset-circuit"],
])
def test_new_commands_reject_bad_args_without_auth_read_or_sensitive_output(monkeypatch, capsys, command):
    monkeypatch.setattr(client_module, "_load_bearer", lambda *a: pytest.fail("invalid arguments read credential"))
    with pytest.raises(SystemExit) as error:
        client_module.main(["--auth-file", "unused", *command])
    output = capsys.readouterr()
    assert error.value.code == 2 and output.out == "" and output.err == "Invalid local client command\n"


@pytest.mark.parametrize("args", [{}, [], {"event_id": True}, {"event_id": "1"}, {"event_id": 0},
                                  {"event_id": 2**63}, {"event_id": 1, "principal": "other"}])
def test_low_level_ack_rejects_invalid_reference_before_http(monkeypatch, args):
    monkeypatch.setattr(client_module.httpx, "Client", lambda **k: pytest.fail("invalid ACK started HTTP"))
    with pytest.raises(client_module.LocalClientError):
        client_module._call("ack_event", args, TOKEN)


@pytest.mark.parametrize("command", [["status"], ["ack-event", "--event-id", "7"],
    ["search-history", "--chat-id", "-1001", "--all-topics", "--query", "fake"]])
def test_new_commands_have_no_automatic_retry_on_unknown_network_result(auth_file, monkeypatch, capsys, command):
    requests = []
    def handler(request):
        requests.append(request)
        raise httpx.ReadTimeout("synthetic timeout " + TOKEN, request=request)
    options = mock_client(monkeypatch, handler)
    assert client_module.main(["--auth-file", str(auth_file), *command]) == 1
    output = capsys.readouterr()
    assert output.out == "" and output.err == "Local gateway command failed\n"
    assert len(requests) == len(options) == 1



@pytest.mark.parametrize("encoding", ["cp1251", "cp866", "ascii"])
@pytest.mark.parametrize("command", ["create-draft", "send-draft", "read-history"])
def test_unicode_result_survives_legacy_stdout_without_false_failure_or_retry(
        auth_file, monkeypatch, capsys, encoding, command):
    import io

    calls = []
    result = {"status": "sent" if command == "send-draft" else "pending-scoped-send",
              "draft": {"draft_id": DRAFT_ID, "text": "\u041f\u0440\u0438\u0432\u0435\u0442 \u2192 \U0001f44b"},
              "receipt": {"message_id": 123}, "echo": TOKEN}
    def handler(request):
        calls.append(request)
        return success(result)
    mock_client(monkeypatch, handler)
    raw = io.BytesIO()
    output = io.TextIOWrapper(raw, encoding=encoding, errors="strict")
    monkeypatch.setattr(client_module.sys, "stdout", output)
    arguments = ["--chat-id", "-1001", "--unthreaded"]
    if command == "create-draft":
        arguments += ["--text", "synthetic draft"]
    elif command == "send-draft":
        arguments = ["--draft-id", DRAFT_ID]
    code = client_module.main(["--auth-file", str(auth_file), command, *arguments])
    output.flush()
    emitted = raw.getvalue().decode(encoding)
    assert code == 0 and len(calls) == 1
    assert json.loads(emitted) == {**result, "echo": "[REDACTED]"}
    assert TOKEN not in emitted and capsys.readouterr().err == ""
