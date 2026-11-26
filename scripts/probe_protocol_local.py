"""Exercise the existing MCP HTTP binding in-process, with fake data only.

No listener, tunnel, credential loading, Telegram or external HTTP is used.
This diagnoses our server contract, not the protocol used by a Grok client.
"""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import tempfile

import httpx

from telegram_gateway.http_server import VERSION, create_app
from telegram_gateway.protocol import CAPABILITIES_KEY, VERSION_KEY
from telegram_gateway.runtime import Runtime
from telegram_gateway.runtime_config import RuntimeConfig


async def probe(state_dir: Path):
    cfg = RuntimeConfig.from_dict({
        "version": 1, "mode": "fake", "state_dir": str(state_dir),
        "network_enabled": False, "outbound_enabled": False,
        "auth": {"mode": "fake", "credentials": {"fixture-protocol-only": "diagnostic"}},
        "policy": {"principals": {"diagnostic": []}},
    })
    runtime = Runtime(cfg)
    await runtime.start()
    try:
        app = create_app(runtime.protocol, runtime.auth, resource_metadata=None,
                         metadata_url="http://127.0.0.1/.well-known/oauth-protected-resource",
                         allowed_hosts={"127.0.0.1"}, allowed_origins=set())
        results = []
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                    base_url="http://127.0.0.1", trust_env=False) as client:
            async def request(label, method="tools/list", *, version=VERSION,
                              authenticated=True, mirrored=True, name=None):
                headers = {"Content-Type": "application/json",
                           "Accept": "application/json, text/event-stream",
                           "MCP-Protocol-Version": version}
                if authenticated:
                    headers["Authorization"] = "Bearer fixture-protocol-only"
                if mirrored:
                    headers["MCP-Method"] = method
                params = {"_meta": {VERSION_KEY: version, CAPABILITIES_KEY: {}}}
                if name is not None:
                    headers["MCP-Name"] = name
                    params.update(name=name, arguments={})
                response = await client.post("/mcp", json={"jsonrpc":"2.0", "id":label,
                    "method":method, "params":params}, headers=headers)
                body = response.json()
                results.append({"case":label, "http_status":response.status_code,
                                "error_code":body.get("error", {}).get("code")})
            await request("unauthenticated", authenticated=False)
            await request("tools_list_mcp2")
            await request("ping_mcp2", "tools/call", name="ping")
            await request("initialize_method", "initialize")
            await request("other_version_rejected", version="2025-11-25")
            await request("missing_method_header", mirrored=False)
            response = await client.get("/mcp")
            results.append({"case":"get_stream", "http_status":response.status_code, "error_code":None})
        expected = [(401,-33001),(200,None),(200,None),(404,-32601),(400,-32022),(400,-32020),(405,None)]
        verified = [(r["http_status"],r["error_code"]) for r in results] == expected
        return {"verified":verified, "supported_protocol":VERSION,
                "initialize_supported":False, "get_sse_supported":False,
                "grok_compatibility_verified":False, "secrets_read":False,
                "external_network_used":False, "listener_started":False, "cases":results}
    finally:
        await runtime.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--temp-parent", type=Path, required=True,
                        help="Existing writable temporary directory outside the checkout")
    args=parser.parse_args()
    try:
        parent=args.temp_parent.resolve(strict=True)
        if not parent.is_dir():
            raise ValueError()
        temporary=tempfile.TemporaryDirectory(prefix="gateway-protocol-fake-",dir=parent)
        owned=Path(temporary.name).resolve(strict=True)
        if not owned.is_relative_to(parent) or owned.parent != parent:
            raise ValueError()
        try:
            result=asyncio.run(probe(owned/"state"))
        finally:
            # Delete only this diagnostic's fresh, verified child directory.
            if Path(temporary.name).resolve(strict=True) != owned:
                raise ValueError()
            temporary.cleanup()
    except Exception:
        print('{"verified":false,"status":"local_diagnostic_failed"}')
        return 1
    print(json.dumps(result,indent=2))
    return 0 if result["verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
