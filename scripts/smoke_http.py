"""Show the four tool results from the already running local FAKE endpoint."""

import asyncio
import json

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


async def main():
    async with streamable_http_client("http://127.0.0.1:8765/mcp") as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            print("TOOLS:", ", ".join(t.name for t in (await session.list_tools()).tools))
            for name, arguments in [
                ("ping", {}),
                ("list_allowed_chats", {}),
                ("read_messages", {"chat_id": 100000001, "limit": 2}),
                ("search_messages", {"chat_id": 100000001, "query": "MCP", "limit": 2}),
                ("read_messages", {"chat_id": 100000002, "limit": 1}),
            ]:
                result = await session.call_tool(name, arguments)
                print(name, json.dumps(result.model_dump(mode="json", exclude_none=True), ensure_ascii=False))


if __name__ == "__main__":
    asyncio.run(main())
