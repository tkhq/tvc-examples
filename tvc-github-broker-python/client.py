"""Request a token with the official MCP v2 client."""

import argparse
import asyncio
import json
import os

import httpx2
from mcp.client import Client
from mcp.client.streamable_http import streamable_http_client


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("access", choices=["read", "write"], nargs="?", default="read")
    parser.add_argument("ttl_seconds", type=int, nargs="?", default=900)
    args = parser.parse_args()
    url = os.environ.get("MCP_URL", "http://127.0.0.1:3000/mcp")
    async with httpx2.AsyncClient(headers={"Authorization": f"Bearer {os.environ['BROKER_TOKEN']}"}) as http:
        async with Client(streamable_http_client(url, http_client=http), mode="2026-07-28") as client:
            result = await client.call_tool("issue_token", vars(args))
            if result.is_error:
                raise SystemExit("Broker could not issue the token")
            # This command intentionally prints a credential. Send stdout to a protected file.
            print(json.dumps(result.structured_content))


if __name__ == "__main__":
    asyncio.run(main())
