import asyncio
import json
import socket
import time
from datetime import datetime, timezone

import httpx
import httpx2
import jwt
import pytest
import uvicorn
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from mcp.client import Client
from mcp.client.streamable_http import streamable_http_client
from pydantic import ValidationError

from broker import GitHubBroker, TokenRequest
from server import create_app


@pytest.fixture
def github():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()).decode()
    state = {"issued": 0, "deleted": [], "delete_status": 204, "lifetime": 3600, "fail_create": False}

    def respond(request):
        authorization = request.headers["Authorization"]
        if request.method == "DELETE":
            state["deleted"].append(authorization)
            return httpx.Response(state["delete_status"])
        payload = jwt.decode(authorization[7:], key.public_key(), algorithms=["RS256"], issuer="123")
        assert payload["exp"] - payload["iat"] <= 600
        if request.url.path.endswith("/installation"):
            assert request.url.path == "/repos/example/demo/installation"
            return httpx.Response(200, json={"id": 456})
        assert request.url.path == "/app/installations/456/access_tokens"
        body = json.loads(request.content)
        assert body["repositories"] == ["demo"]
        assert body["permissions"] in (
            {"contents": "read", "metadata": "read"},
            {"contents": "write", "metadata": "read"},
        )
        if state["fail_create"]:
            return httpx.Response(403, json={"secret": "do-not-leak"})
        state["issued"] += 1
        return httpx.Response(201, json={
            "token": f"fake-{state['issued']}",
            "expires_at": datetime.fromtimestamp(time.time() + state["lifetime"], timezone.utc).isoformat(),
        })

    client = httpx.AsyncClient(transport=httpx.MockTransport(respond), timeout=10)
    return state, GitHubBroker("123", "example/demo", pem, client)


async def test_lifecycle(github, monkeypatch):
    state, broker = github
    now = time.time()
    monkeypatch.setattr("broker.time.time", lambda: now)
    read = await broker.issue(TokenRequest(access="read", ttl_seconds=20))
    write = await broker.issue(TokenRequest(access="write", ttl_seconds=30))
    assert read.token != write.token
    assert datetime.fromisoformat(read.expires_at).timestamp() - now == pytest.approx(20)
    await broker.revoke_expired()
    assert state["deleted"] == []
    now += 20
    state["delete_status"] = 503
    await broker.revoke_expired()
    assert state["deleted"] == ["Bearer fake-1"]
    state["delete_status"] = 204
    await broker.revoke_expired()
    assert len(state["deleted"]) == 2
    await broker.revoke_expired(all_tokens=True)
    assert state["deleted"][-1] == "Bearer fake-2"
    state["lifetime"] = 5
    short = await broker.issue(TokenRequest(ttl_seconds=30))
    assert short.expires_at == short.github_expires_at
    now += 5
    count = len(state["deleted"])
    await broker.revoke_expired()
    assert len(state["deleted"]) == count
    assert broker.leases == []


@pytest.mark.parametrize("ttl", [0, -1, 3601, 1.5, True])
def test_invalid_ttl(ttl):
    with pytest.raises(ValidationError):
        TokenRequest(ttl_seconds=ttl)


async def test_mcp_http(github):
    state, broker = github
    secret = "test-broker-secret-32-characters-long"
    app = create_app(broker, secret)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, loop="asyncio", http="h11", log_level="error"))
    serving = asyncio.create_task(server.serve(sockets=[listener]))
    while not server.started:
        if serving.done():
            await serving
        await asyncio.sleep(0.01)
    url = f"http://127.0.0.1:{port}/mcp"
    try:
        async with httpx.AsyncClient() as probe:
            assert (await probe.get(url)).status_code == 401
            assert (await probe.get(f"http://127.0.0.1:{port}/health")).status_code == 200
            assert (await probe.get(url, headers={"Authorization": f"Bearer {secret}", "Origin": "https://evil.example"})).status_code == 403
        async with httpx2.AsyncClient(headers={"Authorization": f"Bearer {secret}"}) as http:
            async with Client(streamable_http_client(url, http_client=http), mode="2026-07-28") as client:
                tools = await client.list_tools()
                assert [tool.name for tool in tools.tools] == ["issue_token"]
                for invalid in ({"access": "admin"}, {"ttl_seconds": 3601}, {"ttl_seconds": 1.5}):
                    rejected = await client.call_tool("issue_token", invalid)
                    assert rejected.is_error
                assert state["issued"] == 0
                result = await client.call_tool("issue_token", {"access": "read", "ttl_seconds": 1})
                assert not result.is_error
                assert result.structured_content["token"] == "fake-1"
                for _ in range(30):
                    if state["deleted"]:
                        break
                    await asyncio.sleep(0.1)
                assert state["deleted"] == ["Bearer fake-1"]
                state["fail_create"] = True
                failure = await client.call_tool("issue_token", {})
                assert failure.is_error
                assert "do-not-leak" not in failure.model_dump_json()
                state["fail_create"] = False
                await client.call_tool("issue_token", {"access": "write"})
    finally:
        server.should_exit = True
        await serving
        listener.close()
    assert state["deleted"][-1] == "Bearer fake-2"
