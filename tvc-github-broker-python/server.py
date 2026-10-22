"""The same application runs under Python, OCI, or the packaged pivot executable."""

import asyncio
import logging
import os
import secrets
from contextlib import asynccontextmanager
from typing import Annotated, Literal

import httpx
import uvicorn
from mcp.server import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from broker import GitHubBroker, TokenGrant, TokenRequest


class Settings(BaseModel):
    GITHUB_APP_ID: str = Field(min_length=1)
    GITHUB_REPOSITORY: str = Field(pattern=r"^[\w.-]+/[\w.-]+$")
    GITHUB_PRIVATE_KEY: str = Field(min_length=1)
    BROKER_TOKEN: str = Field(min_length=32)
    HOST: str = "127.0.0.1"
    PORT: int = Field(default=3000, ge=1, le=65535)
    PUBLIC_HOST: str = "localhost"


def create_app(broker: GitHubBroker, bearer_token: str, hostname: str = "localhost"):
    async def cleanup(stop: asyncio.Event):
        while not stop.is_set():
            await broker.revoke_expired()
            try:
                await asyncio.wait_for(stop.wait(), timeout=1)
            except TimeoutError:
                pass

    @asynccontextmanager
    async def lifespan(_):
        stop = asyncio.Event()
        task = asyncio.create_task(cleanup(stop))
        try:
            yield
        finally:
            stop.set()
            await task
            await broker.revoke_expired(all_tokens=True)
            await broker.client.aclose()

    mcp = MCPServer("tvc-github-broker", version="1.0.0", lifespan=lifespan)

    @mcp.tool()
    async def issue_token(
        access: Literal["read", "write"] = "read",
        ttl_seconds: Annotated[int, Field(ge=1, le=3600, strict=True)] = 900,
    ) -> TokenGrant:
        """Issue a fresh GitHub token for the configured repository.

        'write' allows reading and writing contents. expires_at is the broker's
        revocation deadline; github_expires_at is GitHub's hard expiry.
        """
        try:
            return await broker.issue(TokenRequest(access=access, ttl_seconds=ttl_seconds))
        except Exception:
            # Do not expose HTTP bodies, private keys, or minted tokens in errors.
            raise ValueError("Unable to issue a GitHub token. Check the App installation and permissions.") from None

    @mcp.custom_route("/health", methods=["GET"])
    async def health(_: Request) -> Response:
        return JSONResponse({"status": "ok"})

    async def authenticate(request: Request, call_next):
        if request.url.path == "/mcp":
            # Here's where you could use OAuth to authenticate agents, using the
            # SDK's token verifier and a real identity provider. This demo shares a key.
            supplied = request.headers.get("authorization", "").encode()
            if not secrets.compare_digest(supplied, f"Bearer {bearer_token}".encode()):
                return Response(status_code=401, headers={"WWW-Authenticate": "Bearer"})
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        return response

    app = mcp.streamable_http_app(
        stateless_http=True, json_response=True,
        transport_security=TransportSecuritySettings(
            allowed_hosts=[hostname, f"{hostname}:*", "localhost:*", "127.0.0.1:*"],
            allowed_origins=[f"https://{hostname}", "http://localhost:*", "http://127.0.0.1:*"],
        ),
    )
    app.add_middleware(BaseHTTPMiddleware, dispatch=authenticate)
    return app


def main():
    try:
        settings = Settings.model_validate(dict(os.environ))
        client = httpx.AsyncClient(timeout=10, follow_redirects=False)
        broker = GitHubBroker(settings.GITHUB_APP_ID, settings.GITHUB_REPOSITORY, settings.GITHUB_PRIVATE_KEY, client)
        app = create_app(broker, settings.BROKER_TOKEN, settings.PUBLIC_HOST)
    except Exception:
        raise SystemExit("Startup failed. Check the required environment variables and RSA private key.") from None

    # Access logs are unnecessary for a credential broker; never log tool results.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    uvicorn.run(app, host=settings.HOST, port=settings.PORT, access_log=False, loop="asyncio", http="h11")


if __name__ == "__main__":
    main()
