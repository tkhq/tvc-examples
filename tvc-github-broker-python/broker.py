"""GitHub token issuance and revocation, independent of MCP and packaging."""

import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal

import httpx
import jwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from pydantic import BaseModel, Field


class TokenRequest(BaseModel):
    access: Literal["read", "write"] = "read"
    ttl_seconds: int = Field(default=900, ge=1, le=3600, strict=True)


class TokenGrant(BaseModel):
    token: str
    repository: str
    access: Literal["read", "write"]
    expires_at: str
    github_expires_at: str


@dataclass
class Lease:
    token: str
    deadline: float
    native_deadline: float


class GitHubBroker:
    def __init__(self, app_id: str, repository: str, private_key: str, client: httpx.AsyncClient):
        self.app_id = app_id
        self.repository = repository
        self.key = load_pem_private_key(private_key.replace("\\n", "\n").encode(), password=None)
        self.client = client
        self.leases: list[Lease] = []

    async def issue(self, request: TokenRequest) -> TokenGrant:
        # Here's where you could use something like Rego for a more robust policy
        # framework: authorize the authenticated agent's access level and TTL.
        now = int(time.time())
        app_jwt = jwt.encode(
            {"iss": self.app_id, "iat": now - 60, "exp": now + 540},
            self.key,
            algorithm="RS256",
        )
        headers = {
            "Authorization": f"Bearer {app_jwt}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2026-03-10",
            "User-Agent": "tvc-github-broker",
        }
        # Resolve from owner/repo rather than trusting an unrelated installation ID.
        installation = await self.client.get(
            f"https://api.github.com/repos/{self.repository}/installation", headers=headers,
        )
        if installation.status_code != 200:
            raise RuntimeError("GitHub App is not installed on this repository.")

        installation_id = installation.json()["id"]
        response = await self.client.post(
            f"https://api.github.com/app/installations/{installation_id}/access_tokens",
            headers=headers,
            json={
                "repositories": [self.repository.split("/")[1]],
                "permissions": {"contents": request.access, "metadata": "read"},
            },
        )
        if response.status_code != 201:
            # Never echo GitHub response bodies or credentials into MCP errors/logs.
            raise RuntimeError(f"GitHub token creation failed (HTTP {response.status_code}).")

        issued = response.json()
        native_deadline = datetime.fromisoformat(issued["expires_at"]).timestamp()
        deadline = min(time.time() + request.ttl_seconds, native_deadline)
        self.leases.append(Lease(issued["token"], deadline, native_deadline))
        return TokenGrant(
            token=issued["token"], repository=self.repository, access=request.access,
            expires_at=datetime.fromtimestamp(deadline, timezone.utc).isoformat(),
            github_expires_at=issued["expires_at"],
        )

    async def revoke_expired(self, all_tokens: bool = False) -> None:
        for lease in list(self.leases):
            if time.time() >= lease.native_deadline:
                self.leases.remove(lease)
                continue
            if not all_tokens and time.time() < lease.deadline:
                continue

            try:
                response = await self.client.delete(
                    "https://api.github.com/installation/token",
                    headers={
                        "Authorization": f"Bearer {lease.token}",
                        "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2026-03-10",
                        "User-Agent": "tvc-github-broker",
                    },
                )
                # 401 means the token is already invalid. Other failures stay queued.
                if response.status_code not in (204, 401):
                    raise RuntimeError("GitHub revocation failed")
                self.leases.remove(lease)
            except (httpx.HTTPError, RuntimeError):
                logging.warning("GitHub revocation failed; will retry. Native expiry still applies.")
