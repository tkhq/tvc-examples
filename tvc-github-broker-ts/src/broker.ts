import { createPrivateKey, type KeyObject } from "node:crypto";
import { SignJWT } from "jose";
import * as z from "zod/v4";

export const requestSchema = z.object({
  access: z.enum(["read", "write"]).default("read"),
  ttl_seconds: z.number().int().min(1).max(3600).default(900),
});

export const configSchema = z.object({
  GITHUB_APP_ID: z.string().min(1),
  GITHUB_REPOSITORY: z.string().regex(/^[\w.-]+\/[\w.-]+$/),
  GITHUB_PRIVATE_KEY: z.string().min(1),
});

type Lease = { token: string; deadline: number; nativeDeadline: number };

export class GitHubBroker {
  private readonly key: KeyObject;
  private readonly leases = new Set<Lease>();

  constructor(
    private readonly config: z.infer<typeof configSchema>,
    private readonly request: typeof fetch = fetch,
  ) {
    // GitHub downloads PKCS#1 PEM keys; Node also accepts PKCS#8 here.
    this.key = createPrivateKey(config.GITHUB_PRIVATE_KEY.replaceAll("\\n", "\n"));
  }

  async issue(input: z.input<typeof requestSchema>) {
    const { access, ttl_seconds } = requestSchema.parse(input);
    // Here's where you could use something like Rego for a more robust policy
    // framework: authorize the authenticated agent's access level and TTL.
    const now = Math.floor(Date.now() / 1000);
    const jwt = await new SignJWT({})
      .setProtectedHeader({ alg: "RS256" })
      .setIssuer(this.config.GITHUB_APP_ID)
      .setIssuedAt(now - 60)
      .setExpirationTime(now + 540)
      .sign(this.key);
    const headers = {
      Authorization: `Bearer ${jwt}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2026-03-10",
      "User-Agent": "tvc-github-broker",
      "Content-Type": "application/json",
    };
    // Resolve from owner/repo, so a misconfigured installation cannot silently
    // grant access to a same-named repository belonging to somebody else.
    const installationResponse = await this.request(
      `https://api.github.com/repos/${this.config.GITHUB_REPOSITORY}/installation`,
      { headers, signal: AbortSignal.timeout(10_000) },
    );
    if (!installationResponse.ok) throw new Error("GitHub App is not installed on this repository.");
    const installation = z.object({ id: z.number().int().positive() }).parse(await installationResponse.json());

    const response = await this.request(
      `https://api.github.com/app/installations/${installation.id}/access_tokens`,
      {
        method: "POST",
        headers,
        // Installation ID fixes the owner; repository name narrows it to one repo.
        body: JSON.stringify({
          repositories: [this.config.GITHUB_REPOSITORY.split("/")[1]],
          permissions: { contents: access, metadata: "read" },
        }),
        signal: AbortSignal.timeout(10_000),
      },
    );

    if (response.status !== 201) {
      // Never echo GitHub response bodies or credentials into MCP errors/logs.
      throw new Error(`GitHub token creation failed (HTTP ${response.status}).`);
    }

    const issued = z.object({
      token: z.string().min(1),
      expires_at: z.iso.datetime(),
    }).parse(await response.json());
    const nativeDeadline = Date.parse(issued.expires_at);
    const deadline = Math.min(Date.now() + ttl_seconds * 1000, nativeDeadline);
    this.leases.add({ token: issued.token, deadline, nativeDeadline });

    return {
      token: issued.token,
      repository: this.config.GITHUB_REPOSITORY,
      access,
      expires_at: new Date(deadline).toISOString(),
      github_expires_at: issued.expires_at,
    };
  }

  async revokeExpired(all = false) {
    for (const lease of this.leases) {
      if (Date.now() >= lease.nativeDeadline) {
        this.leases.delete(lease);
        continue;
      }
      if (!all && Date.now() < lease.deadline) continue;

      try {
        const response = await this.request("https://api.github.com/installation/token", {
          method: "DELETE",
          headers: {
            Authorization: `Bearer ${lease.token}`,
            Accept: "application/vnd.github+json",
            "X-GitHub-Api-Version": "2026-03-10",
            "User-Agent": "tvc-github-broker",
          },
          signal: AbortSignal.timeout(10_000),
        });

        // 401 means the token is already invalid. Other failures stay queued.
        if (response.status !== 204 && response.status !== 401) {
          throw new Error(`HTTP ${response.status}`);
        }
        this.leases.delete(lease);
      } catch {
        console.error("GitHub revocation failed; will retry. Native expiry still applies.");
      }
    }
  }
}
