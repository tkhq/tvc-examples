/**
 * Turnkey client construction for the admin tool. The API key file is read by
 * this process only; key material is never printed.
 */
import fs from "node:fs";
import { Turnkey, type TurnkeyApiClient } from "@turnkey/sdk-server";

export const DEFAULT_API_BASE_URL = "https://api.turnkey.com";

/** Accept SDK-style (`publicKey`) and snake_case (`public_key`) key files. */
export function readApiKeyFile(file: string): { publicKey: string; privateKey: string } {
  const data = JSON.parse(fs.readFileSync(file, "utf8")) as Record<string, unknown>;
  const publicKey = data.publicKey ?? data.public_key;
  const privateKey = data.privateKey ?? data.private_key;
  if (typeof publicKey !== "string" || typeof privateKey !== "string" || !publicKey || !privateKey) {
    throw new Error(`API key file ${file} has no publicKey/privateKey`);
  }
  return { publicKey, privateKey };
}

export function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`missing env ${name}`);
  return v;
}

export function client(keyFile: string, organizationId: string, apiBaseUrl = DEFAULT_API_BASE_URL): TurnkeyApiClient {
  const k = readApiKeyFile(keyFile);
  return new Turnkey({
    apiBaseUrl,
    apiPublicKey: k.publicKey,
    apiPrivateKey: k.privateKey,
    defaultOrganizationId: organizationId,
  }).apiClient();
}
