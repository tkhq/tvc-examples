import { NextRequest, NextResponse } from "next/server";
import { eq, and } from "drizzle-orm";
import { screenAddress } from "@/lib/tvc";
import { turnkey } from "@/lib/turnkey";
import { db } from "@/db";
import { userWallets, screenings } from "@/db/schema";

export async function POST(req: NextRequest) {
  const { address, orgId, userId } = await req.json();

  if (!address || typeof address !== "string") {
    return NextResponse.json({ error: "address is required" }, { status: 400 });
  }
  if (!orgId || typeof orgId !== "string") {
    return NextResponse.json({ error: "orgId is required" }, { status: 400 });
  }
  if (!userId || typeof userId !== "string") {
    return NextResponse.json({ error: "userId is required" }, { status: 400 });
  }

  const trimmedAddress = address.trim();

  // Find or create the user wallet record for this (org, address) pair.
  let [wallet] = await db
    .select()
    .from(userWallets)
    .where(and(eq(userWallets.orgId, orgId), eq(userWallets.address, trimmedAddress)))
    .limit(1);

  if (!wallet) {
    const newWallet = { id: crypto.randomUUID(), orgId, userId, address: trimmedAddress };
    await db.insert(userWallets).values(newWallet);
    wallet = { ...newWallet, createdAt: new Date().toISOString() };
  }

  // Run the sanctions check via the TVC app (inside the Nitro enclave).
  const screening = await screenAddress(trimmedAddress);

  // Fetch the latest boot proof from Turnkey.
  // The boot proof cryptographically attests that:
  //   1. The enclave is a real AWS Nitro Enclave (via awsAttestationDocB64)
  //   2. It's running exactly the binary described in the QOS manifest
  let bootProofData: object | null = null;
  try {
    const { bootProof } = await turnkey.apiClient().getLatestBootProof({
      organizationId: process.env.TURNKEY_ORG_ID!,
      appId: process.env.TVC_APP_ID!,
    });
    if (bootProof) {
      bootProofData = {
        deploymentLabel: bootProof.deploymentLabel ?? null,
        enclaveApp: bootProof.enclaveApp ?? null,
        owner: bootProof.owner ?? null,
        checkedAt: new Date().toISOString(),
      };
    }
  } catch (err) {
    // Boot proof is best-effort — don't fail the screening if it's unavailable.
    console.warn("[screen] boot proof fetch failed:", err);
  }

  // Persist to the audit log.
  await db.insert(screenings).values({
    id: crypto.randomUUID(),
    userWalletId: wallet.id,
    destinationAddress: screening.address,
    sanctioned: screening.sanctioned,
    identifications: JSON.stringify(screening.identifications),
    bootProof: bootProofData ? JSON.stringify(bootProofData) : null,
  });

  return NextResponse.json({
    address: screening.address,
    sanctioned: screening.sanctioned,
    identifications: screening.identifications,
    proof: bootProofData,
  });
}

// Return the screening history for a user's org.
export async function GET(req: NextRequest) {
  const orgId = req.nextUrl.searchParams.get("orgId");

  if (!orgId) {
    return NextResponse.json({ screenings: [] });
  }

  const history = await db
    .select({
      id: screenings.id,
      address: screenings.destinationAddress,
      sanctioned: screenings.sanctioned,
      identifications: screenings.identifications,
      bootProof: screenings.bootProof,
      createdAt: screenings.createdAt,
    })
    .from(screenings)
    .innerJoin(userWallets, eq(screenings.userWalletId, userWallets.id))
    .where(eq(userWallets.orgId, orgId))
    .orderBy(screenings.createdAt)
    .limit(50);

  return NextResponse.json({
    screenings: history.map((s) => ({
      ...s,
      identifications: JSON.parse(s.identifications),
      bootProof: s.bootProof ? JSON.parse(s.bootProof) : null,
    })),
  });
}
