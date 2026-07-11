import { NextRequest, NextResponse } from "next/server";
import { eq } from "drizzle-orm";
import { screenAddress } from "@/lib/tvc";
import { turnkey } from "@/lib/turnkey";
import { db } from "@/db";
import { users, transactions, screenings } from "@/db/schema";

// Request/response shapes for the Turnkey get_boot_proof query.
type GetBootProofRequest = { organizationId: string; ephemeralKey: string };
type GetBootProofResponse = { bootProof: Record<string, unknown> };

export async function POST(req: NextRequest) {
  const { address, orgId, userId, walletAddress, walletId, valueWei, chainId } =
    await req.json();

  if (!address || typeof address !== "string")
    return NextResponse.json({ error: "address is required" }, { status: 400 });
  if (!orgId || typeof orgId !== "string")
    return NextResponse.json({ error: "orgId is required" }, { status: 400 });
  if (!userId || typeof userId !== "string")
    return NextResponse.json({ error: "userId is required" }, { status: 400 });
  if (!walletAddress || typeof walletAddress !== "string")
    return NextResponse.json({ error: "walletAddress is required" }, { status: 400 });

  const destinationAddress = address.trim();

  // Find or create the user record for this Turnkey sub-org.
  let [user] = await db
    .select()
    .from(users)
    .where(eq(users.turnkeySubOrgId, orgId))
    .limit(1);

  if (!user) {
    const newUser = {
      id: crypto.randomUUID(),
      turnkeyUserId: userId,
      turnkeySubOrgId: orgId,
      turnkeyWalletId: walletId ?? userId,
      walletAddress,
    };
    await db.insert(users).values(newUser);
    user = { ...newUser, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() };
  }

  // Create the transaction intent before screening — it exists regardless of outcome.
  const txId = crypto.randomUUID();
  await db.insert(transactions).values({
    id: txId,
    userId: user.id,
    fromAddress: walletAddress,
    toAddress: destinationAddress,
    valueWei: valueWei ?? "0x0",
    data: "0x",
    chainId: chainId ?? parseInt(process.env.NEXT_PUBLIC_CHAIN_ID ?? "11155111"),
    status: "pending",
  });

  // Run the sanctions check via the TVC app (inside the Nitro enclave).
  const screening = await screenAddress(destinationAddress);
  const outcome = screening.isSanctioned ? "blocked" : "allowed";

  console.log("OUTCOME ➡️", outcome);

  // Fetch the boot proof for the exact replica that signed the app proof.
  let bootProof: Record<string, unknown> | null = null;
  if (screening.bootEphemeralKey) {
    try {
      const resp = await turnkey
        .apiClient()
        .request<GetBootProofRequest, GetBootProofResponse>(
          "/public/v1/query/get_boot_proof",
          {
            organizationId: process.env.TURNKEY_ORG_ID!,
            ephemeralKey: screening.bootEphemeralKey,
          },
        );
      bootProof = resp.bootProof;
    } catch (err) {
      console.error("Failed to fetch boot proof:", err);
    }
  }

  // Persist the screening result with both proofs.
  await db.insert(screenings).values({
    id: crypto.randomUUID(),
    userId: user.id,
    transactionId: txId,
    address: destinationAddress,
    isSanctioned: screening.isSanctioned,
    identifications: JSON.stringify(screening.identifications),
    proofScheme: screening.appProof?.scheme ?? null,
    proofPublicKey: screening.appProof?.publicKey ?? null,
    proofPayload: screening.appProof?.proofPayload ?? null,
    proofSignature: screening.appProof?.signature ?? null,
    bootProof: bootProof ? JSON.stringify(bootProof) : null,
    outcome,
  });

  // Reflect the screening outcome on the transaction.
  if (screening.isSanctioned) {
    await db
      .update(transactions)
      .set({ status: "blocked" })
      .where(eq(transactions.id, txId));
  }

  return NextResponse.json({
    address: screening.address,
    isSanctioned: screening.isSanctioned,
    identifications: screening.identifications,
    appProof: screening.appProof,
    bootProof,
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
      fromAddress: transactions.fromAddress,
      toAddress: transactions.toAddress,
      valueWei: transactions.valueWei,
      isSanctioned: screenings.isSanctioned,
      identifications: screenings.identifications,
      proofScheme: screenings.proofScheme,
      proofPublicKey: screenings.proofPublicKey,
      proofPayload: screenings.proofPayload,
      proofSignature: screenings.proofSignature,
      bootProof: screenings.bootProof,
      outcome: screenings.outcome,
      createdAt: screenings.createdAt,
    })
    .from(screenings)
    .innerJoin(transactions, eq(screenings.transactionId, transactions.id))
    .innerJoin(users, eq(screenings.userId, users.id))
    .where(eq(users.turnkeySubOrgId, orgId))
    .orderBy(screenings.createdAt)
    .limit(50);

  return NextResponse.json({
    screenings: history.map(
      ({ proofScheme, proofPublicKey, proofPayload, proofSignature, bootProof, identifications, ...rest }) => ({
        ...rest,
        identifications: JSON.parse(identifications),
        appProof:
          proofScheme && proofPublicKey && proofPayload && proofSignature
            ? { scheme: proofScheme, publicKey: proofPublicKey, proofPayload, signature: proofSignature }
            : null,
        bootProof: bootProof ? JSON.parse(bootProof) : null,
      })
    ),
  });
}
