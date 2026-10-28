import "server-only";
import { and, desc, eq } from "drizzle-orm";
import { audit } from "./audit";
import { hashToken, randomPrefixed } from "./crypto";
import { getDb } from "./db";
import { HttpError } from "./errors";
import { consumeRateLimit } from "./rate-limit";
import { agentToken, user } from "./schema";
import type { Actor } from "./types";

function iso(value: Date | string | null) {
  if (!value) return null;
  return new Date(value).toISOString();
}

export async function createAgentToken(actor: Actor, name: string, request?: Request) {
  await consumeRateLimit(`agent-token:${actor.id}`, 10, 60 * 60);
  const token = randomPrefixed("llv");
  const id = crypto.randomUUID();
  const prefix = token.slice(0, 12);
  const db = await getDb();
  await db.insert(agentToken).values({
    id,
    userId: actor.id,
    name,
    tokenHash: hashToken(token),
    tokenPrefix: prefix,
    createdAt: new Date(),
  });
  await audit({
    actorId: actor.id,
    action: "agent_token.create",
    resourceType: "agent_token",
    resourceId: id,
    metadata: { prefix, name },
    request,
  });
  return { id, name, prefix, token };
}

export async function listAgentTokens(actor: Actor) {
  const db = await getDb();
  const rows = await db
    .select({
      id: agentToken.id,
      name: agentToken.name,
      prefix: agentToken.tokenPrefix,
      revokedAt: agentToken.revokedAt,
      createdAt: agentToken.createdAt,
      lastUsedAt: agentToken.lastUsedAt,
    })
    .from(agentToken)
    .where(eq(agentToken.userId, actor.id))
    .orderBy(desc(agentToken.createdAt));
  return rows.map((row) => ({
    ...row,
    revokedAt: iso(row.revokedAt),
    createdAt: iso(row.createdAt),
    lastUsedAt: iso(row.lastUsedAt),
  }));
}

export async function revokeAgentToken(actor: Actor, tokenId: string, request?: Request) {
  const db = await getDb();
  const [row] = await db
    .select()
    .from(agentToken)
    .where(and(eq(agentToken.id, tokenId), eq(agentToken.userId, actor.id)))
    .limit(1);
  if (!row) throw new HttpError(404, "Token no encontrado");
  if (!row.revokedAt) {
    await db.update(agentToken).set({ revokedAt: new Date() }).where(eq(agentToken.id, tokenId));
  }
  await audit({
    actorId: actor.id,
    action: "agent_token.revoke",
    resourceType: "agent_token",
    resourceId: tokenId,
    metadata: { prefix: row.tokenPrefix },
    request,
  });
}

export async function actorFromBearer(header: string | null) {
  const value = header?.trim() ?? "";
  if (!value.startsWith("Bearer llv_")) throw new HttpError(401, "Token inválido");
  const token = value.slice("Bearer ".length).trim();
  const db = await getDb();
  const [row] = await db
    .select({
      id: agentToken.id,
      revokedAt: agentToken.revokedAt,
      userId: user.id,
      email: user.email,
      name: user.name,
    })
    .from(agentToken)
    .innerJoin(user, eq(user.id, agentToken.userId))
    .where(eq(agentToken.tokenHash, hashToken(token)))
    .limit(1);
  if (!row || row.revokedAt) throw new HttpError(401, "Token inválido");
  await db.update(agentToken).set({ lastUsedAt: new Date() }).where(eq(agentToken.id, row.id));
  const actor: Actor = { id: row.userId, email: row.email.toLowerCase(), name: row.name };
  return { actor, tokenId: row.id };
}
