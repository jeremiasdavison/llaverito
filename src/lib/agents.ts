import "server-only";
import { and, desc, eq } from "drizzle-orm";
import {
  AGENT_TOKEN_DEFAULT_TTL_DAYS,
  formatScopes,
  parseScopes,
  tokenExpiry,
  type AgentScope,
} from "./agent-scopes";
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

function present(row: {
  id: string;
  name: string;
  prefix: string;
  scopes: string;
  revokedAt: Date | null;
  createdAt: Date;
  lastUsedAt: Date | null;
  expiresAt: Date;
}) {
  const expiresAt = new Date(row.expiresAt);
  return {
    id: row.id,
    name: row.name,
    prefix: row.prefix,
    scopes: parseScopes(row.scopes),
    revokedAt: iso(row.revokedAt),
    createdAt: iso(row.createdAt),
    lastUsedAt: iso(row.lastUsedAt),
    expiresAt: expiresAt.toISOString(),
    expired: expiresAt.getTime() <= Date.now(),
  };
}

export async function createAgentToken(
  actor: Actor,
  input: { name: string; scopes?: AgentScope[]; ttlDays?: number },
  request?: Request,
) {
  await consumeRateLimit(`agent-token:${actor.id}`, 10, 60 * 60);
  const scopes = formatScopes(input.scopes?.length ? input.scopes : ["read", "request", "redeem"]);
  if (!scopes) throw new HttpError(400, "El token necesita al menos un permiso válido");
  const ttlDays = input.ttlDays ?? AGENT_TOKEN_DEFAULT_TTL_DAYS;
  const token = randomPrefixed("llv");
  const id = crypto.randomUUID();
  const prefix = token.slice(0, 12);
  const expiresAt = tokenExpiry(ttlDays);
  const db = await getDb();
  await db.insert(agentToken).values({
    id,
    userId: actor.id,
    name: input.name,
    tokenHash: hashToken(token),
    tokenPrefix: prefix,
    scopes,
    expiresAt,
    createdAt: new Date(),
  });
  await audit({
    actorId: actor.id,
    action: "agent_token.create",
    resourceType: "agent_token",
    resourceId: id,
    metadata: { prefix, name: input.name, scopes, ttlDays },
    request,
  });
  return { id, name: input.name, prefix, token, scopes: parseScopes(scopes), expiresAt: expiresAt.toISOString() };
}

export async function listAgentTokens(actor: Actor) {
  const db = await getDb();
  const rows = await db
    .select({
      id: agentToken.id,
      name: agentToken.name,
      prefix: agentToken.tokenPrefix,
      scopes: agentToken.scopes,
      revokedAt: agentToken.revokedAt,
      createdAt: agentToken.createdAt,
      lastUsedAt: agentToken.lastUsedAt,
      expiresAt: agentToken.expiresAt,
    })
    .from(agentToken)
    .where(eq(agentToken.userId, actor.id))
    .orderBy(desc(agentToken.createdAt));
  return rows.map((row) => present(row));
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

export async function rotateAgentToken(actor: Actor, tokenId: string, request?: Request) {
  await consumeRateLimit(`agent-token:${actor.id}`, 10, 60 * 60);
  const db = await getDb();
  const [row] = await db
    .select()
    .from(agentToken)
    .where(and(eq(agentToken.id, tokenId), eq(agentToken.userId, actor.id)))
    .limit(1);
  if (!row) throw new HttpError(404, "Token no encontrado");
  if (row.revokedAt) throw new HttpError(409, "El token ya está revocado");
  const scopes = parseScopes(row.scopes);
  if (scopes.length === 0) throw new HttpError(409, "El token no tiene permisos válidos");
  const token = randomPrefixed("llv");
  const id = crypto.randomUUID();
  const prefix = token.slice(0, 12);
  const expiresAt = tokenExpiry(AGENT_TOKEN_DEFAULT_TTL_DAYS);
  await db.insert(agentToken).values({
    id,
    userId: actor.id,
    name: row.name,
    tokenHash: hashToken(token),
    tokenPrefix: prefix,
    scopes: formatScopes(scopes),
    expiresAt,
    createdAt: new Date(),
  });
  await db.update(agentToken).set({ revokedAt: new Date() }).where(eq(agentToken.id, tokenId));
  await audit({
    actorId: actor.id,
    action: "agent_token.rotate",
    resourceType: "agent_token",
    resourceId: id,
    metadata: { prefix, name: row.name, scopes: formatScopes(scopes) },
    request,
  });
  return {
    id,
    name: row.name,
    prefix,
    token,
    scopes,
    expiresAt: expiresAt.toISOString(),
    replacedId: tokenId,
  };
}

export async function actorFromBearer(header: string | null, scope: AgentScope) {
  const value = header?.trim() ?? "";
  if (!value.startsWith("Bearer llv_")) throw new HttpError(401, "Token inválido");
  const token = value.slice("Bearer ".length).trim();
  const db = await getDb();
  const [row] = await db
    .select({
      id: agentToken.id,
      revokedAt: agentToken.revokedAt,
      expiresAt: agentToken.expiresAt,
      scopes: agentToken.scopes,
      userId: user.id,
      email: user.email,
      name: user.name,
    })
    .from(agentToken)
    .innerJoin(user, eq(user.id, agentToken.userId))
    .where(eq(agentToken.tokenHash, hashToken(token)))
    .limit(1);
  if (!row || row.revokedAt || row.expiresAt.getTime() <= Date.now()) throw new HttpError(401, "Token inválido");
  if (!parseScopes(row.scopes).includes(scope)) throw new HttpError(403, "El token no tiene ese permiso");
  await db.update(agentToken).set({ lastUsedAt: new Date() }).where(eq(agentToken.id, row.id));
  const actor: Actor = { id: row.userId, email: row.email.toLowerCase(), name: row.name };
  return { actor, tokenId: row.id };
}
