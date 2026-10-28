import "server-only";
import { and, desc, eq, inArray } from "drizzle-orm";
import { folderAccess, itemAccess } from "./access";
import { audit } from "./audit";
import {
  decryptString,
  encryptString,
  hashToken,
  parseWrapPublicKey,
  randomPrefixed,
  sealJson,
  type Envelope,
} from "./crypto";
import { getDb, getSql } from "./db";
import { HttpError } from "./errors";
import { canAdminister, canUse } from "./permissions";
import { consumeRateLimit } from "./rate-limit";
import { accessRequest, accessRequestItem, envBinding, item } from "./schema";
import type { Actor, ItemKind } from "./types";

const PENDING_MS = 24 * 60 * 60 * 1000;
const GRANT_MS = 120 * 1000;

function iso(value: Date | string | null) {
  if (!value) return null;
  return new Date(value).toISOString();
}

function wrapOrThrow(value: string) {
  try {
    return parseWrapPublicKey(value);
  } catch {
    throw new HttpError(400, "La clave pública de cierre debe ser X25519 de 32 bytes en base64url");
  }
}

async function insertRequest(input: {
  actor: Actor;
  agentTokenId: string | null;
  folderId: string | null;
  kind: "item" | "env_bundle";
  purpose: string;
  wrapPublicKey: string;
  itemIds: string[];
  request?: Request;
}) {
  const db = await getDb();
  const id = crypto.randomUUID();
  await db.insert(accessRequest).values({
    id,
    requesterUserId: input.actor.id,
    agentTokenId: input.agentTokenId,
    folderId: input.folderId,
    kind: input.kind,
    purpose: input.purpose,
    status: "pending",
    wrapPublicKey: input.wrapPublicKey,
    createdAt: new Date(),
  });
  if (input.itemIds.length) {
    await db.insert(accessRequestItem).values(
      input.itemIds.map((itemId) => ({ requestId: id, itemId })),
    );
  }
  await audit({
    actorId: input.actor.id,
    action: "request.create",
    resourceType: "request",
    resourceId: id,
    metadata: { kind: input.kind, itemCount: input.itemIds.length },
    request: input.request,
  });
  return {
    id,
    status: "pending" as const,
    grantId: null,
    expiresAt: null,
    confirmation: "Quedó pendiente. La aprobación no devuelve el secreto.",
  };
}

export async function createItemRequest(
  actor: Actor,
  input: { itemIds: string[]; purpose: string; wrapPublicKey: string },
  agentTokenId: string | null,
  request?: Request,
) {
  await consumeRateLimit(`request:${actor.id}`, 30, 60 * 60);
  const wrap = wrapOrThrow(input.wrapPublicKey);
  const ids = [...new Set(input.itemIds)];
  for (const itemId of ids) {
    const loaded = await itemAccess(actor, itemId);
    if (!canUse(loaded.access)) throw new HttpError(404, "Elemento no encontrado");
    if (loaded.item.revokedAt) throw new HttpError(409, "Hay un elemento revocado en la solicitud");
  }
  return insertRequest({
    actor,
    agentTokenId,
    folderId: null,
    kind: "item",
    purpose: input.purpose,
    wrapPublicKey: wrap.toString("base64url"),
    itemIds: ids,
    request,
  });
}

export async function createEnvRequest(
  actor: Actor,
  folderId: string,
  input: { purpose: string; wrapPublicKey: string; repository?: string },
  agentTokenId: string | null,
  request?: Request,
) {
  await consumeRateLimit(`request:${actor.id}`, 30, 60 * 60);
  const wrap = wrapOrThrow(input.wrapPublicKey);
  const loaded = await folderAccess(actor, folderId);
  if (!canUse(loaded.access)) throw new HttpError(404, "Carpeta no encontrada");
  if (loaded.folder.kind !== "project") throw new HttpError(400, "El entorno virtual es de carpetas de proyecto");
  if (loaded.folder.githubRepo && input.repository !== loaded.folder.githubRepo) {
    throw new HttpError(403, "El repositorio no coincide con la carpeta");
  }
  const db = await getDb();
  const bindings = await db
    .select({ itemId: envBinding.itemId, revokedAt: item.revokedAt })
    .from(envBinding)
    .innerJoin(item, eq(item.id, envBinding.itemId))
    .where(eq(envBinding.folderId, folderId));
  const active = bindings.filter((row) => !row.revokedAt);
  if (!active.length) throw new HttpError(400, "El proyecto no tiene variables activas");
  return insertRequest({
    actor,
    agentTokenId,
    folderId,
    kind: "env_bundle",
    purpose: input.purpose,
    wrapPublicKey: wrap.toString("base64url"),
    itemIds: [...new Set(active.map((row) => row.itemId))],
    request,
  });
}

async function namesFor(requestIds: string[]) {
  if (!requestIds.length) return new Map<string, { id: string; name: string; kind: ItemKind }[]>();
  const db = await getDb();
  const rows = await db
    .select({
      requestId: accessRequestItem.requestId,
      id: item.id,
      name: item.name,
      kind: item.kind,
    })
    .from(accessRequestItem)
    .innerJoin(item, eq(item.id, accessRequestItem.itemId))
    .where(inArray(accessRequestItem.requestId, requestIds));
  const grouped = new Map<string, { id: string; name: string; kind: ItemKind }[]>();
  for (const row of rows) {
    const list = grouped.get(row.requestId) ?? [];
    list.push({ id: row.id, name: row.name, kind: row.kind });
    grouped.set(row.requestId, list);
  }
  return grouped;
}

async function canDecide(actor: Actor, items: { id: string }[]) {
  if (!items.length) return false;
  try {
    for (const entry of items) {
      const loaded = await itemAccess(actor, entry.id);
      if (!canAdminister(loaded.access)) return false;
    }
    return true;
  } catch (error) {
    if (error instanceof HttpError) return false;
    throw error;
  }
}

export async function listRequests(actor: Actor) {
  const db = await getDb();
  const mine = await db
    .select()
    .from(accessRequest)
    .where(eq(accessRequest.requesterUserId, actor.id))
    .orderBy(desc(accessRequest.createdAt))
    .limit(40);
  const pending = await db
    .select()
    .from(accessRequest)
    .where(eq(accessRequest.status, "pending"))
    .orderBy(desc(accessRequest.createdAt))
    .limit(80);
  const merged = new Map(mine.map((row) => [row.id, row]));
  for (const row of pending) merged.set(row.id, row);
  const names = await namesFor([...merged.keys()]);
  const visible = [];
  for (const row of merged.values()) {
    const items = names.get(row.id) ?? [];
    const decide = row.status === "pending" && (await canDecide(actor, items));
    const own = row.requesterUserId === actor.id;
    if (!own && !decide) continue;
    visible.push({
      id: row.id,
      purpose: row.purpose,
      kind: row.kind,
      status: row.status,
      createdAt: iso(row.createdAt),
      expiresAt: iso(row.grantExpiresAt),
      grantId: null,
      canDecide: decide,
      canCancel: own && row.status === "pending",
      items,
      confirmation:
        row.status === "approved"
          ? "Aprobado. El grant vive del lado del agente y vence rápido."
          : null,
    });
  }
  visible.sort((left, right) => (right.createdAt ?? "").localeCompare(left.createdAt ?? ""));
  return visible;
}

export async function decideRequest(
  actor: Actor,
  requestId: string,
  action: "approve" | "deny",
  request?: Request,
) {
  const db = await getDb();
  const [row] = await db.select().from(accessRequest).where(eq(accessRequest.id, requestId)).limit(1);
  if (!row || row.status !== "pending") throw new HttpError(404, "Solicitud no encontrada");
  if (new Date(row.createdAt).getTime() + PENDING_MS < Date.now()) {
    await db.update(accessRequest).set({ status: "expired" }).where(eq(accessRequest.id, requestId));
    throw new HttpError(409, "La solicitud expiró");
  }
  const names = await namesFor([requestId]);
  const items = names.get(requestId) ?? [];
  const own = row.requesterUserId === actor.id;
  if (action === "deny" && own) {
    await db
      .update(accessRequest)
      .set({ status: "denied", decidedBy: actor.id, decidedAt: new Date() })
      .where(and(eq(accessRequest.id, requestId), eq(accessRequest.status, "pending")));
    await audit({
      actorId: actor.id,
      action: "request.deny",
      resourceType: "request",
      resourceId: requestId,
      metadata: { status: "denied" },
      request,
    });
    return { id: requestId, status: "denied" as const, grantId: null, confirmation: "Solicitud cancelada." };
  }
  if (!(await canDecide(actor, items))) throw new HttpError(403, "No podés resolver esta solicitud");
  if (action === "deny") {
    const updated = await db
      .update(accessRequest)
      .set({ status: "denied", decidedBy: actor.id, decidedAt: new Date() })
      .where(and(eq(accessRequest.id, requestId), eq(accessRequest.status, "pending")))
      .returning({ id: accessRequest.id });
    if (!updated.length) throw new HttpError(409, "La solicitud ya fue resuelta");
    await audit({
      actorId: actor.id,
      action: "request.deny",
      resourceType: "request",
      resourceId: requestId,
      metadata: { status: "denied", itemCount: items.length },
      request,
    });
    return { id: requestId, status: "denied" as const, grantId: null, confirmation: "Solicitud rechazada." };
  }
  const grantId = randomPrefixed("llg");
  const sealed = encryptString(grantId);
  const updated = await db
    .update(accessRequest)
    .set({
      status: "approved",
      grantHash: hashToken(grantId),
      grantWrappedDek: sealed.wrappedDek,
      grantDekIv: sealed.dekIv,
      grantDekTag: sealed.dekTag,
      grantCiphertext: sealed.ciphertext,
      grantIv: sealed.iv,
      grantTag: sealed.tag,
      grantExpiresAt: new Date(Date.now() + GRANT_MS),
      decidedBy: actor.id,
      decidedAt: new Date(),
    })
    .where(and(eq(accessRequest.id, requestId), eq(accessRequest.status, "pending")))
    .returning({ id: accessRequest.id, grantExpiresAt: accessRequest.grantExpiresAt });
  if (!updated.length) throw new HttpError(409, "La solicitud ya fue resuelta");
  await audit({
    actorId: actor.id,
    action: "request.approve",
    resourceType: "request",
    resourceId: requestId,
    metadata: { status: "approved", itemCount: items.length },
    request,
  });
  return {
    id: requestId,
    status: "approved" as const,
    grantId: null,
    expiresAt: iso(updated[0]?.grantExpiresAt ?? null),
    confirmation: "Aprobado. Hay un grant de un solo uso por 2 minutos. Esta respuesta no trae el secreto.",
  };
}

export async function agentRequestStatus(actor: Actor, requestId: string) {
  const db = await getDb();
  const [row] = await db.select().from(accessRequest).where(eq(accessRequest.id, requestId)).limit(1);
  if (!row || row.requesterUserId !== actor.id) throw new HttpError(404, "Solicitud no encontrada");
  let status = row.status;
  if (status === "pending" && new Date(row.createdAt).getTime() + PENDING_MS < Date.now()) status = "expired";
  if (status === "approved" && row.grantExpiresAt && new Date(row.grantExpiresAt).getTime() < Date.now()) {
    status = "expired";
  }
  if (status !== row.status) {
    await db.update(accessRequest).set({ status }).where(eq(accessRequest.id, requestId));
  }
  const names = await namesFor([requestId]);
  let grantId: string | null = null;
  if (status === "approved" && row.grantWrappedDek && row.grantDekIv && row.grantDekTag && row.grantCiphertext && row.grantIv && row.grantTag) {
    try {
      grantId = decryptString({
        wrappedDek: row.grantWrappedDek,
        dekIv: row.grantDekIv,
        dekTag: row.grantDekTag,
        ciphertext: row.grantCiphertext,
        iv: row.grantIv,
        tag: row.grantTag,
      });
    } catch {
      grantId = null;
    }
  }
  return {
    id: row.id,
    status,
    purpose: row.purpose,
    kind: row.kind,
    expiresAt: iso(row.grantExpiresAt),
    grantId,
    items: (names.get(requestId) ?? []).map((entry) => ({ id: entry.id, name: entry.name, kind: entry.kind })),
  };
}

export async function redeemGrant(actor: Actor, grantId: string, request?: Request) {
  await consumeRateLimit(`redeem:${actor.id}`, 8, 15 * 60);
  const hash = hashToken(grantId);
  const db = await getDb();
  const [preview] = await db
    .select({
      id: accessRequest.id,
      requesterUserId: accessRequest.requesterUserId,
      status: accessRequest.status,
      folderId: accessRequest.folderId,
      kind: accessRequest.kind,
      wrapPublicKey: accessRequest.wrapPublicKey,
      grantExpiresAt: accessRequest.grantExpiresAt,
    })
    .from(accessRequest)
    .where(eq(accessRequest.grantHash, hash))
    .limit(1);
  if (!preview || preview.requesterUserId !== actor.id) throw new HttpError(404, "Grant no encontrado");
  if (!preview.wrapPublicKey) throw new HttpError(400, "La solicitud no tiene clave de cierre");
  if (preview.status !== "approved" || !preview.grantExpiresAt || new Date(preview.grantExpiresAt).getTime() < Date.now()) {
    throw new HttpError(410, "El grant venció o ya se usó");
  }
  const sql = await getSql();
  const consumed = (await sql`
    update access_request
    set status = 'consumed', consumed_at = now()
    where grant_hash = ${hash}
      and requester_user_id = ${actor.id}
      and status = 'approved'
      and consumed_at is null
      and grant_expires_at > now()
    returning id
  `) as unknown as { id?: string }[];
  const consumedId = consumed[0]?.id;
  if (!consumedId) throw new HttpError(410, "El grant venció o ya se usó");
  const secrets = await db
    .select({
      id: item.id,
      name: item.name,
      kind: item.kind,
      folderId: item.folderId,
      revokedAt: item.revokedAt,
      wrappedDek: item.wrappedDek,
      dekIv: item.dekIv,
      dekTag: item.dekTag,
      ciphertext: item.ciphertext,
      iv: item.iv,
      tag: item.tag,
    })
    .from(accessRequestItem)
    .innerJoin(item, eq(item.id, accessRequestItem.itemId))
    .where(eq(accessRequestItem.requestId, consumedId));
  if (secrets.some((row) => row.revokedAt || row.ciphertext === "revoked")) {
    await audit({
      actorId: actor.id,
      action: "grant.blocked",
      resourceType: "request",
      resourceId: consumedId,
      metadata: { status: "consumed", itemCount: secrets.length },
      request,
    });
    throw new HttpError(409, "Un elemento fue revocado. El grant se consumió sin revelar nada.");
  }
  const bindings = preview.folderId
    ? await db
        .select({ itemId: envBinding.itemId, envKey: envBinding.envKey })
        .from(envBinding)
        .where(eq(envBinding.folderId, preview.folderId))
    : [];
  const entries = secrets.flatMap((row) => {
    let plaintext = "";
    try {
      plaintext = decryptString(row as Envelope);
    } catch {
      throw new HttpError(500, "No se pudo abrir el secreto");
    }
    const keys = bindings.filter((binding) => binding.itemId === row.id).map((binding) => binding.envKey);
    const targets = keys.length ? keys : [null];
    return targets.map((envKey) => ({
      itemId: row.id,
      name: row.name,
      kind: row.kind,
      envKey,
      secret: plaintext,
    }));
  });
  let recipient: Buffer;
  try {
    recipient = parseWrapPublicKey(preview.wrapPublicKey);
  } catch {
    throw new HttpError(400, "La clave de cierre es inválida");
  }
  const sealed = sealJson({ entries }, recipient);
  await audit({
    actorId: actor.id,
    action: "grant.redeem",
    resourceType: "request",
    resourceId: consumedId,
    metadata: { itemCount: secrets.length, kind: preview.kind },
    request,
  });
  return {
    sealed,
    entries: entries.map(({ secret: _secret, ...rest }) => rest),
  };
}
