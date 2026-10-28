import "server-only";
import { and, desc, eq, inArray } from "drizzle-orm";
import { z } from "zod";
import { folderAccess, itemAccess, requireAdminFolder, requireAdminItem } from "./access";
import { audit } from "./audit";
import { decryptString, encryptString, type Envelope } from "./crypto";
import { getDb } from "./db";
import { HttpError } from "./errors";
import { isUniqueViolation } from "./http";
import { canAdminister } from "./permissions";
import { maxAccess } from "./permissions";
import { consumeRateLimit } from "./rate-limit";
import { envBinding, folder, item, share, user } from "./schema";
import type { Access, Actor, ItemKind } from "./types";
import { apiKeyHint, sshFingerprint } from "./validate";

const publicItemColumns = {
  id: item.id,
  folderId: item.folderId,
  name: item.name,
  kind: item.kind,
  fingerprint: item.fingerprint,
  revokedAt: item.revokedAt,
  createdAt: item.createdAt,
};

function iso(value: Date | string | null) {
  if (!value) return null;
  return new Date(value).toISOString();
}

function toPublicItem(
  row: {
    id: string;
    folderId: string;
    name: string;
    kind: ItemKind;
    fingerprint: string | null;
    revokedAt: Date | null;
    createdAt: Date;
  },
  access: Access,
  sharedDirectly: boolean,
) {
  return {
    id: row.id,
    folderId: row.folderId,
    name: row.name,
    kind: row.kind,
    fingerprint: row.fingerprint,
    revokedAt: iso(row.revokedAt),
    createdAt: iso(row.createdAt),
    access,
    sharedDirectly,
  };
}

function envelope(row: {
  wrappedDek: string;
  dekIv: string;
  dekTag: string;
  ciphertext: string;
  iv: string;
  tag: string;
}): Envelope {
  return {
    wrappedDek: row.wrappedDek,
    dekIv: row.dekIv,
    dekTag: row.dekTag,
    ciphertext: row.ciphertext,
    iv: row.iv,
    tag: row.tag,
  };
}

function fingerprintFor(kind: ItemKind, secret: string, publicKey?: string) {
  if (kind === "api_key") return apiKeyHint(secret);
  if (!publicKey) return null;
  const fingerprint = sshFingerprint(publicKey);
  if (!fingerprint) throw new HttpError(400, "La clave pública SSH no se pudo leer");
  return fingerprint;
}

async function resolveGrantee(actor: Actor, input: string) {
  const trimmed = input.trim();
  if (trimmed.includes("@")) {
    const email = trimmed.toLowerCase();
    if (!z.string().email().safeParse(email).success) throw new HttpError(400, "Email inválido");
    if (email === actor.email) throw new HttpError(400, "No podés compartirlo con vos");
    return email;
  }
  const db = await getDb();
  const [found] = await db.select({ email: user.email }).from(user).where(eq(user.id, trimmed)).limit(1);
  if (!found) throw new HttpError(404, "No hay un usuario con ese id");
  const email = found.email.toLowerCase();
  if (email === actor.email) throw new HttpError(400, "No podés compartirlo con vos");
  return email;
}

export async function listVault(actor: Actor) {
  const db = await getDb();
  const owned = await db.select().from(folder).where(eq(folder.ownerUserId, actor.id));
  const sharedFolders = await db
    .select({ row: folder, permission: share.permission })
    .from(share)
    .innerJoin(folder, eq(share.resourceId, folder.id))
    .where(and(eq(share.resourceType, "folder"), eq(share.granteeEmail, actor.email)));
  const folderMap = new Map<string, { row: (typeof owned)[number]; access: Access }>();
  for (const row of owned) folderMap.set(row.id, { row, access: "owner" });
  for (const shared of sharedFolders) {
    const access: Access = shared.permission === "admin" ? "admin" : "use";
    const current = folderMap.get(shared.row.id);
    folderMap.set(shared.row.id, {
      row: current?.row ?? shared.row,
      access: current ? maxAccess(current.access, access) : access,
    });
  }
  const folderIds = [...folderMap.keys()];
  const folderItems = folderIds.length
    ? await db.select(publicItemColumns).from(item).where(inArray(item.folderId, folderIds))
    : [];
  const direct = await db
    .select({ ...publicItemColumns, permission: share.permission })
    .from(share)
    .innerJoin(item, eq(share.resourceId, item.id))
    .where(and(eq(share.resourceType, "item"), eq(share.granteeEmail, actor.email)));
  const items = new Map<string, ReturnType<typeof toPublicItem>>();
  for (const row of folderItems) {
    items.set(row.id, toPublicItem(row, folderMap.get(row.folderId)?.access ?? "use", false));
  }
  for (const row of direct) {
    const access: Access = row.permission === "admin" ? "admin" : "use";
    const existing = items.get(row.id);
    if (existing) existing.access = maxAccess(existing.access, access);
    else items.set(row.id, toPublicItem(row, access, true));
  }
  return {
    folders: [...folderMap.values()].map(({ row, access }) => ({
      id: row.id,
      name: row.name,
      kind: row.kind,
      githubRepo: row.githubRepo,
      createdAt: iso(row.createdAt),
      access,
    })),
    items: [...items.values()],
  };
}

export async function createFolder(
  actor: Actor,
  input: { name: string; kind: "personal" | "project"; githubRepo?: string },
  request?: Request,
) {
  if (input.kind === "personal") {
    throw new HttpError(409, "La carpeta personal se crea sola con la cuenta");
  }
  const db = await getDb();
  const id = crypto.randomUUID();
  const githubRepo = input.githubRepo?.trim() || null;
  await db.insert(folder).values({
    id,
    ownerUserId: actor.id,
    name: input.name,
    kind: "project",
    githubRepo,
    createdAt: new Date(),
  });
  await audit({
    actorId: actor.id,
    action: "folder.create",
    resourceType: "folder",
    resourceId: id,
    metadata: { name: input.name, kind: "project" },
    request,
  });
  return { id, name: input.name, kind: "project" as const, githubRepo, access: "owner" as const };
}

export async function updateFolder(
  actor: Actor,
  folderId: string,
  input: { name?: string; githubRepo?: string },
  request?: Request,
) {
  const { folder: row } = await requireAdminFolder(actor, folderId);
  const db = await getDb();
  const githubRepo = row.kind === "project" ? input.githubRepo?.trim() || row.githubRepo : null;
  if (row.kind === "personal" && input.githubRepo) {
    throw new HttpError(400, "La carpeta personal no se vincula a un repo");
  }
  await db
    .update(folder)
    .set({
      name: input.name ?? row.name,
      githubRepo: input.githubRepo === "" ? null : githubRepo,
    })
    .where(eq(folder.id, folderId));
  await audit({
    actorId: actor.id,
    action: "folder.update",
    resourceType: "folder",
    resourceId: folderId,
    metadata: { name: input.name ?? row.name },
    request,
  });
  return { id: folderId };
}

export async function deleteFolder(actor: Actor, folderId: string, request?: Request) {
  const { folder: row } = await requireAdminFolder(actor, folderId);
  if (row.kind === "personal") throw new HttpError(400, "La carpeta personal no se puede borrar");
  if (row.ownerUserId !== actor.id) throw new HttpError(403, "Solo el dueño puede borrar la carpeta");
  const db = await getDb();
  const ids = await db.select({ id: item.id }).from(item).where(eq(item.folderId, folderId));
  await db.delete(share).where(and(eq(share.resourceType, "folder"), eq(share.resourceId, folderId)));
  if (ids.length) {
    await db.delete(share).where(
      and(
        eq(share.resourceType, "item"),
        inArray(
          share.resourceId,
          ids.map((entry) => entry.id),
        ),
      ),
    );
  }
  await db.delete(folder).where(eq(folder.id, folderId));
  await audit({
    actorId: actor.id,
    action: "folder.delete",
    resourceType: "folder",
    resourceId: folderId,
    metadata: { name: row.name },
    request,
  });
}

export async function createItem(
  actor: Actor,
  input: { folderId: string; name: string; kind: ItemKind; secret: string; publicKey?: string },
  request?: Request,
) {
  await requireAdminFolder(actor, input.folderId);
  if (input.kind === "ssh_key" && !input.secret.includes("PRIVATE KEY")) {
    throw new HttpError(400, "La clave SSH tiene que incluir el bloque PRIVATE KEY");
  }
  const sealed = encryptString(input.secret);
  const id = crypto.randomUUID();
  const db = await getDb();
  try {
    await db.insert(item).values({
      id,
      folderId: input.folderId,
      createdBy: actor.id,
      name: input.name,
      kind: input.kind,
      ...sealed,
      fingerprint: fingerprintFor(input.kind, input.secret, input.publicKey || undefined),
      revokedAt: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    });
  } catch (error) {
    if (isUniqueViolation(error)) throw new HttpError(409, "Ya hay un elemento activo con ese nombre");
    throw error;
  }
  await audit({
    actorId: actor.id,
    action: "item.create",
    resourceType: "item",
    resourceId: id,
    metadata: { name: input.name, kind: input.kind, folderId: input.folderId },
    request,
  });
  return { id, name: input.name, kind: input.kind, folderId: input.folderId };
}

export async function revokeItem(actor: Actor, itemId: string, request?: Request) {
  const { item: row } = await requireAdminItem(actor, itemId);
  if (row.revokedAt) throw new HttpError(409, "El elemento ya está revocado");
  const db = await getDb();
  await db
    .update(item)
    .set({
      revokedAt: new Date(),
      wrappedDek: "revoked",
      dekIv: "revoked",
      dekTag: "revoked",
      ciphertext: "revoked",
      iv: "revoked",
      tag: "revoked",
      updatedAt: new Date(),
    })
    .where(eq(item.id, itemId));
  await audit({
    actorId: actor.id,
    action: "item.revoke",
    resourceType: "item",
    resourceId: itemId,
    metadata: { name: row.name, kind: row.kind },
    request,
  });
}

export async function rotateItem(
  actor: Actor,
  itemId: string,
  input: { secret: string; publicKey?: string },
  request?: Request,
) {
  const { item: row } = await requireAdminItem(actor, itemId);
  if (row.revokedAt) throw new HttpError(409, "El elemento está revocado");
  if (row.kind === "ssh_key" && !input.secret.includes("PRIVATE KEY")) {
    throw new HttpError(400, "La clave SSH tiene que incluir el bloque PRIVATE KEY");
  }
  const sealed = encryptString(input.secret);
  const db = await getDb();
  await db
    .update(item)
    .set({
      ...sealed,
      fingerprint: fingerprintFor(row.kind, input.secret, input.publicKey || undefined),
      updatedAt: new Date(),
    })
    .where(eq(item.id, itemId));
  await audit({
    actorId: actor.id,
    action: "item.rotate",
    resourceType: "item",
    resourceId: itemId,
    metadata: { name: row.name, kind: row.kind },
    request,
  });
  return { id: itemId };
}

export async function unlockItem(actor: Actor, itemId: string, request?: Request) {
  await consumeRateLimit(`unlock:${actor.id}`, 5, 15 * 60);
  const { item: row, access } = await itemAccess(actor, itemId);
  if (!canAdminister(access)) throw new HttpError(403, "Solo un administrador puede revelar el secreto");
  if (row.revokedAt) throw new HttpError(409, "El elemento está revocado");
  let secret = "";
  try {
    secret = decryptString(envelope(row));
  } catch {
    throw new HttpError(500, "No se pudo abrir el secreto");
  }
  await audit({
    actorId: actor.id,
    action: "item.unlock",
    resourceType: "item",
    resourceId: itemId,
    metadata: { name: row.name, kind: row.kind },
    request,
  });
  return { id: row.id, name: row.name, kind: row.kind, secret };
}

export async function listShares(actor: Actor, resourceType: "folder" | "item", resourceId: string) {
  if (resourceType === "folder") await requireAdminFolder(actor, resourceId);
  else await requireAdminItem(actor, resourceId);
  const db = await getDb();
  const rows = await db
    .select({
      id: share.id,
      granteeEmail: share.granteeEmail,
      permission: share.permission,
      createdAt: share.createdAt,
    })
    .from(share)
    .where(and(eq(share.resourceType, resourceType), eq(share.resourceId, resourceId)))
    .orderBy(desc(share.createdAt));
  return rows.map((row) => ({ ...row, createdAt: iso(row.createdAt) }));
}

export async function createShare(
  actor: Actor,
  input: { resourceType: "folder" | "item"; resourceId: string; grantee: string; permission: "use" | "admin" },
  request?: Request,
) {
  if (input.resourceType === "folder") await requireAdminFolder(actor, input.resourceId);
  else await requireAdminItem(actor, input.resourceId);
  const granteeEmail = await resolveGrantee(actor, input.grantee);
  const db = await getDb();
  const [saved] = await db
    .insert(share)
    .values({
      id: crypto.randomUUID(),
      resourceType: input.resourceType,
      resourceId: input.resourceId,
      granteeEmail,
      permission: input.permission,
      createdBy: actor.id,
      createdAt: new Date(),
    })
    .onConflictDoUpdate({
      target: [share.resourceType, share.resourceId, share.granteeEmail],
      set: { permission: input.permission },
    })
    .returning({
      id: share.id,
      granteeEmail: share.granteeEmail,
      permission: share.permission,
      resourceType: share.resourceType,
      resourceId: share.resourceId,
    });
  await audit({
    actorId: actor.id,
    action: "share.create",
    resourceType: input.resourceType,
    resourceId: input.resourceId,
    metadata: { permission: input.permission },
    request,
  });
  return saved;
}

export async function deleteShare(actor: Actor, shareId: string, request?: Request) {
  const db = await getDb();
  const [row] = await db.select().from(share).where(eq(share.id, shareId)).limit(1);
  if (!row) throw new HttpError(404, "El permiso no existe");
  if (row.resourceType === "folder") await requireAdminFolder(actor, row.resourceId);
  else await requireAdminItem(actor, row.resourceId);
  await db.delete(share).where(eq(share.id, shareId));
  await audit({
    actorId: actor.id,
    action: "share.delete",
    resourceType: row.resourceType,
    resourceId: row.resourceId,
    metadata: { permission: row.permission },
    request,
  });
}

export async function envManifest(actor: Actor, folderId: string) {
  const { folder: row, access } = await folderAccess(actor, folderId);
  if (row.kind !== "project") throw new HttpError(400, "El entorno virtual es de carpetas de proyecto");
  const db = await getDb();
  const rows = await db
    .select({
      bindingId: envBinding.id,
      envKey: envBinding.envKey,
      itemId: item.id,
      itemName: item.name,
      kind: item.kind,
      revokedAt: item.revokedAt,
    })
    .from(envBinding)
    .innerJoin(item, eq(item.id, envBinding.itemId))
    .where(eq(envBinding.folderId, folderId))
    .orderBy(envBinding.envKey);
  return {
    folderId: row.id,
    githubRepo: row.githubRepo,
    access,
    entries: rows.map((entry) => ({
      bindingId: entry.bindingId,
      envKey: entry.envKey,
      itemId: entry.itemId,
      itemName: entry.itemName,
      kind: entry.kind,
      revoked: Boolean(entry.revokedAt),
      value: null,
    })),
  };
}

export async function bindEnv(
  actor: Actor,
  folderId: string,
  input: { itemId: string; envKey: string },
  request?: Request,
) {
  const { folder: row } = await requireAdminFolder(actor, folderId);
  if (row.kind !== "project") throw new HttpError(400, "El entorno virtual es de carpetas de proyecto");
  const { item: secret } = await requireAdminItem(actor, input.itemId);
  if (secret.folderId !== folderId) throw new HttpError(400, "El elemento tiene que estar en esta carpeta");
  if (secret.revokedAt) throw new HttpError(409, "El elemento está revocado");
  const db = await getDb();
  const id = crypto.randomUUID();
  try {
    await db.insert(envBinding).values({
      id,
      folderId,
      itemId: input.itemId,
      envKey: input.envKey,
      createdAt: new Date(),
    });
  } catch (error) {
    if (isUniqueViolation(error)) throw new HttpError(409, "Esa variable ya está usada en el proyecto");
    throw error;
  }
  await audit({
    actorId: actor.id,
    action: "env.bind",
    resourceType: "folder",
    resourceId: folderId,
    metadata: { envKey: input.envKey },
    request,
  });
  return { id, envKey: input.envKey, itemId: input.itemId, value: null };
}

export async function unbindEnv(actor: Actor, folderId: string, bindingId: string, request?: Request) {
  await requireAdminFolder(actor, folderId);
  const db = await getDb();
  const [row] = await db
    .select({ id: envBinding.id, envKey: envBinding.envKey })
    .from(envBinding)
    .where(and(eq(envBinding.id, bindingId), eq(envBinding.folderId, folderId)))
    .limit(1);
  if (!row) throw new HttpError(404, "El mapeo no existe");
  await db.delete(envBinding).where(eq(envBinding.id, bindingId));
  await audit({
    actorId: actor.id,
    action: "env.unbind",
    resourceType: "folder",
    resourceId: folderId,
    metadata: { envKey: row.envKey },
    request,
  });
}
