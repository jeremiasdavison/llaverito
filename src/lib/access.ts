import "server-only";
import { and, eq } from "drizzle-orm";
import { getDb } from "./db";
import { HttpError } from "./errors";
import { canAdminister, maxAccess } from "./permissions";
import { folder, item, share } from "./schema";
import type { Access, Actor } from "./types";

export async function folderAccess(actor: Actor, folderId: string) {
  const db = await getDb();
  const [row] = await db.select().from(folder).where(eq(folder.id, folderId)).limit(1);
  if (!row) throw new HttpError(404, "Carpeta no encontrada");
  if (row.ownerUserId === actor.id) return { folder: row, access: "owner" as Access };
  const [shared] = await db
    .select({ permission: share.permission })
    .from(share)
    .where(
      and(
        eq(share.resourceType, "folder"),
        eq(share.resourceId, folderId),
        eq(share.granteeEmail, actor.email),
      ),
    )
    .limit(1);
  if (!shared) throw new HttpError(404, "Carpeta no encontrada");
  return { folder: row, access: (shared.permission === "admin" ? "admin" : "use") as Access };
}

export async function itemAccess(actor: Actor, itemId: string) {
  const db = await getDb();
  const [row] = await db.select().from(item).where(eq(item.id, itemId)).limit(1);
  if (!row) throw new HttpError(404, "Elemento no encontrado");
  let access: Access = "none";
  try {
    access = (await folderAccess(actor, row.folderId)).access;
  } catch (error) {
    if (!(error instanceof HttpError) || error.status !== 404) throw error;
  }
  const [direct] = await db
    .select({ permission: share.permission })
    .from(share)
    .where(
      and(eq(share.resourceType, "item"), eq(share.resourceId, itemId), eq(share.granteeEmail, actor.email)),
    )
    .limit(1);
  if (direct) access = maxAccess(access, direct.permission === "admin" ? "admin" : "use");
  if (access === "none") throw new HttpError(404, "Elemento no encontrado");
  return { item: row, access };
}

export async function requireAdminFolder(actor: Actor, folderId: string) {
  const result = await folderAccess(actor, folderId);
  if (!canAdminister(result.access)) throw new HttpError(403, "No tenés permiso para administrar esta carpeta");
  return result;
}

export async function requireAdminItem(actor: Actor, itemId: string) {
  const result = await itemAccess(actor, itemId);
  if (!canAdminister(result.access)) throw new HttpError(403, "No tenés permiso para administrar este elemento");
  return result;
}
