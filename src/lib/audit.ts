import "server-only";
import { and, desc, eq, inArray, or } from "drizzle-orm";
import { getDb } from "./db";
import { clientIp } from "./http";
import { auditEvent, folder, item } from "./schema";
import type { Actor } from "./types";

const SAFE_META = /^(kind|name|permission|folderId|itemCount|prefix|status|envKey|resourceType)$/;

function cleanMeta(metadata: Record<string, string | number | boolean | null>) {
  const output: Record<string, string | number | boolean | null> = {};
  for (const [key, value] of Object.entries(metadata)) {
    if (!SAFE_META.test(key)) continue;
    if (typeof value === "string" && (value.includes("PRIVATE KEY") || value.length > 200)) continue;
    output[key] = value;
  }
  return output;
}

export async function audit(input: {
  actorId: string | null;
  action: string;
  resourceType?: string | null;
  resourceId?: string | null;
  metadata?: Record<string, string | number | boolean | null>;
  request?: Request;
}) {
  const db = await getDb();
  await db.insert(auditEvent).values({
    id: crypto.randomUUID(),
    actorUserId: input.actorId,
    action: input.action,
    resourceType: input.resourceType ?? null,
    resourceId: input.resourceId ?? null,
    metadata: cleanMeta(input.metadata ?? {}),
    ip: input.request ? clientIp(input.request) : null,
    userAgent: input.request?.headers.get("user-agent")?.slice(0, 200) ?? null,
    createdAt: new Date(),
  });
}

export async function listAudit(actor: Actor) {
  const db = await getDb();
  const ownedFolders = await db
    .select({ id: folder.id })
    .from(folder)
    .where(eq(folder.ownerUserId, actor.id));
  const folderIds = ownedFolders.map((row) => row.id);
  const ownedItems = folderIds.length
    ? await db.select({ id: item.id }).from(item).where(inArray(item.folderId, folderIds))
    : [];
  const itemIds = ownedItems.map((row) => row.id);
  const filters = [eq(auditEvent.actorUserId, actor.id)];
  if (folderIds.length) {
    filters.push(and(eq(auditEvent.resourceType, "folder"), inArray(auditEvent.resourceId, folderIds))!);
  }
  if (itemIds.length) {
    filters.push(and(eq(auditEvent.resourceType, "item"), inArray(auditEvent.resourceId, itemIds))!);
  }
  const rows = await db
    .select({
      id: auditEvent.id,
      action: auditEvent.action,
      resourceType: auditEvent.resourceType,
      resourceId: auditEvent.resourceId,
      metadata: auditEvent.metadata,
      ip: auditEvent.ip,
      createdAt: auditEvent.createdAt,
    })
    .from(auditEvent)
    .where(or(...filters))
    .orderBy(desc(auditEvent.createdAt))
    .limit(100);
  return rows.map((row) => ({
    ...row,
    createdAt: new Date(row.createdAt).toISOString(),
  }));
}
