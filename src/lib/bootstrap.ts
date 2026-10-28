import "server-only";
import { and, eq } from "drizzle-orm";
import { getDb } from "./db";
import { isUniqueViolation } from "./http";
import { folder } from "./schema";

export async function ensurePersonalFolder(userId: string) {
  const db = await getDb();
  const existing = await db
    .select({ id: folder.id })
    .from(folder)
    .where(and(eq(folder.ownerUserId, userId), eq(folder.kind, "personal")))
    .limit(1);
  if (existing[0]) return existing[0].id;
  const id = crypto.randomUUID();
  try {
    await db.insert(folder).values({
      id,
      ownerUserId: userId,
      name: "Personal",
      kind: "personal",
      githubRepo: null,
      createdAt: new Date(),
    });
    return id;
  } catch (error) {
    if (!isUniqueViolation(error)) throw error;
    const again = await db
      .select({ id: folder.id })
      .from(folder)
      .where(and(eq(folder.ownerUserId, userId), eq(folder.kind, "personal")))
      .limit(1);
    if (again[0]) return again[0].id;
    throw error;
  }
}
