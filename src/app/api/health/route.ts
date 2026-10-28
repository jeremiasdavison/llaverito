import { encryptionStatus } from "@/lib/crypto";
import { pingDb } from "@/lib/db";
import { json } from "@/lib/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const encryption = encryptionStatus();
  let database: "up" | "down" = "down";
  try {
    await pingDb();
    database = "up";
  } catch {
    database = "down";
  }
  const ok = encryption === "configured" && database === "up";
  return json({ ok, encryption, database }, ok ? 200 : 503);
}
