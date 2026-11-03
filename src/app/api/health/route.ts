import { pingDb } from "@/lib/db";
import { json } from "@/lib/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  let database: "up" | "down" = "down";
  try {
    await pingDb();
    database = "up";
  } catch {
    database = "down";
  }
  const ok = database === "up";
  return json({ ok, encryption: "client", database }, ok ? 200 : 503);
}
