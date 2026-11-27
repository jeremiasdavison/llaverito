import { encryptionStatus } from "@/lib/crypto";
import { probeDatabase } from "@/lib/db";
import { json } from "@/lib/http";
import { assessReadiness, readAuthSecretStatus, readAuthUrlStatus } from "@/lib/readiness";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  let database: "missing" | "up" | "down" = "down";
  let schema: "unknown" | "ready" | "failed" = "unknown";
  let latencyMs: number | null = null;
  try {
    const probe = await probeDatabase();
    database = probe.database;
    schema = probe.schema;
    latencyMs = probe.latencyMs;
  } catch {
    database = "down";
    schema = "unknown";
    latencyMs = null;
  }
  const body = assessReadiness({
    encryption: encryptionStatus(),
    authSecret: readAuthSecretStatus(),
    authUrl: readAuthUrlStatus(),
    database,
    schema,
    latencyMs,
  });
  return json(body, body.ok ? 200 : 503);
}
