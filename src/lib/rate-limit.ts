import "server-only";
import { sql } from "drizzle-orm";
import { getDb } from "./db";
import { HttpError } from "./errors";
import { consumeMemoryLimit } from "./rate-limit-memory";

export async function consumeRateLimit(bucket: string, max: number, windowSeconds: number) {
  const memory = consumeMemoryLimit(bucket, max, windowSeconds);
  if (!memory.allowed) throw new HttpError(429, "Demasiados intentos. Esperá un momento.", "RATE_LIMITED");
  const db = await getDb();
  let rows: { count?: number }[];
  try {
    const result = await db.execute(sql`
    insert into app_rate_limit (bucket, count, expires_at)
    values (${bucket}, 1, now() + make_interval(secs => ${windowSeconds}))
    on conflict (bucket) do update set
      count = case
        when app_rate_limit.expires_at < now() then 1
        else app_rate_limit.count + 1
      end,
      expires_at = case
        when app_rate_limit.expires_at < now() then now() + make_interval(secs => ${windowSeconds})
        else app_rate_limit.expires_at
      end
    returning count
  `);
    rows = result.rows as { count?: number }[];
  } catch (error) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(503, "No se pudo verificar el límite de intentos. Probá de nuevo.", "RATE_LIMIT_UNAVAILABLE");
  }
  const count = Number(rows[0]?.count);
  if (!Number.isFinite(count)) {
    throw new HttpError(503, "No se pudo verificar el límite de intentos. Probá de nuevo.", "RATE_LIMIT_UNAVAILABLE");
  }
  if (count > max) throw new HttpError(429, "Demasiados intentos. Esperá un momento.", "RATE_LIMITED");
}
