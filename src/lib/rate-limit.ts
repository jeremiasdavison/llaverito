import "server-only";
import { HttpError } from "./errors";
import { getSql } from "./db";

export async function consumeRateLimit(bucket: string, max: number, windowSeconds: number) {
  const sql = await getSql();
  const rows = (await sql`
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
  `) as unknown as { count?: number }[];
  const count = Number(rows[0]?.count ?? 0);
  if (count > max) throw new HttpError(429, "Demasiados intentos. Esperá un momento.");
}
