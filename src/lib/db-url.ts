export function poolConfig(connectionString: string) {
  const parsed = new URL(connectionString);
  const local = parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1";
  // Supabase injects sslmode, supa, and pgbouncer. psycopg and node-pg reject supa.
  for (const key of ["sslmode", "ssl", "supa", "pgbouncer"]) parsed.searchParams.delete(key);
  return {
    connectionString: parsed.toString(),
    max: 1,
    ssl: local ? undefined : { rejectUnauthorized: false as const },
  };
}
