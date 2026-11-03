import { drizzle } from "drizzle-orm/node-postgres";
import { Pool } from "pg";
import { ConfigError } from "./errors";
import { schema } from "./schema";
import { statements } from "./statements";

type Database = ReturnType<typeof drizzle<typeof schema>>;
type Client = { pool: Pool; db: Database };

let client: Client | null = null;
let ready: Promise<void> | null = null;

export function databaseUrl(): string {
  const url = process.env.DATABASE_URL || process.env.POSTGRES_URL;
  if (!url) throw new ConfigError();
  return url;
}

export function poolConfig(connectionString: string) {
  const parsed = new URL(connectionString);
  const local = parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1";
  parsed.searchParams.delete("sslmode");
  parsed.searchParams.delete("ssl");
  return {
    connectionString: parsed.toString(),
    max: 1,
    ssl: local ? undefined : { rejectUnauthorized: false },
  };
}

function connect(): Client {
  if (client) return client;
  const pool = new Pool(poolConfig(databaseUrl()));
  const created = { pool, db: drizzle(pool, { schema }) };
  client = created;
  return created;
}

async function applySchema(pool: Pool) {
  for (const statement of statements) {
    await pool.query(statement);
  }
}

export async function ensureSchema() {
  const { pool } = connect();
  if (!ready) {
    ready = applySchema(pool).catch((error: unknown) => {
      ready = null;
      throw error;
    });
  }
  await ready;
}

export async function getDb() {
  const current = connect();
  await ensureSchema();
  return current.db;
}

export async function query<T>(text: string, params: unknown[] = []) {
  const { pool } = connect();
  await ensureSchema();
  const result = await pool.query(text, params);
  return result.rows as T[];
}

export async function pingDb() {
  await query("select 1 as ok");
}
