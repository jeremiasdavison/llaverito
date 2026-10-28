import { neon } from "@neondatabase/serverless";
import { drizzle } from "drizzle-orm/neon-http";
import { ConfigError } from "./errors";
import { schema } from "./schema";
import { statements } from "./statements";

type Sql = ReturnType<typeof neon<false, false>>;
type Database = ReturnType<typeof drizzle<typeof schema>>;
type Client = { sql: Sql; db: Database };

let client: Client | null = null;
let ready: Promise<void> | null = null;

export function databaseUrl(): string {
  const url = process.env.DATABASE_URL || process.env.POSTGRES_URL;
  if (!url) throw new ConfigError();
  return url;
}

async function applySchema(sql: Sql) {
  for (const statement of statements) {
    await sql.query(statement);
  }
}

export async function ensureSchema() {
  const { sql } = connect();
  if (!ready) {
    ready = applySchema(sql).catch((error) => {
      ready = null;
      throw error;
    });
  }
  await ready;
}

function connect(): Client {
  if (client) return client;
  const sql = neon(databaseUrl());
  const created = { sql, db: drizzle(sql, { schema }) };
  client = created;
  return created;
}

export async function getDb() {
  const current = connect();
  await ensureSchema();
  return current.db;
}

export async function getSql() {
  const current = connect();
  await ensureSchema();
  return current.sql;
}

export async function pingDb() {
  const sql = await getSql();
  await sql`select 1 as ok`;
}
