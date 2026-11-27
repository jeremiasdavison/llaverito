import { neon, neonConfig, Pool } from "@neondatabase/serverless";
import { drizzle } from "drizzle-orm/neon-serverless";
import ws from "ws";
import { databaseUrlFrom } from "./database-url";
import { ConfigError, DatabaseConfigError, DatabaseError } from "./errors";
import { applySchemaStatements, SCHEMA_MIGRATION_ID } from "./migrate-sql";
import { safeLog } from "./redact";
import { schema } from "./schema";

// Better Auth inserts the user, the account, and the session in one transaction.
// The Neon HTTP driver rejects that. The serverless Pool speaks transactions.
neonConfig.webSocketConstructor = ws as unknown as typeof WebSocket;

type Sql = ReturnType<typeof neon<false, false>>;
type Database = ReturnType<typeof createDatabase>;
type Client = { sql: Sql; db: Database };

function createDatabase(url: string) {
  const pool = new Pool({ connectionString: url, max: 3 });
  pool.on("error", (error: Error) => {
    logDatabase(error);
  });
  return drizzle(pool, { schema });
}

let client: Client | null = null;
let ready: Promise<void> | null = null;

export function databaseUrl(): string {
  const url = databaseUrlFrom(process.env);
  if (!url) throw new DatabaseConfigError();
  return url;
}

function errorCode(error: unknown): string | undefined {
  if (!error || typeof error !== "object") return undefined;
  if ("code" in error && typeof error.code === "string") return error.code;
  if ("cause" in error) return errorCode(error.cause);
  return undefined;
}

function logDatabase(error: unknown) {
  safeLog("database unavailable", {
    name: error instanceof Error ? error.name : "Error",
    code: errorCode(error),
  });
}

function wrapDatabase(error: unknown): never {
  if (error instanceof ConfigError) throw error;
  logDatabase(error);
  throw new DatabaseError();
}

async function migrationApplied(sql: Sql): Promise<boolean> {
  try {
    const rows = await sql`select id from schema_migration where id = ${SCHEMA_MIGRATION_ID}`;
    return Array.isArray(rows) && rows.length > 0;
  } catch {
    return false;
  }
}

async function applySchema(sql: Sql) {
  if (await migrationApplied(sql)) return;
  await applySchemaStatements((statement, params) => sql.query(statement, params));
}

export async function ensureSchema() {
  const current = connect();
  if (!ready) {
    ready = applySchema(current.sql).catch((error: unknown) => {
      ready = null;
      throw error;
    });
  }
  try {
    await ready;
  } catch (error) {
    wrapDatabase(error);
  }
}

function connect(): Client {
  if (client) return client;
  const url = databaseUrl();
  const created = { sql: neon(url), db: createDatabase(url) };
  client = created;
  return created;
}

export function useTestDatabase(db: unknown) {
  if (process.env.NODE_ENV === "production") {
    throw new Error("useTestDatabase is only available outside production");
  }
  const fail = () => {
    throw new Error("the test database does not use the Neon client");
  };
  client = { sql: fail as unknown as Sql, db: db as Database };
  ready = Promise.resolve();
}

export async function getDb() {
  try {
    const current = connect();
    await ensureSchema();
    return current.db;
  } catch (error) {
    wrapDatabase(error);
  }
}

export async function getSql() {
  try {
    const current = connect();
    await ensureSchema();
    return current.sql;
  } catch (error) {
    wrapDatabase(error);
  }
}

export type DatabaseProbe = {
  database: "missing" | "up" | "down";
  schema: "unknown" | "ready" | "failed";
  latencyMs: number | null;
};

export async function probeDatabase(): Promise<DatabaseProbe> {
  if (!databaseUrlFrom(process.env)) {
    return { database: "missing", schema: "unknown", latencyMs: null };
  }
  const started = Date.now();
  try {
    const { sql } = connect();
    await sql`select 1 as ok`;
  } catch (error) {
    if (error instanceof ConfigError && !(error instanceof DatabaseError)) {
      return { database: "missing", schema: "unknown", latencyMs: null };
    }
    logDatabase(error);
    return { database: "down", schema: "unknown", latencyMs: Date.now() - started };
  }
  try {
    await ensureSchema();
    return { database: "up", schema: "ready", latencyMs: Date.now() - started };
  } catch (error) {
    if (!(error instanceof DatabaseError)) logDatabase(error);
    return { database: "up", schema: "failed", latencyMs: Date.now() - started };
  }
}
