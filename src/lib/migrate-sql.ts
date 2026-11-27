import { statements } from "./statements";

export const SCHEMA_MIGRATION_ID = "0001_init";

export type SqlQuery = (statement: string, params?: unknown[]) => Promise<unknown>;

export async function applySchemaStatements(query: SqlQuery) {
  for (const statement of statements) {
    await query(statement);
  }
  await query(`insert into schema_migration (id) values ($1) on conflict (id) do nothing`, [
    SCHEMA_MIGRATION_ID,
  ]);
}
