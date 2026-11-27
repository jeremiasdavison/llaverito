import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { getTableName, is } from "drizzle-orm";
import { PgTable } from "drizzle-orm/pg-core";
import { applySchemaStatements, SCHEMA_MIGRATION_ID } from "../src/lib/migrate-sql.ts";
import { schema } from "../src/lib/schema.ts";
import { statements } from "../src/lib/statements.ts";

test("schema sql stays idempotent and covers every drizzle table", async () => {
  const calls: { statement: string; params?: unknown[] }[] = [];
  await applySchemaStatements(async (statement, params) => {
    calls.push({ statement, params });
  });
  assert.ok(calls.length > statements.length);
  for (const call of calls.slice(0, -1)) {
    assert.match(
      call.statement,
      /CREATE (TABLE|INDEX|UNIQUE INDEX) IF NOT EXISTS|ADD COLUMN IF NOT EXISTS|^UPDATE .+ WHERE .+ IS NULL|ALTER COLUMN \S+ SET (DEFAULT|NOT NULL)/,
    );
    assert.equal(call.statement.includes("DROP "), false);
  }
  const journal = calls.at(-1);
  assert.equal(journal?.statement.includes("$1"), true);
  assert.deepEqual(journal?.params, [SCHEMA_MIGRATION_ID]);
  const sql = calls.map((call) => call.statement).join("\n");
  for (const value of Object.values(schema)) {
    if (!is(value, PgTable)) continue;
    assert.equal(sql.includes(getTableName(value)), true, getTableName(value));
  }
});

test("migrate script skips a missing database during build and fails when asked directly", () => {
  const env = {
    PATH: process.env.PATH,
    LLAVERITO_SKIP_LOCAL_ENV: "1",
  };
  const skip = spawnSync(
    process.execPath,
    ["--experimental-strip-types", "--import", "./scripts/register-hooks.mjs", "scripts/migrate.ts", "--if-configured"],
    { encoding: "utf8", env },
  );
  assert.equal(skip.status, 0, skip.stderr);
  assert.match(skip.stdout, /DATABASE_URL/);
  assert.equal(skip.stdout.includes("postgres://"), false);

  const required = spawnSync(
    process.execPath,
    ["--experimental-strip-types", "--import", "./scripts/register-hooks.mjs", "scripts/migrate.ts"],
    { encoding: "utf8", env },
  );
  assert.equal(required.status, 1);
  assert.match(required.stderr, /npm run db:migrate/);
});
