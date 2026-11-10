import assert from "node:assert/strict";
import test from "node:test";
import { poolConfig } from "../src/lib/db-url.ts";

test("supabase pooler urls drop the supa query before node-pg connects", () => {
  const raw =
    "postgresql://user:secret@aws-1-sa-east-1.pooler.supabase.com:6543/postgres?sslmode=require&supa=base-pooler.x&pgbouncer=true";
  const config = poolConfig(raw);
  const url = new URL(config.connectionString);
  assert.equal(url.searchParams.has("supa"), false);
  assert.equal(url.searchParams.has("sslmode"), false);
  assert.equal(url.searchParams.has("pgbouncer"), false);
  assert.equal(url.hostname, "aws-1-sa-east-1.pooler.supabase.com");
  assert.deepEqual(config.ssl, { rejectUnauthorized: false });
});
