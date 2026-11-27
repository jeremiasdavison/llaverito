import assert from "node:assert/strict";
import test from "node:test";
import { ConfigError, DatabaseConfigError, DatabaseError } from "../src/lib/errors.ts";
import { serviceErrorResponse } from "../src/lib/http.ts";
import {
  assessReadiness,
  readAuthSecretStatus,
  readAuthUrlStatus,
  readDatabasePresence,
} from "../src/lib/readiness.ts";

const ready = {
  encryption: "configured" as const,
  authSecret: "configured" as const,
  authUrl: "configured" as const,
  database: "up" as const,
  schema: "ready" as const,
  latencyMs: 12,
};

test("health names a missing database url instead of calling it down", () => {
  const report = assessReadiness({
    ...ready,
    database: "missing",
    schema: "unknown",
    latencyMs: null,
  });
  assert.equal(report.ok, false);
  assert.deepEqual(report.missing, ["DATABASE_URL"]);
  assert.equal(report.invalid.length, 0);
  assert.match(report.hint, /Neon/);
});

test("health is ok only when signup can run", () => {
  const report = assessReadiness(ready);
  assert.equal(report.ok, true);
  assert.equal(report.hint, "Listo para crear una cuenta.");
  assert.equal(assessReadiness({ ...ready, authUrl: "unset" }).ok, true);
  assert.equal(assessReadiness({ ...ready, authUrl: "invalid" }).ok, false);
  assert.equal(assessReadiness({ ...ready, database: "down" }).ok, false);
  assert.match(assessReadiness({ ...ready, database: "down" }).hint, /no responde/);
  assert.equal(assessReadiness({ ...ready, schema: "failed" }).missing.includes("DATABASE_URL"), false);
});

test("secret status rejects placeholders and short values", () => {
  assert.equal(readAuthSecretStatus({}), "missing");
  assert.equal(readAuthSecretStatus({ BETTER_AUTH_SECRET: "replace-with-openssl-rand-base64-32" }), "missing");
  assert.equal(readAuthSecretStatus({ BETTER_AUTH_SECRET: "too-short" }), "invalid");
  assert.equal(readAuthSecretStatus({ BETTER_AUTH_SECRET: "a".repeat(32) }), "configured");
  assert.equal(readAuthUrlStatus({}), "unset");
  assert.equal(readAuthUrlStatus({ BETTER_AUTH_URL: "not a url" }), "invalid");
  assert.equal(readAuthUrlStatus({ BETTER_AUTH_URL: "https://llaverito-six.vercel.app" }), "configured");
  assert.equal(readDatabasePresence({ POSTGRES_URL: " postgres://db.example/app " }), "present");
  assert.equal(readDatabasePresence({ DATABASE_URL: "  " }), "missing");
});

test("api errors stay friendly and do not echo the driver", async () => {
  const missing = serviceErrorResponse(new ConfigError());
  const noDatabase = serviceErrorResponse(new DatabaseConfigError());
  const down = serviceErrorResponse(new DatabaseError());
  assert.ok(missing && noDatabase && down);
  assert.equal(missing.status, 503);
  assert.equal(down.status, 503);
  const missingBody = (await missing.json()) as { message: string; error: string };
  const downBody = (await down.json()) as { message: string };
  assert.match(missingBody.message, /BETTER_AUTH_SECRET/);
  assert.equal(missingBody.message, missingBody.error);
  const noDatabaseBody = (await noDatabase.json()) as { message: string };
  assert.match(noDatabaseBody.message, /DATABASE_URL/);
  assert.equal(noDatabaseBody.message.includes("BETTER_AUTH_SECRET"), false);
  assert.match(downBody.message, /Neon/);
  assert.equal(downBody.message.includes("postgres://"), false);
  assert.equal(serviceErrorResponse(new Error("password=secret")), null);
});
