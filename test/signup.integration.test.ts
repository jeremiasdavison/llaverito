import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { eq } from "drizzle-orm";

process.env.BETTER_AUTH_SECRET = crypto.randomBytes(32).toString("base64");
process.env.ENCRYPTION_KEY = Buffer.alloc(32, 7).toString("base64");
delete process.env.BETTER_AUTH_URL;
delete process.env.DATABASE_URL;
delete process.env.POSTGRES_URL;

const { PGlite } = await import("@electric-sql/pglite");
const { drizzle } = await import("drizzle-orm/pglite");
const { applySchemaStatements } = await import("../src/lib/migrate-sql.ts");
const { useTestDatabase } = await import("../src/lib/db.ts");
const { schema, folder, item, auditEvent } = await import("../src/lib/schema.ts");
const { decryptString } = await import("../src/lib/crypto.ts");

const client = await PGlite.create();
await applySchemaStatements(async (statement, params) => {
  if (params && params.length > 0) await client.query(statement, params);
  else await client.exec(statement);
});
await applySchemaStatements(async (statement, params) => {
  if (params && params.length > 0) await client.query(statement, params);
  else await client.exec(statement);
});
const db = drizzle(client, { schema });
useTestDatabase(db);

const { getAuth } = await import("../src/lib/auth.ts");
const { createItem } = await import("../src/lib/vault.ts");

const origin = "https://llaverito-six.vercel.app";
const email = "ada@example.com";
const password = "correct-horse-1";
const secret = "sk-test-value-not-real";

function cookieHeader(response: Response): string {
  const list =
    typeof response.headers.getSetCookie === "function"
      ? response.headers.getSetCookie()
      : [response.headers.get("set-cookie") ?? ""];
  return list
    .filter(Boolean)
    .map((entry) => entry.split(";")[0]?.trim() ?? "")
    .filter(Boolean)
    .join("; ");
}

test("signup then login then create a secret", { timeout: 120_000 }, async () => {
  const auth = await getAuth();
  const signUpResponse = await auth.handler(
    new Request(`${origin}/api/auth/sign-up/email`, {
      method: "POST",
      headers: { "content-type": "application/json", origin },
      body: JSON.stringify({ email, password, name: "Ada" }),
    }),
  );
  const signUpText = await signUpResponse.text();
  assert.equal(signUpResponse.status, 200, signUpText);
  const signUp = JSON.parse(signUpText) as { user?: { id?: string; email?: string }; token?: string };
  assert.equal(signUp.user?.email, email);
  assert.equal(typeof signUp.user?.id, "string");
  assert.equal(signUpText.includes(secret), false);

  const signInResponse = await auth.handler(
    new Request(`${origin}/api/auth/sign-in/email`, {
      method: "POST",
      headers: { "content-type": "application/json", origin },
      body: JSON.stringify({ email, password }),
    }),
  );
  const signInText = await signInResponse.text();
  assert.equal(signInResponse.status, 200, signInText);
  const cookie = cookieHeader(signInResponse);
  assert.ok(cookie.length > 0, signInText);

  const sessionResponse = await auth.handler(
    new Request(`${origin}/api/auth/get-session`, {
      headers: { cookie, origin },
    }),
  );
  const sessionText = await sessionResponse.text();
  assert.equal(sessionResponse.status, 200, sessionText);
  const session = JSON.parse(sessionText) as { user?: { id?: string; email?: string } };
  assert.equal(session.user?.id, signUp.user?.id);
  assert.equal(session.user?.email, email);

  const userId = signUp.user?.id ?? "";
  const folders = await db.select().from(folder).where(eq(folder.ownerUserId, userId));
  assert.equal(folders.length, 1);
  assert.equal(folders[0]?.kind, "personal");
  assert.equal(folders[0]?.name, "Personal");

  const created = await createItem(
    { id: userId, email, name: "Ada" },
    { folderId: folders[0]!.id, name: "OpenAI", kind: "api_key", secret },
  );
  assert.equal(JSON.stringify(created).includes(secret), false);
  const [stored] = await db.select().from(item).where(eq(item.id, created.id));
  assert.ok(stored);
  assert.equal(stored.ciphertext === secret, false);
  assert.equal(
    decryptString({
      wrappedDek: stored.wrappedDek,
      dekIv: stored.dekIv,
      dekTag: stored.dekTag,
      ciphertext: stored.ciphertext,
      iv: stored.iv,
      tag: stored.tag,
    }),
    secret,
  );
  const events = await db.select().from(auditEvent).where(eq(auditEvent.action, "item.create"));
  assert.equal(events.length, 1);
  assert.equal(JSON.stringify(events[0]?.metadata).includes(secret), false);

  await client.close();
});
