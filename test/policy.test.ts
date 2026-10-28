import assert from "node:assert/strict";
import test from "node:test";
import { maxAccess, canAdminister } from "../src/lib/permissions.ts";
import { isStrongPassword } from "../src/lib/passwords.ts";
import { redact } from "../src/lib/redact.ts";
import { apiKeyHint, itemSchema } from "../src/lib/validate.ts";

test("access rank keeps admin above use", () => {
  assert.equal(maxAccess("use", "admin"), "admin");
  assert.equal(maxAccess("owner", "admin"), "owner");
  assert.equal(canAdminister("use"), false);
  assert.equal(canAdminister("admin"), true);
});

test("password policy rejects short or single-class secrets", () => {
  assert.equal(isStrongPassword("password"), false);
  assert.equal(isStrongPassword("123456789012"), false);
  assert.equal(isStrongPassword("correct-horse-1"), true);
});

test("redaction and hints do not keep the secret", () => {
  const secret = "super-secret-value";
  assert.notEqual(apiKeyHint(secret), secret);
  assert.equal(apiKeyHint(secret).endsWith(secret.slice(-4)), true);
  const cleaned = redact({ name: "openai", secret, note: "ok" }) as { secret: string; name: string };
  assert.equal(cleaned.secret, "[redacted]");
  assert.equal(cleaned.name, "openai");
});

test("item schema rejects an ssh blob without a private key header", () => {
  const result = itemSchema.safeParse({
    folderId: "550e8400-e29b-41d4-a716-446655440000",
    name: "ci",
    kind: "ssh_key",
    secret: "not-a-key-material",
  });
  assert.equal(result.success, false);
});
