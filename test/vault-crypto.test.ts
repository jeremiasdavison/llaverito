import assert from "node:assert/strict";
import nodeCrypto from "node:crypto";
import test from "node:test";
import { decryptSecret, deriveKek, encryptSecret, generateSecretKey, randomSalt, sealJson } from "../src/lib/vault-crypto.ts";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

test("client envelope hides the secret and round-trips with password plus secret key", async () => {
  const secretKey = await generateSecretKey();
  const salt = randomSalt();
  const kek = await deriveKek("correct-horse-1", secretKey, salt);
  const envelope = await encryptSecret("sk-test-value-not-real", kek);
  assert.equal(JSON.stringify(envelope).includes("sk-test-value-not-real"), false);
  assert.equal(await decryptSecret(envelope, kek), "sk-test-value-not-real");
  const wrong = await deriveKek("correct-horse-1", await generateSecretKey(), salt);
  await assert.rejects(() => decryptSecret(envelope, wrong));
});

test("browser seal opens with the runner script", async () => {
  const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync("x25519");
  const publicRaw = Buffer.from(publicKey.export({ format: "der", type: "spki" })).subarray(-32);
  const privateRaw = Buffer.from(privateKey.export({ format: "der", type: "pkcs8" })).subarray(-32);
  const publicB64 = publicRaw.toString("base64url");
  const sealed = await sealJson({ entries: [{ envKey: "DEMO_TOKEN", secret: "abc123xyz" }] }, publicB64);
  assert.equal(JSON.stringify(sealed).includes("abc123xyz"), false);
  const dir = mkdtempSync(join(tmpdir(), "llaverito-"));
  const file = join(dir, "sealed.json");
  writeFileSync(file, JSON.stringify({ sealed }));
  const result = spawnSync("node", ["scripts/unseal.mjs", file], {
    env: { ...process.env, LLAVERITO_WRAP_PRIVATE_KEY: privateRaw.toString("base64url") },
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /DEMO_TOKEN="abc123xyz"/);
});
