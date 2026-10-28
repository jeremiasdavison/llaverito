import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

process.env.ENCRYPTION_KEY = Buffer.alloc(32, 9).toString("base64");

const { decryptString, encryptString, openSeal, sealJson } = await import("../src/lib/crypto.ts");

test("envelope encryption round-trips and fails closed on tampering", () => {
  const secret = "sk-test-value-not-real";
  const envelope = encryptString(secret);
  assert.equal(decryptString(envelope), secret);
  assert.equal(JSON.stringify(envelope).includes(secret), false);
  const tampered = { ...envelope, ciphertext: Buffer.from("nope").toString("base64") };
  assert.throws(() => decryptString(tampered));
});

test("seal opens only with the recipient private key", () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("x25519");
  const publicRaw = Buffer.from(publicKey.export({ format: "der", type: "spki" })).subarray(-32);
  const privateRaw = Buffer.from(privateKey.export({ format: "der", type: "pkcs8" })).subarray(-32);
  const sealed = sealJson({ entries: [{ envKey: "DEMO_TOKEN", secret: "abc123xyz" }] }, publicRaw);
  assert.equal(JSON.stringify(sealed).includes("abc123xyz"), false);
  const opened = openSeal(sealed, privateRaw) as { entries: { secret: string }[] };
  assert.equal(opened.entries[0]?.secret, "abc123xyz");
  assert.throws(() => openSeal(sealed, crypto.randomBytes(32)));
});

test("runner unseal script writes env lines and not a log of the algorithm mismatch", () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("x25519");
  const publicRaw = Buffer.from(publicKey.export({ format: "der", type: "spki" })).subarray(-32);
  const privateRaw = Buffer.from(privateKey.export({ format: "der", type: "pkcs8" })).subarray(-32);
  const sealed = sealJson({ entries: [{ envKey: "DEMO_TOKEN", secret: "abc123xyz", name: "demo" }] }, publicRaw);
  const dir = mkdtempSync(join(tmpdir(), "llaverito-"));
  const file = join(dir, "sealed.json");
  writeFileSync(file, JSON.stringify({ sealed }));
  const result = spawnSync("node", ["scripts/unseal.mjs", file], {
    env: { ...process.env, LLAVERITO_WRAP_PRIVATE_KEY: privateRaw.toString("base64url") },
    encoding: "utf8",
  });
  assert.equal(result.status, 0);
  assert.match(result.stdout, /DEMO_TOKEN="abc123xyz"/);
});
