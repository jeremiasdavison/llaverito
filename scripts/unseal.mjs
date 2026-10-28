import crypto from "node:crypto";
import { readFileSync } from "node:fs";

const SPKI = Buffer.from("302a300506032b656e032100", "hex");
const PKCS8 = Buffer.from("302e020100300506032b656e04220420", "hex");
const INFO = Buffer.from("llaverito-seal-v1");

const rawKey = process.env.LLAVERITO_WRAP_PRIVATE_KEY;
if (!rawKey) {
  console.error("Falta LLAVERITO_WRAP_PRIVATE_KEY en el entorno del runner.");
  process.exit(1);
}

const privateRaw = Buffer.from(rawKey, "base64url");
if (privateRaw.length !== 32) {
  console.error("La clave privada tiene que ser X25519 de 32 bytes en base64url.");
  process.exit(1);
}

const file = process.argv[2];
const payload = JSON.parse(file ? readFileSync(file, "utf8") : readFileSync(0, "utf8"));
const sealed = payload.sealed ?? payload;
if (sealed.alg !== "X25519-HKDF-SHA256-AES-256-GCM") {
  console.error("Algoritmo de cierre no soportado.");
  process.exit(1);
}

const privateKey = crypto.createPrivateKey({
  key: Buffer.concat([PKCS8, privateRaw]),
  format: "der",
  type: "pkcs8",
});
const ephemeral = crypto.createPublicKey({
  key: Buffer.concat([SPKI, Buffer.from(sealed.ephemeralPublicKey, "base64url")]),
  format: "der",
  type: "spki",
});
const shared = crypto.diffieHellman({ privateKey, publicKey: ephemeral });
const aesKey = Buffer.from(crypto.hkdfSync("sha256", shared, Buffer.alloc(0), INFO, 32));
const decipher = crypto.createDecipheriv("aes-256-gcm", aesKey, Buffer.from(sealed.iv, "base64url"));
decipher.setAuthTag(Buffer.from(sealed.tag, "base64url"));
const opened = JSON.parse(
  Buffer.concat([
    decipher.update(Buffer.from(sealed.ciphertext, "base64url")),
    decipher.final(),
  ]).toString("utf8"),
);
aesKey.fill(0);

const entries = Array.isArray(opened.entries) ? opened.entries : [];
let unbound = 0;
for (const entry of entries) {
  const value = String(entry.secret ?? "");
  const quoted = `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n")}"`;
  if (typeof entry.envKey === "string" && /^[A-Z][A-Z0-9_]{0,63}$/.test(entry.envKey)) {
    process.stdout.write(`${entry.envKey}=${quoted}\n`);
    continue;
  }
  unbound += 1;
  process.stdout.write(`LLAVERITO_UNBOUND_${unbound}=${quoted}\n`);
  console.error(`LLAVERITO_UNBOUND_${unbound} <- ${String(entry.name ?? "item")}`);
}
