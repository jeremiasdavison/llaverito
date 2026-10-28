import crypto from "node:crypto";

if (typeof window !== "undefined") {
  throw new Error("This module is server-only");
}

const X25519_SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");
const X25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
const SEAL_INFO = Buffer.from("llaverito-seal-v1");

export type Envelope = {
  wrappedDek: string;
  dekIv: string;
  dekTag: string;
  ciphertext: string;
  iv: string;
  tag: string;
};

export type SealedPayload = {
  alg: "X25519-HKDF-SHA256-AES-256-GCM";
  ephemeralPublicKey: string;
  iv: string;
  ciphertext: string;
  tag: string;
};

export function encryptionStatus(): "configured" | "missing" | "invalid" {
  const raw = process.env.ENCRYPTION_KEY;
  if (!raw) return "missing";
  return masterKeyOrNull(raw) ? "configured" : "invalid";
}

function masterKeyOrNull(raw: string): Buffer | null {
  const decoded = Buffer.from(raw, "base64");
  if (decoded.length === 32) return decoded;
  const url = Buffer.from(raw, "base64url");
  return url.length === 32 ? url : null;
}

function masterKey(): Buffer {
  const raw = process.env.ENCRYPTION_KEY;
  const key = raw ? masterKeyOrNull(raw) : null;
  if (!key) throw new Error("ENCRYPTION_KEY is not configured");
  return key;
}

function aesEncrypt(key: Buffer, plaintext: Buffer) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv, ciphertext, tag };
}

function aesDecrypt(key: Buffer, iv: Buffer, ciphertext: Buffer, tag: Buffer) {
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

export function encryptString(plaintext: string): Envelope {
  const dek = crypto.randomBytes(32);
  const body = aesEncrypt(dek, Buffer.from(plaintext, "utf8"));
  const wrapped = aesEncrypt(masterKey(), dek);
  dek.fill(0);
  return {
    wrappedDek: wrapped.ciphertext.toString("base64"),
    dekIv: wrapped.iv.toString("base64"),
    dekTag: wrapped.tag.toString("base64"),
    ciphertext: body.ciphertext.toString("base64"),
    iv: body.iv.toString("base64"),
    tag: body.tag.toString("base64"),
  };
}

export function decryptString(envelope: Envelope): string {
  const dek = aesDecrypt(
    masterKey(),
    Buffer.from(envelope.dekIv, "base64"),
    Buffer.from(envelope.wrappedDek, "base64"),
    Buffer.from(envelope.dekTag, "base64"),
  );
  try {
    const plaintext = aesDecrypt(
      dek,
      Buffer.from(envelope.iv, "base64"),
      Buffer.from(envelope.ciphertext, "base64"),
      Buffer.from(envelope.tag, "base64"),
    );
    return plaintext.toString("utf8");
  } finally {
    dek.fill(0);
  }
}

export function parseWrapPublicKey(value: string): Buffer {
  const raw = Buffer.from(value, "base64url");
  if (raw.length !== 32) {
    throw new Error("wrap public key must be 32 bytes");
  }
  return raw;
}

export function sealJson(value: unknown, recipientPublicRaw: Buffer): SealedPayload {
  if (recipientPublicRaw.length !== 32) throw new Error("recipient public key must be 32 bytes");
  const { publicKey, privateKey } = crypto.generateKeyPairSync("x25519");
  const recipient = crypto.createPublicKey({
    key: Buffer.concat([X25519_SPKI_PREFIX, recipientPublicRaw]),
    format: "der",
    type: "spki",
  });
  const shared = crypto.diffieHellman({ privateKey, publicKey: recipient });
  const aesKey = Buffer.from(crypto.hkdfSync("sha256", shared, Buffer.alloc(0), SEAL_INFO, 32));
  const sealed = aesEncrypt(aesKey, Buffer.from(JSON.stringify(value), "utf8"));
  const ephemeral = Buffer.from(publicKey.export({ format: "der", type: "spki" })).subarray(-32);
  aesKey.fill(0);
  return {
    alg: "X25519-HKDF-SHA256-AES-256-GCM",
    ephemeralPublicKey: ephemeral.toString("base64url"),
    iv: sealed.iv.toString("base64url"),
    ciphertext: sealed.ciphertext.toString("base64url"),
    tag: sealed.tag.toString("base64url"),
  };
}

export function openSeal(sealed: SealedPayload, recipientPrivateRaw: Buffer): unknown {
  if (sealed.alg !== "X25519-HKDF-SHA256-AES-256-GCM") {
    throw new Error("unsupported seal");
  }
  const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([X25519_PKCS8_PREFIX, recipientPrivateRaw]),
    format: "der",
    type: "pkcs8",
  });
  const ephemeral = crypto.createPublicKey({
    key: Buffer.concat([X25519_SPKI_PREFIX, Buffer.from(sealed.ephemeralPublicKey, "base64url")]),
    format: "der",
    type: "spki",
  });
  const shared = crypto.diffieHellman({ privateKey, publicKey: ephemeral });
  const aesKey = Buffer.from(crypto.hkdfSync("sha256", shared, Buffer.alloc(0), SEAL_INFO, 32));
  try {
    const plaintext = aesDecrypt(
      aesKey,
      Buffer.from(sealed.iv, "base64url"),
      Buffer.from(sealed.ciphertext, "base64url"),
      Buffer.from(sealed.tag, "base64url"),
    );
    return JSON.parse(plaintext.toString("utf8")) as unknown;
  } finally {
    aesKey.fill(0);
  }
}

export function hashToken(value: string): string {
  return crypto.createHash("sha256").update(value).digest("hex");
}

export function randomPrefixed(prefix: "llv" | "llg"): string {
  return `${prefix}_${crypto.randomBytes(32).toString("base64url")}`;
}
