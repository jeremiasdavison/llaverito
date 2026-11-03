export const KDF_ITERATIONS = 600_000;
const SEAL_SALT = new TextEncoder().encode("llaverito-seal-salt-v1");
const SEAL_INFO = new TextEncoder().encode("llaverito-seal-v1");

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

function source(bytes: Uint8Array): BufferSource {
  return Uint8Array.from(bytes);
}

function bytesToB64(bytes: Uint8Array) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function b64ToBytes(value: string) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

export function bytesToB64Url(bytes: Uint8Array) {
  return bytesToB64(bytes).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

export function b64UrlToBytes(value: string) {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "===".slice((value.length + 3) % 4);
  return b64ToBytes(padded);
}

async function aesEncrypt(key: CryptoKey, plaintext: Uint8Array) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const packed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, source(plaintext)));
  return {
    iv: bytesToB64(iv),
    ciphertext: bytesToB64(packed.slice(0, -16)),
    tag: bytesToB64(packed.slice(-16)),
  };
}

async function aesDecrypt(key: CryptoKey, ivB64: string, ciphertextB64: string, tagB64: string) {
  const iv = b64ToBytes(ivB64);
  const body = b64ToBytes(ciphertextB64);
  const tag = b64ToBytes(tagB64);
  const packed = new Uint8Array(body.length + tag.length);
  packed.set(body);
  packed.set(tag, body.length);
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, packed));
}

export async function generateSecretKey() {
  return `llv1-${bytesToB64Url(crypto.getRandomValues(new Uint8Array(32)))}`;
}

export function randomSalt() {
  return bytesToB64(crypto.getRandomValues(new Uint8Array(16)));
}

export async function deriveKek(password: string, secretKey: string, saltB64: string) {
  const material = new TextEncoder().encode(`${password}\0${secretKey}`);
  const base = await crypto.subtle.importKey("raw", material, "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: b64ToBytes(saltB64), iterations: KDF_ITERATIONS, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function encryptSecret(secret: string, kek: CryptoKey): Promise<Envelope> {
  const dekRaw = crypto.getRandomValues(new Uint8Array(32));
  const dek = await crypto.subtle.importKey("raw", source(dekRaw), "AES-GCM", false, ["encrypt"]);
  const body = await aesEncrypt(dek, new TextEncoder().encode(secret));
  const wrapped = await aesEncrypt(kek, dekRaw);
  dekRaw.fill(0);
  return {
    wrappedDek: wrapped.ciphertext,
    dekIv: wrapped.iv,
    dekTag: wrapped.tag,
    ciphertext: body.ciphertext,
    iv: body.iv,
    tag: body.tag,
  };
}

export async function decryptSecret(envelope: Envelope, kek: CryptoKey) {
  const dekRaw = await aesDecrypt(kek, envelope.dekIv, envelope.wrappedDek, envelope.dekTag);
  try {
    const dek = await crypto.subtle.importKey("raw", source(dekRaw), "AES-GCM", false, ["decrypt"]);
    const plaintext = await aesDecrypt(dek, envelope.iv, envelope.ciphertext, envelope.tag);
    return new TextDecoder().decode(plaintext);
  } finally {
    dekRaw.fill(0);
  }
}

export async function createIdentity(kek: CryptoKey) {
  const pair = (await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"])) as CryptoKeyPair;
  const publicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const privatePkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  const wrapped = await aesEncrypt(kek, privatePkcs8);
  privatePkcs8.fill(0);
  return {
    publicKey: bytesToB64Url(publicRaw),
    wrappedPrivateKey: wrapped.ciphertext,
    privateKeyIv: wrapped.iv,
    privateKeyTag: wrapped.tag,
  };
}

export async function openIdentity(
  kek: CryptoKey,
  wrappedPrivateKey: string,
  privateKeyIv: string,
  privateKeyTag: string,
) {
  const pkcs8 = await aesDecrypt(kek, privateKeyIv, wrappedPrivateKey, privateKeyTag);
  return crypto.subtle.importKey("pkcs8", source(pkcs8), { name: "X25519" }, false, ["deriveBits"]);
}

async function importPublic(raw: Uint8Array) {
  return crypto.subtle.importKey("raw", source(raw), { name: "X25519" }, true, []);
}

async function sealRaw(plaintext: Uint8Array, recipientPublicRaw: Uint8Array): Promise<SealedPayload> {
  const ephemeral = (await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"])) as CryptoKeyPair;
  const shared = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "X25519", public: await importPublic(recipientPublicRaw) },
      ephemeral.privateKey,
      256,
    ),
  );
  const hkdf = await crypto.subtle.importKey("raw", source(shared), "HKDF", false, ["deriveKey"]);
  const aesKey = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: source(SEAL_SALT), info: source(SEAL_INFO) },
    hkdf,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  const encrypted = await aesEncrypt(aesKey, plaintext);
  const ephRaw = new Uint8Array(await crypto.subtle.exportKey("raw", ephemeral.publicKey));
  shared.fill(0);
  return {
    alg: "X25519-HKDF-SHA256-AES-256-GCM",
    ephemeralPublicKey: bytesToB64Url(ephRaw),
    iv: bytesToB64Url(b64ToBytes(encrypted.iv)),
    ciphertext: bytesToB64Url(b64ToBytes(encrypted.ciphertext)),
    tag: bytesToB64Url(b64ToBytes(encrypted.tag)),
  };
}

export async function sealJson(value: unknown, recipientPublicKey: string) {
  const raw = b64UrlToBytes(recipientPublicKey);
  if (raw.length !== 32) throw new Error("recipient public key must be 32 bytes");
  return sealRaw(new TextEncoder().encode(JSON.stringify(value)), raw);
}

export async function sealDek(dekRaw: Uint8Array, recipientPublicKey: string) {
  return sealJson({ dek: bytesToB64(dekRaw) }, recipientPublicKey);
}

export async function openDek(seal: SealedPayload, privateKey: CryptoKey) {
  const ephemeral = await importPublic(b64UrlToBytes(seal.ephemeralPublicKey));
  const shared = new Uint8Array(
    await crypto.subtle.deriveBits({ name: "X25519", public: ephemeral }, privateKey, 256),
  );
  const hkdf = await crypto.subtle.importKey("raw", source(shared), "HKDF", false, ["deriveKey"]);
  const aesKey = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: source(SEAL_SALT), info: source(SEAL_INFO) },
    hkdf,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
  shared.fill(0);
  const plaintext = await aesDecrypt(
    aesKey,
    bytesToB64(b64UrlToBytes(seal.iv)),
    bytesToB64(b64UrlToBytes(seal.ciphertext)),
    bytesToB64(b64UrlToBytes(seal.tag)),
  );
  const parsed = JSON.parse(new TextDecoder().decode(plaintext)) as { dek?: string };
  if (!parsed.dek) throw new Error("sealed dek missing");
  return b64ToBytes(parsed.dek);
}

export async function decryptWithDek(envelope: Pick<Envelope, "ciphertext" | "iv" | "tag">, dekRaw: Uint8Array) {
  const dek = await crypto.subtle.importKey("raw", source(dekRaw), "AES-GCM", false, ["decrypt"]);
  const plaintext = await aesDecrypt(dek, envelope.iv, envelope.ciphertext, envelope.tag);
  return new TextDecoder().decode(plaintext);
}

export async function exportDek(envelope: Envelope, kek: CryptoKey) {
  return aesDecrypt(kek, envelope.dekIv, envelope.wrappedDek, envelope.dekTag);
}

export function apiKeyHint(secret: string) {
  return `••••${secret.slice(-4)}`;
}

export async function sshFingerprint(publicKey: string) {
  const parts = publicKey.trim().split(/\s+/);
  if (!/^ssh-(ed25519|rsa|ecdsa)/.test(parts[0] ?? "")) return null;
  const blob = b64ToBytes(parts[1] ?? "");
  if (blob.length < 16) return null;
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", blob));
  return `SHA256:${bytesToB64(hash).replace(/=+$/, "")}`;
}
