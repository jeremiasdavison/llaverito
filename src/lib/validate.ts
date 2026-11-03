import crypto from "node:crypto";
import { z } from "zod";

const envKey = z
  .string()
  .regex(/^[A-Z][A-Z0-9_]{0,63}$/, "La variable debe verse como OPENAI_API_KEY");

const wrapPublicKey = z
  .string()
  .min(40)
  .max(80)
  .regex(/^[A-Za-z0-9_-]+$/, "La clave pública tiene que ir en base64url");

export const folderSchema = z.object({
  name: z.string().trim().min(1, "El nombre es obligatorio").max(80),
  kind: z.enum(["personal", "project"]),
  githubRepo: z
    .string()
    .trim()
    .max(120)
    .regex(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/, "Usá owner/repo")
    .optional()
    .or(z.literal("")),
});

export const folderPatchSchema = z.object({
  name: z.string().trim().min(1).max(80).optional(),
  githubRepo: z
    .string()
    .trim()
    .max(120)
    .regex(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/, "Usá owner/repo")
    .optional()
    .or(z.literal("")),
});

const b64 = z.string().min(8).max(200_000).regex(/^[A-Za-z0-9+/=_-]+$/);

export const envelopeSchema = z
  .object({
    wrappedDek: b64,
    dekIv: b64,
    dekTag: b64,
    ciphertext: b64,
    iv: b64,
    tag: b64,
  })
  .strict();

export const sealedSchema = z
  .object({
    alg: z.literal("X25519-HKDF-SHA256-AES-256-GCM"),
    ephemeralPublicKey: z.string().min(40).max(80),
    iv: z.string().min(8).max(64),
    ciphertext: z.string().min(8).max(500_000),
    tag: z.string().min(8).max(64),
  })
  .strict();

export const itemSchema = z
  .object({
    folderId: z.uuid("Elegí una carpeta"),
    name: z.string().trim().min(1, "El nombre es obligatorio").max(120),
    kind: z.enum(["api_key", "ssh_key"]),
    fingerprint: z.string().max(80).nullable().optional(),
    envelope: envelopeSchema,
  })
  .strict();

export const rotateSchema = z
  .object({
    fingerprint: z.string().max(80).nullable().optional(),
    envelope: envelopeSchema,
  })
  .strict();

export const unlockSchema = z.object({
  confirm: z.literal(true, { error: "Confirmá que querés ver el secreto" }),
});

export const shareSchema = z.object({
  resourceType: z.enum(["folder", "item"]),
  resourceId: z.uuid(),
  grantee: z.string().trim().min(1).max(200),
  permission: z.enum(["use", "admin"]),
});

export const requestSchema = z.object({
  itemIds: z.array(z.uuid()).min(1).max(20),
  purpose: z.string().trim().min(3, "Decí para qué").max(500),
  wrapPublicKey,
});

export const envBindSchema = z.object({
  itemId: z.uuid(),
  envKey,
});

export const envRequestSchema = z.object({
  purpose: z.string().trim().min(3).max(500),
  wrapPublicKey,
  repository: z
    .string()
    .trim()
    .regex(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/)
    .optional()
    .or(z.literal("")),
});

export const decisionSchema = z
  .object({
    action: z.enum(["approve", "deny"]),
    sealed: sealedSchema.optional(),
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.action === "approve" && !value.sealed) {
      ctx.addIssue({ code: "custom", path: ["sealed"], message: "La aprobación tiene que incluir el sobre cifrado en el navegador" });
    }
  });

export const profileSchema = z
  .object({
    kdfSalt: z.string().min(8).max(80),
    kdfIterations: z.literal(600_000),
    publicKey: z.string().min(40).max(80),
    wrappedPrivateKey: b64,
    privateKeyIv: b64,
    privateKeyTag: b64,
  })
  .strict();

export const shareKeysSchema = z
  .object({
    wraps: z
      .array(
        z.object({
          itemId: z.uuid(),
          seal: sealedSchema,
        }),
      )
      .min(1)
      .max(50),
  })
  .strict();

export const githubLinkSchema = z.object({
  githubRepo: z.string().trim().regex(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/, "Usá owner/repo"),
}).strict();

export const agentTokenSchema = z.object({
  name: z.string().trim().min(1).max(80),
});

export const redeemSchema = z.object({
  grantId: z.string().regex(/^llg_[A-Za-z0-9_-]{20,}$/),
});

export function sshFingerprint(publicKey: string): string | null {
  const parts = publicKey.trim().split(/\s+/);
  const type = parts[0] ?? "";
  const material = parts[1] ?? "";
  if (!/^ssh-(ed25519|rsa|ecdsa)/.test(type)) return null;
  const blob = Buffer.from(material, "base64");
  if (blob.length < 16) return null;
  const hash = crypto.createHash("sha256").update(blob).digest("base64").replace(/=+$/, "");
  return `SHA256:${hash}`;
}

export function apiKeyHint(secret: string): string {
  return `••••${secret.slice(-4)}`;
}
