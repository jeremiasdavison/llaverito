import { databaseUrlFrom } from "./database-url";

export type SecretStatus = "configured" | "missing" | "invalid";
export type AuthUrlStatus = "unset" | "configured" | "invalid";
export type DatabaseStatus = "missing" | "up" | "down";
export type SchemaStatus = "unknown" | "ready" | "failed";

export type ReadinessInput = {
  encryption: SecretStatus;
  authSecret: SecretStatus;
  authUrl: AuthUrlStatus;
  database: DatabaseStatus;
  schema: SchemaStatus;
  latencyMs: number | null;
};

export type ReadinessReport = ReadinessInput & {
  ok: boolean;
  missing: string[];
  invalid: string[];
  hint: string;
};

export function readAuthSecretStatus(env: NodeJS.ProcessEnv = process.env): SecretStatus {
  const secret = env.BETTER_AUTH_SECRET;
  if (!secret || secret.includes("replace-with")) return "missing";
  if (secret.length < 32) return "invalid";
  return "configured";
}

export function readAuthUrlStatus(env: NodeJS.ProcessEnv = process.env): AuthUrlStatus {
  const value = env.BETTER_AUTH_URL;
  if (!value || value.includes("replace-with")) return "unset";
  try {
    const url = new URL(value);
    if (url.protocol !== "http:" && url.protocol !== "https:") return "invalid";
    return "configured";
  } catch {
    return "invalid";
  }
}

export function readDatabasePresence(env: NodeJS.ProcessEnv = process.env): "present" | "missing" {
  return databaseUrlFrom(env) ? "present" : "missing";
}

export function assessReadiness(input: ReadinessInput): ReadinessReport {
  const missing: string[] = [];
  const invalid: string[] = [];
  if (input.database === "missing") missing.push("DATABASE_URL");
  if (input.authSecret === "missing") missing.push("BETTER_AUTH_SECRET");
  if (input.authSecret === "invalid") invalid.push("BETTER_AUTH_SECRET");
  if (input.encryption === "missing") missing.push("ENCRYPTION_KEY");
  if (input.encryption === "invalid") invalid.push("ENCRYPTION_KEY");

  const ok =
    input.encryption === "configured" &&
    input.authSecret === "configured" &&
    input.authUrl !== "invalid" &&
    input.database === "up" &&
    input.schema === "ready";

  return { ...input, ok, missing, invalid, hint: hintFor(input, missing, invalid, ok) };
}

function hintFor(
  input: ReadinessInput,
  missing: string[],
  invalid: string[],
  ok: boolean,
): string {
  if (ok) return "Listo para crear una cuenta.";
  const parts: string[] = [];
  if (missing.includes("DATABASE_URL")) {
    parts.push(
      "Definí DATABASE_URL (o POSTGRES_URL) con el connection string del pooler de Neon y redeployá.",
    );
  } else if (input.database === "down") {
    parts.push("DATABASE_URL está definida pero la base no responde.");
  } else if (input.schema === "failed") {
    parts.push("La base responde pero no se pudo aplicar el esquema. Corré npm run db:migrate.");
  }
  if (missing.includes("BETTER_AUTH_SECRET") || invalid.includes("BETTER_AUTH_SECRET")) {
    parts.push("Definí BETTER_AUTH_SECRET con al menos 32 caracteres (openssl rand -base64 32).");
  }
  if (missing.includes("ENCRYPTION_KEY") || invalid.includes("ENCRYPTION_KEY")) {
    parts.push("Definí ENCRYPTION_KEY como base64 de 32 bytes. Si ya hay secretos guardados, no la cambies.");
  }
  if (input.authUrl === "invalid") {
    parts.push("BETTER_AUTH_URL tiene que ser una URL http(s), o quedar sin definir.");
  }
  return parts.join(" ") || "El servicio no está listo.";
}
