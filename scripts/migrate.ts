import { readFileSync } from "node:fs";
import { neon } from "@neondatabase/serverless";
import { databaseUrlFrom } from "../src/lib/database-url.ts";
import { applySchemaStatements, SCHEMA_MIGRATION_ID } from "../src/lib/migrate-sql.ts";

function loadLocalEnv() {
  try {
    const text = readFileSync(".env.local", "utf8");
    for (const line of text.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const eq = trimmed.indexOf("=");
      if (eq <= 0) continue;
      const key = trimmed.slice(0, eq);
      let value = trimmed.slice(eq + 1);
      if (
        (value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))
      ) {
        value = value.slice(1, -1);
      }
      if (!process.env[key]) process.env[key] = value;
    }
  } catch {
    // .env.local is optional when the variables are already exported.
  }
}

function publicError(error: unknown): string {
  const message = error instanceof Error ? error.message : "error desconocido";
  return message.replace(/postgres(?:ql)?:\/\/\S+/gi, "postgres://[redacted]").slice(0, 400);
}

if (process.env.LLAVERITO_SKIP_LOCAL_ENV !== "1") loadLocalEnv();

const ifConfigured = process.argv.includes("--if-configured");
const url = databaseUrlFrom(process.env);
if (!url) {
  const message = "No hay DATABASE_URL ni POSTGRES_URL.";
  if (ifConfigured) {
    console.log(
      `${message} El build sigue. El esquema se aplica en el primer request cuando la variable exista.`,
    );
    process.exit(0);
  }
  console.error(`${message} Definila y volvé a correr npm run db:migrate.`);
  process.exit(1);
}

try {
  const sql = neon(url);
  await applySchemaStatements((statement, params) => sql.query(statement, params));
  console.log(`Esquema listo (${SCHEMA_MIGRATION_ID}).`);
} catch (error) {
  console.error(`No se pudo aplicar el esquema: ${publicError(error)}`);
  process.exit(1);
}
