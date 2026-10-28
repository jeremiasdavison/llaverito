import { readFileSync } from "node:fs";
import { neon } from "@neondatabase/serverless";
import { statements } from "../src/lib/statements.ts";

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

loadLocalEnv();
const url = process.env.DATABASE_URL || process.env.POSTGRES_URL;
if (!url) {
  console.error("Falta DATABASE_URL.");
  process.exit(1);
}

const sql = neon(url);
for (const statement of statements) {
  await sql.query(statement);
}
console.log(`Schema listo (${statements.length} sentencias).`);
