import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const root = new URL("..", import.meta.url).pathname;
const skipDirs = new Set([".git", ".next", ".vercel", "node_modules", "dist", "coverage", "out"]);
const skipFiles = new Set([
  ".env",
  ".env.local",
  ".env.development.local",
  ".env.test.local",
  ".env.production.local",
]);
const textExt = /\.(?:ts|tsx|js|mjs|cjs|md|json|yml|yaml|css|sql|txt|example)$/;
const privateKey = /-----BEGIN [A-Z ]*PRIVATE KEY-----/;
const databaseUrl = /postgres(?:ql)?:\/\/([^:\s/@]+):([^@\s/]+)@/gi;
const placeholderPasswords = new Set([
  "USER",
  "PASSWORD",
  "password",
  "PASS",
  "secret",
  "example",
  "changeme",
  "replace-with",
]);

const problems = [];

function walk(dir) {
  for (const entry of readdirSync(dir)) {
    if (skipDirs.has(entry) || skipFiles.has(entry)) continue;
    const path = join(dir, entry);
    const stat = statSync(path);
    if (stat.isDirectory()) {
      walk(path);
      continue;
    }
    if (!textExt.test(entry) || stat.size > 1_000_000) continue;
    const text = readFileSync(path, "utf8");
    const rel = relative(root, path);
    if (privateKey.test(text)) problems.push(`${rel}: contiene un bloque PRIVATE KEY`);
    for (const match of text.matchAll(databaseUrl)) {
      const password = match[2] ?? "";
      if (!placeholderPasswords.has(password)) {
        problems.push(`${rel}: connection string con clave que no es un placeholder`);
      }
    }
  }
}

walk(root);
if (problems.length) {
  console.error(problems.join("\n"));
  process.exit(1);
}
console.log("repo check ok");
