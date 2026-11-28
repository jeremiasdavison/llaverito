import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

// La CSP del proxy usa un nonce por request con 'strict-dynamic'. Una página prerenderizada sale
// con <script> sin nonce, el navegador los bloquea y el form cae a un GET con la contraseña en la URL.

const root = fileURLToPath(new URL("..", import.meta.url));
const appDir = join(root, "src", "app");
const segmentFiles = /^(page|layout|not-found|error|global-error|loading|template|default)\.tsx$/;

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((entry) => {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) return entry === "api" ? [] : walk(path);
    return segmentFiles.test(entry) ? [path] : [];
  });
}

const source = (path: string) => readFileSync(path, "utf8");
const forcesDynamic = (text: string) =>
  /export const dynamic\s*=\s*["']force-dynamic["']/.test(text) ||
  (/import\s*\{[^}]*\bconnection\b[^}]*\}\s*from\s*["']next\/server["']/.test(text) &&
    /await connection\(\)/.test(text));
const forbidsStatic = (text: string) => /export const dynamic\s*=\s*["'](force-static|error)["']/.test(text);

function dynamicLayoutAbove(file: string) {
  let dir = dirname(file);
  while (dir.startsWith(appDir)) {
    const layout = join(dir, "layout.tsx");
    try {
      if (forcesDynamic(source(layout))) return relative(root, layout);
    } catch {
      // ese segmento no tiene layout
    }
    if (dir === appDir) break;
    dir = dirname(dir);
  }
  return null;
}

test("el layout raíz y las páginas públicas se renderizan por request", () => {
  const rootLayout = source(join(appDir, "layout.tsx"));
  assert.ok(forcesDynamic(rootLayout), "src/app/layout.tsx tiene que forzar render dinámico");
  for (const page of ["page.tsx", join("sign-up", "page.tsx"), join("sign-in", "page.tsx")]) {
    assert.ok(forcesDynamic(source(join(appDir, page))), `src/app/${page} tiene que ser dinámica`);
  }
});

test("ninguna página o layout de src/app queda estático", () => {
  const files = walk(appDir);
  assert.ok(files.length >= 5);
  for (const file of files) {
    const rel = relative(root, file).split(sep).join("/");
    const text = source(file);
    assert.equal(forbidsStatic(text), false, `${rel} fuerza render estático`);
    assert.ok(forcesDynamic(text) || dynamicLayoutAbove(file), `${rel} no es dinámico ni cuelga de un layout dinámico`);
  }
});

test("los forms de auth y 2FA usan POST y cancelan el envío nativo", () => {
  const authForms = ["auth-form.tsx", "step-up-dialog.tsx", "security-client.tsx"];
  for (const name of authForms) {
    const text = source(join(root, "src", "components", name));
    const forms = text.match(/<form\b[^>]*>/g) ?? [];
    assert.ok(forms.length > 0, `${name} no tiene <form>`);
    for (const form of forms) {
      assert.match(form, /method="post"/, `${name}: ${form}`);
      assert.match(form, /onSubmit=/, `${name}: ${form}`);
    }
    const handlers = text.match(/event\.preventDefault\(\)/g) ?? [];
    assert.ok(handlers.length >= forms.length, `${name}: cada onSubmit tiene que llamar a preventDefault`);
  }
});
