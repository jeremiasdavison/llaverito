import { ConfigError, HttpError } from "./errors";
import { safeLog } from "./redact";
import type { ZodType } from "zod";

export function json(body: unknown, status = 200) {
  return Response.json(body, {
    status,
    headers: {
      "Cache-Control": "no-store",
      Pragma: "no-cache",
    },
  });
}

export function clientIp(request: Request): string | null {
  const forwarded = request.headers.get("x-forwarded-for");
  const value = forwarded?.split(",")[0]?.trim() || request.headers.get("x-real-ip") || "";
  return value ? value.slice(0, 64) : null;
}

export function assertSameOrigin(request: Request) {
  const fetchSite = request.headers.get("sec-fetch-site");
  if (fetchSite === "cross-site") throw new HttpError(403, "Origen no permitido");
  const origin = request.headers.get("origin");
  const host = request.headers.get("x-forwarded-host") ?? request.headers.get("host");
  if (!origin || !host) throw new HttpError(403, "Origen no permitido");
  let originHost = "";
  try {
    originHost = new URL(origin).host;
  } catch {
    throw new HttpError(403, "Origen no permitido");
  }
  const allowed = new Set(host.split(",").map((entry) => entry.trim()));
  if (!allowed.has(originHost)) throw new HttpError(403, "Origen no permitido");
}

export async function readJson<T>(request: Request, schema: ZodType<T>): Promise<T> {
  const type = request.headers.get("content-type") ?? "";
  if (!type.includes("application/json")) throw new HttpError(415, "Se espera JSON");
  const text = await request.text();
  if (text.length > 96_000) throw new HttpError(413, "El cuerpo es demasiado grande");
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    throw new HttpError(400, "JSON inválido");
  }
  const result = schema.safeParse(parsed);
  if (!result.success) {
    throw new HttpError(400, result.error.issues[0]?.message ?? "Datos inválidos");
  }
  return result.data;
}

export function handle(request: Request, fn: () => Promise<Response>) {
  return fn().catch((error: unknown) => {
    if (error instanceof HttpError) return json({ error: error.message }, error.status);
    if (error instanceof ConfigError) {
      return json(
        {
          error:
            "Falta configurar la base o las claves. Revisá DATABASE_URL, BETTER_AUTH_SECRET y ENCRYPTION_KEY.",
        },
        503,
      );
    }
    safeLog("request failed", {
      path: new URL(request.url).pathname,
      name: error instanceof Error ? error.name : "Error",
    });
    return json({ error: "Error interno" }, 500);
  });
}

export function isUniqueViolation(error: unknown): boolean {
  const seen = new Set<unknown>();
  let current: unknown = error;
  while (current && typeof current === "object" && !seen.has(current)) {
    seen.add(current);
    if ("code" in current && (current as { code?: string }).code === "23505") return true;
    const message = "message" in current ? String((current as { message?: unknown }).message) : "";
    if (message.includes("duplicate key")) return true;
    current = "cause" in current ? (current as { cause?: unknown }).cause : undefined;
  }
  return false;
}
