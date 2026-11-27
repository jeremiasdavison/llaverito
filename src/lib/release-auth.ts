import "server-only";
import { and, eq } from "drizzle-orm";
import { hashPassword, verifyPassword } from "better-auth/crypto";
import { getAuth } from "./auth";
import { getDb } from "./db";
import { HttpError } from "./errors";
import { consumeRateLimit } from "./rate-limit";
import { account, user } from "./schema";
import { requireSession } from "./session";
import { readCookie, readStepUp, signStepUp, STEP_UP_TTL_MS, stepUpCookieName, stepUpSetCookie } from "./step-up-token";
import type { Actor } from "./types";

function authSecret() {
  const secret = process.env.BETTER_AUTH_SECRET;
  if (!secret || secret.length < 32 || secret.includes("replace-with")) {
    throw new HttpError(503, "Falta configurar la base o las claves. Revisá DATABASE_URL, BETTER_AUTH_SECRET y ENCRYPTION_KEY.");
  }
  return secret;
}

export async function userHasTwoFactor(userId: string) {
  const db = await getDb();
  const [row] = await db
    .select({ enabled: user.twoFactorEnabled })
    .from(user)
    .where(eq(user.id, userId))
    .limit(1);
  return Boolean(row?.enabled);
}

export async function verifyUserPassword(userId: string, password: string) {
  const db = await getDb();
  const [row] = await db
    .select({ password: account.password })
    .from(account)
    .where(and(eq(account.userId, userId), eq(account.providerId, "credential")))
    .limit(1);
  if (!row?.password) {
    await hashPassword(password);
    return false;
  }
  return verifyPassword({ hash: row.password, password });
}

async function verifySecondFactor(request: Request, code: string) {
  const auth = await getAuth();
  const headers = request.headers;
  try {
    if (/^\d{6}$/.test(code)) {
      await auth.api.verifyTOTP({ body: { code, trustDevice: false }, headers, request });
      return true;
    }
    await auth.api.verifyBackupCode({ body: { code, trustDevice: false }, headers, request });
    return true;
  } catch {
    return false;
  }
}

export async function grantStepUp(request: Request, actor: Actor, sessionId: string, password: string, code: string) {
  await consumeRateLimit(`step-up:${actor.id}`, 8, 15 * 60);
  const passwordOk = await verifyUserPassword(actor.id, password);
  if (!passwordOk) throw new HttpError(401, "Contraseña incorrecta.");
  const enabled = await userHasTwoFactor(actor.id);
  if (enabled) {
    if (!code) throw new HttpError(401, "Ingresá el código del segundo factor.");
    const verified = await verifySecondFactor(request, code);
    if (!verified) throw new HttpError(401, "Código incorrecto.");
  }
  const token = signStepUp(
    { u: actor.id, s: sessionId, f: enabled ? 1 : 0, e: Date.now() + STEP_UP_TTL_MS },
    authSecret(),
  );
  return { token, twoFactor: enabled, cookie: stepUpSetCookie(token, process.env.NODE_ENV === "production") };
}

export async function requireRelease(request: Request) {
  const { user: actor, sessionId } = await requireSession();
  if (!(await userHasTwoFactor(actor.id))) {
    throw new HttpError(
      403,
      "Activá el segundo factor en Seguridad antes de revelar, aprobar, compartir o crear un token.",
      "two_factor_required",
    );
  }
  const token = readCookie(request.headers.get("cookie"), stepUpCookieName(process.env.NODE_ENV === "production"));
  const claims = token ? readStepUp(token, authSecret()) : null;
  if (!claims || claims.u !== actor.id || claims.s !== sessionId || claims.f !== 1) {
    throw new HttpError(403, "Confirmá tu contraseña y el código del segundo factor.", "step_up_required", {
      twoFactor: true,
    });
  }
  return actor;
}
