import "server-only";
import { betterAuth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { APIError, createAuthMiddleware } from "better-auth/api";
import { nextCookies } from "better-auth/next-js";
import { twoFactor } from "better-auth/plugins";
import { ensurePersonalFolder } from "./bootstrap";
import { trustedClientIp } from "./client-ip";
import { getDb } from "./db";
import { ConfigError, HttpError } from "./errors";
import { trustedOriginsFromEnv } from "./origins";
import { isStrongPassword, passwordIssues } from "./passwords";
import { breachedPassword } from "./pwned";
import { consumeMemoryLimit } from "./rate-limit-memory";
import { consumeRateLimit } from "./rate-limit";
import { authSchema } from "./schema";

let singleton: ReturnType<typeof createAuth> | null = null;

function baseURL() {
  const value = process.env.BETTER_AUTH_URL;
  if (!value || value.includes("replace-with")) return undefined;
  try {
    return new URL(value).origin;
  } catch {
    return undefined;
  }
}

function requireSecret() {
  const secret = process.env.BETTER_AUTH_SECRET;
  if (!secret || secret.length < 32 || secret.includes("replace-with")) throw new ConfigError();
  return secret;
}

function authRequest(ctx: { request?: Request }) {
  return ctx.request;
}

async function limitAuthAttempt(request: Request | undefined, path: string) {
  const ip = request ? trustedClientIp(request.headers) ?? "unknown" : "unknown";
  const burst = consumeMemoryLimit(`auth-burst:${ip}:${path}`, 5, 60);
  if (!burst.allowed) {
    throw APIError.from("TOO_MANY_REQUESTS", {
      code: "RATE_LIMITED",
      message: "Demasiados intentos. Esperá un momento.",
    });
  }
  try {
    await consumeRateLimit(`auth:${ip}:${path}`, 20, 15 * 60);
  } catch (error) {
    if (error instanceof HttpError) {
      throw APIError.from(error.status === 429 ? "TOO_MANY_REQUESTS" : "SERVICE_UNAVAILABLE", {
        code: error.code ?? "RATE_LIMITED",
        message: error.message,
      });
    }
    throw error;
  }
}

async function createAuth() {
  const db = await getDb();
  const secure = process.env.NODE_ENV === "production";
  return betterAuth({
    appName: "Llaverito",
    secret: requireSecret(),
    baseURL: baseURL(),
    trustedOrigins: trustedOriginsFromEnv(process.env),
    database: drizzleAdapter(db, { provider: "pg", schema: authSchema }),
    emailAndPassword: {
      enabled: true,
      minPasswordLength: 12,
      maxPasswordLength: 128,
      autoSignIn: true,
      requireEmailVerification: false,
    },
    session: {
      expiresIn: 60 * 60 * 24 * 7,
      updateAge: 60 * 60 * 24,
      cookieCache: { enabled: false },
    },
    rateLimit: {
      enabled: true,
      storage: "database",
      window: 60,
      max: 30,
      customRules: {
        "/sign-in/email": { window: 60, max: 5 },
        "/sign-up/email": { window: 60 * 60, max: 5 },
        "/two-factor/verify-totp": { window: 60, max: 5 },
        "/two-factor/verify-backup-code": { window: 60, max: 5 },
      },
    },
    advanced: {
      useSecureCookies: secure,
      ipAddress: {
        ipAddressHeaders: ["x-real-ip", "x-vercel-forwarded-for", "x-forwarded-for"],
      },
      defaultCookieAttributes: {
        sameSite: "lax",
        httpOnly: true,
        secure,
      },
    },
    telemetry: { enabled: false },
    databaseHooks: {
      user: {
        create: {
          after: async (created) => {
            await ensurePersonalFolder(created.id);
          },
        },
      },
    },
    hooks: {
      before: createAuthMiddleware(async (ctx) => {
        const limited =
          ctx.path === "/sign-in/email" || ctx.path === "/sign-up/email" || ctx.path.startsWith("/two-factor/");
        if (limited) await limitAuthAttempt(authRequest(ctx), ctx.path);
        if (ctx.path !== "/sign-up/email") return;
        const body = ctx.body as { password?: unknown; email?: unknown } | undefined;
        const password = body?.password;
        if (typeof password !== "string" || !isStrongPassword(password)) {
          throw APIError.from("BAD_REQUEST", {
            code: "WEAK_PASSWORD",
            message:
              typeof password === "string"
                ? passwordIssues(password)[0] ?? "La contraseña no cumple la política."
                : "La contraseña no cumple la política.",
          });
        }
        const email = typeof body?.email === "string" ? body.email.toLowerCase() : "";
        const local = email.split("@")[0] ?? "";
        if (local.length >= 4 && password.toLowerCase().includes(local)) {
          throw APIError.from("BAD_REQUEST", {
            code: "WEAK_PASSWORD",
            message: "La contraseña no puede incluir el email.",
          });
        }
        if (await breachedPassword(password)) {
          throw APIError.from("BAD_REQUEST", {
            code: "PASSWORD_COMPROMISED",
            message: "Esa contraseña apareció en una filtración. Elegí otra.",
          });
        }
      }),
    },
    plugins: [
      twoFactor({
        issuer: "Llaverito",
        backupCodeOptions: { storeBackupCodes: "encrypted" },
      }),
      nextCookies(),
    ],
  });
}

export function getAuth() {
  if (singleton) return singleton;
  const created = createAuth();
  singleton = created;
  return created;
}
