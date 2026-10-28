import "server-only";
import { betterAuth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { APIError, createAuthMiddleware } from "better-auth/api";
import { nextCookies } from "better-auth/next-js";
import { ensurePersonalFolder } from "./bootstrap";
import { getDb } from "./db";
import { ConfigError } from "./errors";
import { isStrongPassword } from "./passwords";
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

async function createAuth() {
  const db = await getDb();
  const secure = process.env.NODE_ENV === "production";
  return betterAuth({
    secret: requireSecret(),
    baseURL: baseURL(),
    trustedOrigins: ["https://*.vercel.app"],
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
      cookieCache: { enabled: true, maxAge: 5 * 60 },
    },
    rateLimit: {
      enabled: true,
      storage: "database",
      window: 60,
      max: 30,
      customRules: {
        "/sign-in/email": { window: 60, max: 5 },
        "/sign-up/email": { window: 60 * 60, max: 8 },
      },
    },
    advanced: {
      useSecureCookies: secure,
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
        if (ctx.path !== "/sign-up/email") return;
        const password = (ctx.body as { password?: unknown } | undefined)?.password;
        if (typeof password !== "string" || !isStrongPassword(password)) {
          throw APIError.from("BAD_REQUEST", {
            code: "WEAK_PASSWORD",
            message: "La contraseña necesita 12 caracteres o más, con letras y números.",
          });
        }
      }),
    },
    plugins: [nextCookies()],
  });
}

export function getAuth() {
  if (singleton) return singleton;
  const created = createAuth();
  singleton = created;
  return created;
}
