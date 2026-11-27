import "server-only";
import { headers } from "next/headers";
import { getAuth } from "./auth";
import { ConfigError, HttpError } from "./errors";
import type { Actor } from "./types";

export type SessionContext = { user: Actor; sessionId: string };

export async function getSessionContext(): Promise<SessionContext | null> {
  try {
    const session = await (await getAuth()).api.getSession({ headers: await headers() });
    if (!session?.user || !session.session?.id) return null;
    return {
      user: {
        id: session.user.id,
        email: session.user.email.toLowerCase(),
        name: session.user.name,
      },
      sessionId: session.session.id,
    };
  } catch (error) {
    if (error instanceof ConfigError) throw error;
    throw new ConfigError();
  }
}

export async function getSessionUser(): Promise<Actor | null> {
  const context = await getSessionContext();
  return context?.user ?? null;
}

export async function requireSession() {
  const context = await getSessionContext();
  if (!context) throw new HttpError(401, "Tenés que iniciar sesión");
  return context;
}

export async function requireUser() {
  return (await requireSession()).user;
}
