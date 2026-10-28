import "server-only";
import { headers } from "next/headers";
import { getAuth } from "./auth";
import { ConfigError, HttpError } from "./errors";
import type { Actor } from "./types";

export async function getSessionUser(): Promise<Actor | null> {
  try {
    const session = await (await getAuth()).api.getSession({ headers: await headers() });
    if (!session?.user) return null;
    return {
      id: session.user.id,
      email: session.user.email.toLowerCase(),
      name: session.user.name,
    };
  } catch (error) {
    if (error instanceof ConfigError) throw error;
    throw new ConfigError();
  }
}

export async function requireUser() {
  const user = await getSessionUser();
  if (!user) throw new HttpError(401, "Tenés que iniciar sesión");
  return user;
}
