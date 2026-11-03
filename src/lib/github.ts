import "server-only";
import { and, eq } from "drizzle-orm";
import { getDb } from "./db";
import { HttpError } from "./errors";
import { account } from "./schema";
import type { Actor } from "./types";

export async function githubAccount(actor: Actor) {
  const db = await getDb();
  const [row] = await db
    .select({ accessToken: account.accessToken })
    .from(account)
    .where(and(eq(account.userId, actor.id), eq(account.providerId, "github")))
    .limit(1);
  return row?.accessToken ?? null;
}

export async function listGithubRepos(actor: Actor) {
  const token = await githubAccount(actor);
  if (!token) throw new HttpError(404, "Conectá GitHub para ver repositorios");
  const response = await fetch(
    "https://api.github.com/user/repos?per_page=100&sort=updated&affiliation=owner,collaborator,organization_member",
    {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/vnd.github+json",
        "User-Agent": "llaverito",
      },
    },
  );
  if (!response.ok) throw new HttpError(502, "GitHub no devolvió los repositorios");
  const payload = (await response.json()) as { full_name?: string; private?: boolean }[];
  return payload
    .filter((repo) => repo.full_name)
    .map((repo) => ({ fullName: repo.full_name as string, private: Boolean(repo.private) }));
}
