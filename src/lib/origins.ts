const WILDCARD = /[*?]/;

function addOrigin(origins: Set<string>, value: string | undefined) {
  if (!value) return;
  const trimmed = value.trim();
  if (!trimmed || WILDCARD.test(trimmed)) return;
  try {
    const url = new URL(trimmed.includes("://") ? trimmed : `https://${trimmed}`);
    if (url.protocol !== "https:" && url.protocol !== "http:") return;
    const local = url.hostname === "localhost" || url.hostname === "127.0.0.1";
    if (url.protocol === "http:" && !local) return;
    origins.add(url.origin);
  } catch {
    return;
  }
}

export function trustedOriginsFromEnv(env: Record<string, string | undefined>): string[] {
  const origins = new Set<string>();
  addOrigin(origins, env.BETTER_AUTH_URL);
  addOrigin(origins, env.VERCEL_PROJECT_PRODUCTION_URL);
  addOrigin(origins, env.VERCEL_BRANCH_URL);
  addOrigin(origins, env.VERCEL_URL);
  for (const part of (env.BETTER_AUTH_TRUSTED_ORIGINS ?? "").split(",")) addOrigin(origins, part);
  if (env.NODE_ENV !== "production") {
    addOrigin(origins, "http://localhost:3000");
    addOrigin(origins, "http://127.0.0.1:3000");
  }
  return [...origins];
}
