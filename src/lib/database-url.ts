export function databaseUrlFrom(env: NodeJS.ProcessEnv): string | null {
  const url = env.DATABASE_URL?.trim() || env.POSTGRES_URL?.trim() || "";
  return url.length > 0 ? url : null;
}
