export const AGENT_SCOPES = ["read", "request", "redeem"] as const;
export type AgentScope = (typeof AGENT_SCOPES)[number];

export const AGENT_TOKEN_DEFAULT_TTL_DAYS = 90;
export const AGENT_TOKEN_MAX_TTL_DAYS = 90;

export function parseScopes(value: string | null | undefined): AgentScope[] {
  if (!value) return [];
  const seen = new Set<AgentScope>();
  for (const part of value.split(",")) {
    const scope = part.trim();
    if (!AGENT_SCOPES.includes(scope as AgentScope)) return [];
    seen.add(scope as AgentScope);
  }
  return AGENT_SCOPES.filter((scope) => seen.has(scope));
}

export function formatScopes(scopes: readonly string[]): string {
  return parseScopes(scopes.join(",")).join(",");
}

export function tokenExpiry(ttlDays: number, now = Date.now()): Date {
  const days = Math.min(Math.max(Math.floor(ttlDays) || AGENT_TOKEN_DEFAULT_TTL_DAYS, 1), AGENT_TOKEN_MAX_TTL_DAYS);
  return new Date(now + days * 24 * 60 * 60 * 1000);
}
