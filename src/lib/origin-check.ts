export function sameOriginAllowed(request: { url: string; headers: { get(name: string): string | null } }): boolean {
  const fetchSite = request.headers.get("sec-fetch-site");
  if (fetchSite === "cross-site") return false;
  const origin = request.headers.get("origin");
  if (!origin || origin === "null") return false;
  let originHost = "";
  try {
    const url = new URL(origin);
    if (url.protocol !== "https:" && url.protocol !== "http:") return false;
    originHost = url.host;
  } catch {
    return false;
  }
  const hostHeader = request.headers.get("host")?.split(",")[0]?.trim() ?? "";
  let urlHost = "";
  try {
    urlHost = new URL(request.url).host;
  } catch {
    urlHost = "";
  }
  const allowed = new Set([hostHeader, urlHost].filter(Boolean));
  return allowed.has(originHost);
}
