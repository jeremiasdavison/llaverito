export function safeAppPath(value: string | undefined): string {
  if (!value || value.length > 200) return "/app";
  if (value !== "/app" && !value.startsWith("/app/") && !value.startsWith("/app?")) return "/app";
  if (value.startsWith("//") || value.includes("\\") || value.includes("://")) return "/app";
  if (/[\u0000-\u001f]/.test(value)) return "/app";
  return value;
}
