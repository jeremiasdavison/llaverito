const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const IPV6 = /^[0-9a-f:]+$/i;

function isIp(value: string): boolean {
  if (value.length > 64) return false;
  if (IPV4.test(value)) return value.split(".").every((part) => Number(part) <= 255);
  return value.includes(":") && IPV6.test(value);
}

function lastIp(header: string | null): string | null {
  if (!header) return null;
  const parts = header.split(",").map((part) => part.trim()).filter(Boolean);
  const candidate = parts[parts.length - 1];
  return candidate && isIp(candidate) ? candidate : null;
}

export function trustedClientIp(headers: { get(name: string): string | null }): string | null {
  const vercel = lastIp(headers.get("x-vercel-forwarded-for"));
  if (vercel) return vercel;
  const real = headers.get("x-real-ip")?.trim() ?? "";
  if (isIp(real)) return real;
  return lastIp(headers.get("x-forwarded-for"));
}
