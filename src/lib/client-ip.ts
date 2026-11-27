import crypto from "node:crypto";

const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const IPV6 = /^[0-9a-f:]+$/i;

function isIp(value: string): boolean {
  if (value.length > 64) return false;
  if (IPV4.test(value)) return value.split(".").every((part) => Number(part) <= 255);
  return value.includes(":") && IPV6.test(value);
}

function firstIp(header: string | null): string | null {
  if (!header) return null;
  const candidate = header.split(",")[0]?.trim() ?? "";
  return isIp(candidate) ? candidate : null;
}

export function trustedClientIp(headers: { get(name: string): string | null }): string | null {
  const vercel = firstIp(headers.get("x-vercel-forwarded-for"));
  if (vercel) return vercel;
  const real = headers.get("x-real-ip")?.trim() ?? "";
  if (isIp(real)) return real;
  return firstIp(headers.get("x-forwarded-for"));
}

export function authCallerKey(headers: { get(name: string): string | null } | undefined): string {
  const ip = headers ? trustedClientIp(headers) : null;
  if (ip) return ip;
  const cookie = headers?.get("cookie") ?? "";
  for (const part of cookie.split(";")) {
    const separator = part.indexOf("=");
    if (separator <= 0) continue;
    const name = part.slice(0, separator).trim();
    if (!name.endsWith("session_token")) continue;
    const value = part.slice(separator + 1).trim();
    if (!value) continue;
    return `session:${crypto.createHash("sha256").update(value).digest("hex").slice(0, 24)}`;
  }
  return "no-ip";
}
