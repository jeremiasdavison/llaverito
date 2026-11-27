import crypto from "node:crypto";

export const STEP_UP_COOKIE = "llv_step";
export const STEP_UP_TTL_MS = 5 * 60 * 1000;

export type StepUpClaims = {
  u: string;
  s: string;
  e: number;
  f: 0 | 1;
};

export function signStepUp(claims: StepUpClaims, secret: string): string {
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const mac = crypto.createHmac("sha256", secret).update(payload).digest("base64url");
  return `${payload}.${mac}`;
}

export function readStepUp(token: string, secret: string, now = Date.now()): StepUpClaims | null {
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [payload, mac] = parts;
  if (!payload || !mac) return null;
  const expected = crypto.createHmac("sha256", secret).update(payload).digest("base64url");
  const left = Buffer.from(mac);
  const right = Buffer.from(expected);
  if (left.length !== right.length || !crypto.timingSafeEqual(left, right)) return null;
  try {
    const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as Partial<StepUpClaims>;
    if (typeof claims.u !== "string" || claims.u.length < 1 || typeof claims.s !== "string" || claims.s.length < 1) {
      return null;
    }
    if (claims.f !== 0 && claims.f !== 1) return null;
    if (typeof claims.e !== "number" || !Number.isFinite(claims.e)) return null;
    if (claims.e <= now || claims.e > now + STEP_UP_TTL_MS + 5_000) return null;
    return { u: claims.u, s: claims.s, e: claims.e, f: claims.f };
  } catch {
    return null;
  }
}

export function stepUpCookieName(secure: boolean) {
  return secure ? `__Host-${STEP_UP_COOKIE}` : STEP_UP_COOKIE;
}

export function stepUpSetCookie(token: string, secure: boolean): string {
  const parts = [
    `${stepUpCookieName(secure)}=${token}`,
    "HttpOnly",
    "SameSite=Strict",
    "Path=/",
    `Max-Age=${Math.floor(STEP_UP_TTL_MS / 1000)}`,
  ];
  if (secure) parts.push("Secure");
  return parts.join("; ");
}

export function readCookie(header: string | null, name: string): string | null {
  if (!header) return null;
  for (const part of header.split(";")) {
    const separator = part.indexOf("=");
    if (separator <= 0) continue;
    if (part.slice(0, separator).trim() !== name) continue;
    return part.slice(separator + 1).trim();
  }
  return null;
}
