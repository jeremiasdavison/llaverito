import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { formatScopes, parseScopes, tokenExpiry } from "../src/lib/agent-scopes.ts";
import { authCallerKey, trustedClientIp } from "../src/lib/client-ip.ts";
import { sameOriginAllowed } from "../src/lib/origin-check.ts";
import { trustedOriginsFromEnv } from "../src/lib/origins.ts";
import { isStrongPassword, passwordIssues, passwordStrength } from "../src/lib/passwords.ts";
import { safeAppPath } from "../src/lib/paths.ts";
import { breachedPassword } from "../src/lib/pwned.ts";
import { consumeMemoryLimit, resetMemoryLimits } from "../src/lib/rate-limit-memory.ts";
import { readStepUp, signStepUp, STEP_UP_TTL_MS } from "../src/lib/step-up-token.ts";

test("trusted origins stay on this deployment", () => {
  const origins = trustedOriginsFromEnv({
    NODE_ENV: "production",
    BETTER_AUTH_URL: "https://llaverito-six.vercel.app",
    VERCEL_URL: "llaverito-abc123-team.vercel.app",
    VERCEL_BRANCH_URL: "llaverito-git-main-team.vercel.app",
    BETTER_AUTH_TRUSTED_ORIGINS: "https://cofre.example.com, https://*.vercel.app, http://evil.example",
  });
  assert.deepEqual(origins, [
    "https://llaverito-six.vercel.app",
    "https://llaverito-git-main-team.vercel.app",
    "https://llaverito-abc123-team.vercel.app",
    "https://cofre.example.com",
  ]);
  assert.equal(origins.some((origin) => origin.includes("*")), false);
});

test("auth source does not trust every vercel.app host", () => {
  const source = readFileSync(new URL("../src/lib/auth.ts", import.meta.url), "utf8");
  assert.equal(source.includes("*.vercel.app"), false);
  assert.equal(source.includes("trustedOriginsFromEnv"), true);
});

test("password policy keeps passphrases and rejects common secrets", () => {
  assert.equal(isStrongPassword("correct-horse-1"), true);
  assert.equal(isStrongPassword("Password1234"), false);
  assert.equal(isStrongPassword("qwertyuiop12"), false);
  assert.ok(passwordIssues("password123456").some((issue) => issue.includes("común")));
  assert.equal(passwordStrength("correct-horse-battery-1").score >= 3, true);
  assert.equal(passwordStrength("Password1234").label, "Débil");
});

test("pwned check uses the hash prefix and fails open on network errors", async () => {
  const previous = process.env.PWNED_PASSWORD_CHECK;
  delete process.env.PWNED_PASSWORD_CHECK;
  let requested = "";
  const breached = await breachedPassword("correct-horse-1", async (input) => {
    requested = input;
    return new Response("0018A45C4D1DEF81644B54AB7F969B88D65:1\nFF00:0\n", { status: 200 });
  });
  assert.equal(breached, false);
  assert.match(requested, /^https:\/\/api\.pwnedpasswords\.com\/range\/[0-9A-F]{5}$/);
  const unavailable = await breachedPassword("correct-horse-1", async () => {
    throw new Error("offline");
  });
  assert.equal(unavailable, null);
  process.env.PWNED_PASSWORD_CHECK = "false";
  assert.equal(await breachedPassword("correct-horse-1", async () => {
    throw new Error("should not be called");
  }), null);
  if (previous === undefined) delete process.env.PWNED_PASSWORD_CHECK;
  else process.env.PWNED_PASSWORD_CHECK = previous;
});

test("memory limiter blocks the next attempt inside the window", () => {
  resetMemoryLimits();
  assert.equal(consumeMemoryLimit("ip", 2, 60, 1_000).allowed, true);
  assert.equal(consumeMemoryLimit("ip", 2, 60, 1_100).allowed, true);
  assert.equal(consumeMemoryLimit("ip", 2, 60, 1_200).allowed, false);
  assert.equal(consumeMemoryLimit("ip", 2, 60, 61_200).allowed, true);
});

test("step-up token expires and is bound to the signature", () => {
  const now = 1_700_000_000_000;
  const token = signStepUp({ u: "user", s: "session", f: 1, e: now + STEP_UP_TTL_MS }, "secret-secret-secret-secret");
  assert.deepEqual(readStepUp(token, "secret-secret-secret-secret", now + 1_000), {
    u: "user",
    s: "session",
    f: 1,
    e: now + STEP_UP_TTL_MS,
  });
  assert.equal(readStepUp(token, "other-secret-other-secret-other", now + 1_000), null);
  assert.equal(readStepUp(token, "secret-secret-secret-secret", now + STEP_UP_TTL_MS), null);
});

test("agent scopes reject unknown permissions and cap lifetime", () => {
  assert.deepEqual(parseScopes("redeem,read"), ["read", "redeem"]);
  assert.deepEqual(parseScopes("read,admin"), []);
  assert.equal(formatScopes(["redeem", "read"]), "read,redeem");
  const expiry = tokenExpiry(400, Date.UTC(2026, 0, 1));
  assert.equal(expiry.toISOString(), new Date(Date.UTC(2026, 0, 1) + 90 * 24 * 60 * 60 * 1000).toISOString());
});

test("same-origin check ignores a spoofed forwarded host", () => {
  const ok = new Request("https://llaverito-six.vercel.app/api/items", {
    method: "POST",
    headers: {
      origin: "https://llaverito-six.vercel.app",
      host: "llaverito-six.vercel.app",
      "x-forwarded-host": "attacker.vercel.app",
      "sec-fetch-site": "same-origin",
    },
  });
  assert.equal(sameOriginAllowed(ok), true);
  const cross = new Request("https://llaverito-six.vercel.app/api/items", {
    method: "POST",
    headers: {
      origin: "https://attacker.vercel.app",
      host: "llaverito-six.vercel.app",
      "x-forwarded-host": "attacker.vercel.app",
      "sec-fetch-site": "same-site",
    },
  });
  assert.equal(sameOriginAllowed(cross), false);
});

test("client ip prefers the platform header over a spoofed forwarded list", () => {
  const headers = new Headers({
    "x-forwarded-for": "1.2.3.4, 5.6.7.8",
    "x-real-ip": "203.0.113.10",
    "x-vercel-forwarded-for": "198.51.100.20, 203.0.113.8",
  });
  assert.equal(trustedClientIp(headers), "198.51.100.20");
  assert.equal(trustedClientIp(new Headers({ "x-real-ip": "203.0.113.10" })), "203.0.113.10");
});

test("auth rate-limit keys stay per caller when the request object is absent", () => {
  const first = new Headers({ "x-vercel-forwarded-for": "198.51.100.4, 203.0.113.9" });
  const second = new Headers({ "x-vercel-forwarded-for": "198.51.100.5, 203.0.113.9" });
  assert.equal(authCallerKey(first), "198.51.100.4");
  assert.notEqual(authCallerKey(first), authCallerKey(second));
  const onlyCookies = [
    new Headers({ cookie: "better-auth.session_token=alpha" }),
    new Headers({ cookie: "better-auth.session_token=beta" }),
  ].map((headers) => authCallerKey(headers));
  assert.equal(onlyCookies[0]?.startsWith("session:"), true);
  assert.notEqual(onlyCookies[0], onlyCookies[1]);
  assert.notEqual(onlyCookies[0], "unknown");
  assert.notEqual(onlyCookies[0], "no-ip");
});

test("next path stays inside the app", () => {
  assert.equal(safeAppPath("/app/security"), "/app/security");
  assert.equal(safeAppPath("/app.evil.com"), "/app");
  assert.equal(safeAppPath("//evil.com"), "/app");
  assert.equal(safeAppPath("/app/\\evil"), "/app");
});
