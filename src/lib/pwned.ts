import crypto from "node:crypto";

type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export async function breachedPassword(password: string, fetchImpl: FetchLike = fetch): Promise<boolean | null> {
  if (process.env.PWNED_PASSWORD_CHECK === "false") return null;
  const sha1 = crypto.createHash("sha1").update(password, "utf8").digest("hex").toUpperCase();
  const prefix = sha1.slice(0, 5);
  const suffix = sha1.slice(5);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 1_500);
  try {
    const response = await fetchImpl(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: { "Add-Padding": "true", "User-Agent": "llaverito-password-check" },
      signal: controller.signal,
    });
    if (!response.ok) return null;
    const body = await response.text();
    for (const line of body.split(/\r?\n/)) {
      const [hash, count] = line.split(":");
      if (hash?.toUpperCase() === suffix && Number(count) > 0) return true;
    }
    return false;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}
