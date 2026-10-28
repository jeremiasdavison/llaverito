const SENSITIVE_KEY =
  /secret|password|token|ciphertext|authorization|private|dek|wrapped|grant|cookie|envelope/i;

export function redact(value: unknown): unknown {
  if (Array.isArray(value)) return value.map((entry) => redact(entry));
  if (!value || typeof value !== "object") {
    if (typeof value === "string" && value.includes("PRIVATE KEY")) return "[redacted]";
    return value;
  }
  const output: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value)) {
    output[key] = SENSITIVE_KEY.test(key) ? "[redacted]" : redact(entry);
  }
  return output;
}

export function safeLog(message: string, meta?: Record<string, unknown>) {
  const payload = meta ? (redact(meta) as Record<string, unknown>) : {};
  console.log(JSON.stringify({ message, ...payload }));
}
