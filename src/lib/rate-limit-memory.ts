type Bucket = { count: number; resetAt: number };

const buckets = new Map<string, Bucket>();
const MAX_BUCKETS = 5_000;

export function resetMemoryLimits() {
  buckets.clear();
}

export function consumeMemoryLimit(key: string, max: number, windowSeconds: number, now = Date.now()) {
  if (buckets.size > MAX_BUCKETS) {
    for (const [entry, bucket] of buckets) {
      if (now >= bucket.resetAt) buckets.delete(entry);
    }
    if (buckets.size > MAX_BUCKETS) {
      const overflow = buckets.size - MAX_BUCKETS;
      let removed = 0;
      for (const entry of buckets.keys()) {
        buckets.delete(entry);
        if (++removed >= overflow) break;
      }
    }
  }
  const current = buckets.get(key);
  if (!current || now >= current.resetAt) {
    buckets.set(key, { count: 1, resetAt: now + windowSeconds * 1000 });
    return { allowed: true, count: 1 };
  }
  current.count += 1;
  return { allowed: current.count <= max, count: current.count };
}
