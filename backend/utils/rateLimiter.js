import { redis } from "../redis.js";

export async function rateLimit(key, limit = 10, windowSeconds = 60) {
  try {
    const now = Date.now();
    const windowStart = now - windowSeconds * 1000;

    // Remove expired entries
    await redis.zRemRangeByScore(key, 0, windowStart);

    // Count requests in current window
    const count = await redis.zCard(key);

    if (count >= limit) {
      return false; // limit exceeded
    }

    // Add current request timestamp
    await redis.zAdd(key, { score: now, value: now.toString() });
    // Set TTL to avoid memory leak
    await redis.expire(key, windowSeconds + 1);

    return true; // allowed
  } catch (err) {
    console.error("Rate limiter error:", err);
    return true; // fail-open in case Redis is down
  }
}
