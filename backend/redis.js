import { createClient } from "redis";
import dotenv from "dotenv";
dotenv.config();

export const redis = createClient({
  url: process.env.REDIS_URL || "redis://localhost:6379",
});

redis.on("connect", () => console.log("🔌 Redis connected"));
redis.on("error", (err) => console.log("❌ Redis Error:", err));

await redis.connect();
