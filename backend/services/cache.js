
import { redis } from "../redis.js";
import { fetchPublicPosts } from "./bluesky.js";

const FEED_LIST_KEY = "global_feed:list";
const FEED_META_KEY = "global_feed:meta";
const MUTEX_KEY = "global_feed:mutex";

const SHORT_TTL = Number(process.env.FEED_SHORT_TTL || 30);   
const ABSOLUTE_TTL = Number(process.env.FEED_ABSOLUTE_TTL || 300); 


async function acquireMutex() {
  try {
    const res = await redis.set(MUTEX_KEY, "1", { NX: true, EX: 10 });
   
    return Boolean(res);
  } catch (err) {
    console.error("Mutex acquire error:", err?.message || err);
    return false;
  }
}


async function refreshCache() {
  try {
    console.log("Fetching Bluesky public timeline with limit:", 20);
    const posts = await fetchPublicPosts(20);

    if (!posts || !posts.length) {
      console.log("No posts fetched during refresh");
      return posts || [];
    }

    
    await redis.del(FEED_LIST_KEY);

   
    const values = posts.map(p => JSON.stringify(p));
    if (values.length) {
      
      await redis.rPush(FEED_LIST_KEY, values);
    }

    const ts = Date.now().toString();
    await redis.hSet(FEED_META_KEY, { updatedAt: ts });

   
    await redis.expire(FEED_LIST_KEY, SHORT_TTL);
    await redis.expire(FEED_META_KEY, SHORT_TTL);

    console.log(`🌐 Cache refreshed with ${posts.length} posts and short TTL ${SHORT_TTL}s`);
    return posts;
  } catch (err) {
    console.error("refreshCache error:", err?.message || err);
    return [];
  } finally {
    
    try {
      await redis.del(MUTEX_KEY);
    } catch (e) {
      // ignore
    }
  }
}

export async function getFeed() {
  try {
    const meta = await redis.hGetAll(FEED_META_KEY).catch(() => ({}));
    const now = Date.now();

  
    if (meta && meta.updatedAt) {
      const age = (now - Number(meta.updatedAt)) / 1000;
      if (age > ABSOLUTE_TTL) {
        console.log("🔄 Absolute TTL expired → forcing refresh");
       
        const locked = await acquireMutex();
        if (locked) {
          return await refreshCache();
        } else {
         
          console.log("Another process is refreshing after absolute TTL; serving stale if any");
        }
      }
    }

   
    const cached = await redis.lRange(FEED_LIST_KEY, 0, -1).catch(() => []);
    if (cached && cached.length > 0) {
      const items = cached.map(c => {
        try { return JSON.parse(c); } catch { return null; }
      }).filter(Boolean);
      console.log(`📥 Cache hit: ${items.length} items`);
      if (items.length) return items;
    }

  
    const gotLock = await acquireMutex();
    if (gotLock) {
      console.log("🔒 Mutex acquired → updating feed...");
      const fresh = await refreshCache();
      return fresh || [];
    }

   
    console.log("⏳ Another process is refreshing… returning empty fallback");
    return [];
  } catch (err) {
    console.error("getFeed error:", err?.message || err);
    return [];
  }
}
