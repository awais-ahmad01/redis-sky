
import axios from "axios";

const LOGIN_URL = "https://bsky.social/xrpc/com.atproto.server.createSession";
// const TIMELINE_URL = "https://bsky.social/xrpc/app.bsky.feed.getTimeline";
const TIMELINE_URL = "https://api.bsky.app/xrpc/app.bsky.feed.getTimeline";

let cachedAccessJwt = null;
let cachedLoginAt = 0;
const CACHE_TTL_MS = 10 * 60 * 1000; 

async function loginToBluesky() {
  try {
    if (cachedAccessJwt && (Date.now() - cachedLoginAt) < CACHE_TTL_MS) {
      return cachedAccessJwt;
    }

    if (!process.env.BLUESKY_IDENTIFIER || !process.env.BLUESKY_APP_PASSWORD) {
      console.warn("⚠ BLUESKY_IDENTIFIER or BLUESKY_APP_PASSWORD not set in .env");
      return null;
    }

    const res = await axios.post(
      LOGIN_URL,
      {
        identifier: process.env.BLUESKY_IDENTIFIER,
        password: process.env.BLUESKY_APP_PASSWORD
      },
      { timeout: 10000 }
    );

    const data = res.data || {};
    if (data?.accessJwt) {
      cachedAccessJwt = data.accessJwt;
      cachedLoginAt = Date.now();
      console.log("🔐 Logged into Bluesky (session created)");
      return cachedAccessJwt;
    } else {
      console.log("⚠ Bluesky login succeeded but no accessJwt in response", data);
      return null;
    }
  } catch (err) {
  
    const info = err?.response?.data || err?.message || err;
    console.log("❌ Bluesky login error:", info);
    return null;
  }
}


export async function fetchPublicPosts(limit = 20) {
  try {
    const token = await loginToBluesky();
    if (!token) {
      console.warn("⚠ No Bluesky session token - returning mock posts");
      return generateMockPosts(limit);
    }

    
    const res = await axios.get(`${TIMELINE_URL}?limit=${limit}`, {
      headers: { Authorization: `Bearer ${token}` },
      timeout: 10000,
    });

    const data = res.data || {};
    const feed = Array.isArray(data.feed) ? data.feed : (Array.isArray(data?.items) ? data.items : []);

    
    const posts = feed.map((item) => {
      
      const postObj = item?.post || item || {};
      const record = postObj?.record || postObj;
      const author = item?.author || postObj?.author || {};
      const text = record?.text ?? record?.content ?? "";
      const createdAt = record?.createdAt ?? postObj?.indexedAt ?? new Date().toISOString();
      const avatar = author?.avatar || null;
      const replyCount = postObj?.replyCount ?? (postObj?.counts?.replies ?? 0);
      const repostCount = postObj?.repostCount ?? (postObj?.counts?.reposts ?? 0);
      const likeCount = postObj?.likeCount ?? (postObj?.counts?.likes ?? 0);

      
      let embed = null;
      try {
        
        if (record?.embed?.images && Array.isArray(record.embed.images) && record.embed.images.length) {
          embed = record.embed.images[0]?.image?.blob?.uri || record.embed.images[0]?.thumb || null;
        } else if (record?.images && Array.isArray(record.images) && record.images.length) {
          embed = record.images[0];
        }
      } catch (e) {
        embed = null;
      }

      return {
        id: postObj?.uri || postObj?.cid || `${Date.now()}_${Math.random()}`,
        authorHandle: author?.handle || author?.did || "unknown",
        authorDisplayName: author?.displayName || author?.handle || "Unknown",
        authorAvatar: avatar,
        text,
        createdAt,
        replyCount: replyCount || 0,
        repostCount: repostCount || 0,
        likeCount: likeCount || 0,
        embed,
        raw: postObj,
      };
    });

    if (!posts.length) {
      console.warn("⚠ Bluesky returned empty feed; using mock fallback");
      return generateMockPosts(limit);
    }

    return posts;
  } catch (err) {
    const status = err?.response?.status;
    const info = err?.response?.data || err?.message || err;
    console.error("❌ Bluesky fetch error:", info);

    if (status === 401) {
      console.log("🔁 Received 401 — trying to refresh session and retry once");
      cachedAccessJwt = null;
      const token2 = await loginToBluesky();
      if (token2) {
        try {
          const res2 = await axios.get(`${TIMELINE_URL}?limit=${limit}`, {
            headers: { Authorization: `Bearer ${token2}` },
            timeout: 10000,
          });
          const feed2 = res2.data?.feed || [];
          if (feed2.length) {
            return feed2.map((item) => ({
              id: (item?.post?.uri || item?.cid || `${Date.now()}_${Math.random()}`),
              authorHandle: item?.author?.handle || "unknown",
              authorDisplayName: item?.author?.displayName || item?.author?.handle || "Unknown",
              authorAvatar: item?.author?.avatar || null,
              text: item?.post?.record?.text ?? item?.post?.record?.content ?? "",
              createdAt: item?.post?.record?.createdAt || new Date().toISOString(),
              replyCount: item?.post?.replyCount || 0,
              repostCount: item?.post?.repostCount || 0,
              likeCount: item?.post?.likeCount || 0,
              embed: null,
              raw: item,
            }));
          }
        } catch (err2) {
          console.error("❌ Retry after re-login failed:", err2?.response?.data || err2?.message || err2);
        }
      }
    }
    return generateMockPosts(limit);
  }
}

function generateMockPosts(n = 10) {
  return Array.from({ length: n }, (_, i) => ({
    id: `mock_${Date.now()}_${i}`,
    authorHandle: `mock_user_${i+1}`,
    authorDisplayName: `Mock User ${i+1}`,
    authorAvatar: null,
    text: `This is a fallback mock Bluesky post #${i+1}`,
    createdAt: new Date(Date.now() - i * 60000).toISOString(),
    replyCount: 0,
    repostCount: 0,
    likeCount: 0,
    embed: null,
    raw: null,
  }));
}
