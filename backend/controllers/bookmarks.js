
import { pool } from "../db.js";      
import { redis } from "../redis.js"; 

const BOOKMARKS_KEY_PREFIX = "user:bookmarks:"; 
const BOOKMARKS_TTL = 60 * 60; 


function cacheKey(userId) {
  return `${BOOKMARKS_KEY_PREFIX}${userId}`;
}


export const getBookmarks = async (req, res) => {
  try {
    const userId = req.user.id;
    const key = cacheKey(userId);

 
    const cached = await redis.get(key);
    if (cached) {
     
      return res.json({ bookmarks: JSON.parse(cached) });
    }

    const q = `
      SELECT id, post_id, post_data, created_at
      FROM bookmarks
      WHERE user_id = $1
      ORDER BY created_at DESC
    `;
    const result = await pool.query(q, [userId]);

    const bookmarks = result.rows.map(r => ({
      bookmarkId: r.id,
      id: r.post_id,
      ...r.post_data,
      bookmarkedAt: r.created_at
    }));

    
    await redis.set(key, JSON.stringify(bookmarks), { EX: BOOKMARKS_TTL });

    return res.json({ bookmarks });
  } catch (err) {
    console.error("getBookmarks error:", err);
    return res.status(500).json({ error: "Failed to get bookmarks" });
  }
};


export const addBookmark = async (req, res) => {
  try {
   console.log("=== ADD BOOKMARK DEBUG ===");
    console.log("Headers:", req.headers);
    console.log("Content-Type:", req.headers['content-type']);
    console.log("Raw body:", req.body);
    console.log("Body type:", typeof req.body);
    console.log("Body keys:", Object.keys(req.body || {}));
    console.log("========================");

    const userId = req.user.id;
    const { postId } = req.body;

    if (!postId) {
      console.log("❌ postId is missing or undefined");
      return res.status(400).json({ error: "postId required" });
    }

    
    let postData = null;
    try {
    
      const feedListKey = process.env.FEED_LIST_KEY || "global_feed:list";
      const feed = await redis.lRange(feedListKey, 0, -1);
      for (const p of feed) {
        try {
          const parsed = JSON.parse(p);
          if (parsed && parsed.id === postId) {
            postData = parsed;
            break;
          }
        } catch (e) {
          // ignore malformed cache entries
        }
      }
    } catch (e) {
      // redis read failed — ignore, continue with fallback
    }

    if (!postData) {
     
      postData = {
        id: postId,
        authorHandle: "unknown",
        authorDisplayName: "Unknown",
        authorAvatar: null,
        text: "",
        createdAt: new Date().toISOString(),
        replyCount: 0,
        repostCount: 0,
        likeCount: 0,
        embed: null,
        raw: {}
      };
    }

    // Insert bookmark, but avoid duplicate via ON CONFLICT DO NOTHING
    const insertQuery = `
      INSERT INTO bookmarks (user_id, post_id, post_data)
      VALUES ($1, $2, $3)
      ON CONFLICT (user_id, post_id) DO UPDATE
        SET post_data = EXCLUDED.post_data
      RETURNING id, post_id, post_data, created_at
    `;
    const result = await pool.query(insertQuery, [userId, postId, postData]);

    await redis.del(cacheKey(userId));

    if (result.rowCount === 0) {
      // shouldn't happen because of DO UPDATE returning row, but safe fallback
      return res.status(200).json({ message: "Already bookmarked" });
    }

    const row = result.rows[0];
    const bookmark = {
      bookmarkId: row.id,
      id: row.post_id,
      ...row.post_data,
      bookmarkedAt: row.created_at
    };

    return res.json({ message: "Bookmarked", bookmark });
  } catch (err) {
    console.error("addBookmark error:", err);
    return res.status(500).json({ error: "Failed to add bookmark" });
  }
};

export const removeBookmark = async (req, res) => {
  try {
    const userId = req.user.id;
    const { postId } = req.params;

    if (!postId) return res.status(400).json({ error: "postId required" });

    const deleteQuery = `
      DELETE FROM bookmarks
      WHERE user_id = $1 AND post_id = $2
      RETURNING id
    `;
    const result = await pool.query(deleteQuery, [userId, postId]);

    await redis.del(cacheKey(userId));

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Bookmark not found" });
    }

    return res.json({ message: "Bookmark removed" });
  } catch (err) {
    console.error("removeBookmark error:", err);
    return res.status(500).json({ error: "Failed to remove bookmark" });
  }
};

export const checkBookmark = async (req, res) => {
  try {
    const userId = req.user.id;
    const { postId } = req.params;

    if (!postId) return res.status(400).json({ error: "postId required" });

    const q = `SELECT 1 FROM bookmarks WHERE user_id = $1 AND post_id = $2 LIMIT 1`;
    const result = await pool.query(q, [userId, postId]);

    return res.json({ isBookmarked: result.rowCount > 0 });
  } catch (err) {
    console.error("checkBookmark error:", err);
    return res.status(500).json({ error: "Failed to check bookmark" });
  }
};
