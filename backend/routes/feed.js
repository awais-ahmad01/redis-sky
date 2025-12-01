import express from "express";
import { getFeed } from "../services/cache.js";
import { redisSub } from "../redis.js";
import { rateLimit } from "../utils/rateLimiter.js";

const router = express.Router();

// router.get("/global", async (req, res) => {
//   try {
//     const feed = await getFeed();
//     res.json({ feed });
//   } catch (err) {
//     console.log("Feed error:", err);
//     res.status(500).json({ error: "Failed loading feed" });
//   }
// });


router.get("/events", async (req, res) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.flushHeaders();

  console.log("👂 SSE client connected");


  const handler = (message) => {
    console.log("📨 SSE pushing event to client", message);

    res.write(`event: feed_update\n`);
    res.write(`data: ${message}\n\n`);
  };

  redisSub.subscribe("feed_update", handler);

  req.on("close", () => {
    redisSub.unsubscribe("feed_update", handler);
  });
});



// router.get("/global", async (req, res) => {
//   try {
//     const page = Number(req.query.page || 1);
//     const limit = Number(req.query.limit || 10);
//     const start = (page - 1) * limit;
//     const end = start + limit;

//     const feed = await getFeed(); // returns full cached feed

//     console.log(`Serving feed page ${page} with limit ${limit} (items ${start} to ${end}) from total ${feed.length} posts `);

//     const paginated = feed.slice(start, end);

//     console.log(`Paginated feed has ${paginated.length} posts ${paginated}`);

//     res.json({
//       page,
//       limit,
//       hasMore: end < feed.length,
//       feed: paginated
//     });
//   } catch (err) {
//     console.log("Feed error:", err);
//     res.status(500).json({ error: "Failed loading feed" });
//   }
// });




router.get("/global", async (req, res) => {
  try {
    const ip = req.ip; // or req.user.id if authenticated
    console.log("Rate limiting check for IP:", ip);
    const allowed = await rateLimit(`rate:feed:${ip}`, 5, 60); // 20 requests per 60s
    if (!allowed) {
      return res.status(429).json({ error: "Too many requests. Please try later." });
    }

    const page = Number(req.query.page || 1);
    const limit = Number(req.query.limit || 10);
    const start = (page - 1) * limit;
    const end = start + limit;

    const feed = await getFeed(); // returns full cached feed

    const paginated = feed.slice(start, end);

    res.json({
      page,
      limit,
      hasMore: end < feed.length,
      feed: paginated
    });
  } catch (err) {
    console.log("Feed error:", err);
    res.status(500).json({ error: "Failed loading feed" });
  }
});


export default router;
