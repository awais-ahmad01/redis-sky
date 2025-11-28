import express from "express";
import { getFeed } from "../services/cache.js";

const router = express.Router();

router.get("/global", async (req, res) => {
  try {
    const feed = await getFeed();
    res.json({ feed });
  } catch (err) {
    console.log("Feed error:", err);
    res.status(500).json({ error: "Failed loading feed" });
  }
});

export default router;
