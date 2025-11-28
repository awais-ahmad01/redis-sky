import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import feedRoutes from "./routes/feed.js";
import "./redis.js"; 
import authRoutes from "./routes/auth.js";
import bookmarkRoutes from './routes/bookmarks.js';
import { pool } from "./db.js";
import cookieParser from "cookie-parser";


dotenv.config();

const app = express();

app.use(cors({ origin: true, credentials: true }));

app.use(express.json());
app.use(cookieParser());

app.use("/auth", authRoutes);
app.use("/feed", feedRoutes);
app.use("/bookmarks", bookmarkRoutes);

app.listen(4000, () => console.log("🚀 Backend running on port 4000"));
