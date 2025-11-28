import express from "express";
import { authMiddleware } from "../middleware/authMiddleware.js";
import {
  getBookmarks,
  addBookmark,
  removeBookmark,
  checkBookmark
} from "../controllers/bookmarks.js";

const router = express.Router();

router.use(authMiddleware);

router.get("/", getBookmarks);
router.post("/", addBookmark);
router.delete("/:postId", removeBookmark);
router.get("/check/:postId", checkBookmark);

export default router;