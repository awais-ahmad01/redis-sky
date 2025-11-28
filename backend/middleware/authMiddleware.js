import jwt from "jsonwebtoken";
import { pool } from "../db.js";

export async function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader)
    return res.status(401).json({ error: "No authorization header" });

  const token = authHeader.split(" ")[1];
  if (!token)
    return res.status(401).json({ error: "No token provided" });

  try {
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

    // Fetch user with token_version
    const result = await pool.query(
      "SELECT id, email, name, token_version FROM users WHERE id=$1",
      [decoded.userId]
    );

    if (result.rowCount === 0)
      return res.status(401).json({ error: "User not found" });

    const user = result.rows[0];

    // Check token version
    if (decoded.tokenVersion !== user.token_version) {
      return res.status(401).json({ error: "Token is no longer valid" });
    }

    // Attach user to request
    req.user = {
      id: user.id,
      email: user.email,
      name: user.name,
      token_version: user.token_version
    };

    next();

  } catch (err) {
    console.error("Auth middleware error:", err.message);
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}