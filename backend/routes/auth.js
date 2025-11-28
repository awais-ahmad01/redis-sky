import express from "express";
import { authMiddleware } from "../middleware/authMiddleware.js";
const router = express.Router();

import {
  signup,
  verifyEmail,
  login,
  refreshToken,
  me,
  magicLinkRequest,
  magicLinkConsume,
  oauthGoogleUrl,
  oauthGoogleCallback,
  oauthLinkConfirm,
  forgotPassword,
  resetPassword,
  requestOtp,
  verifyOtp,
  logout
} from "../controllers/auth.js";

router.post("/signup", signup);

router.post("/verify-email", verifyEmail);

router.post("/login", login);

router.post("/refresh", refreshToken);

router.get("/me", authMiddleware, me);


router.post("/magic/request", magicLinkRequest);


router.post("/magic/consume", magicLinkConsume);

router.get("/oauth/google/url", oauthGoogleUrl);

router.get("/oauth/google/callback", oauthGoogleCallback);

router.post("/oauth/link/confirm", oauthLinkConfirm);


router.post("/forgot-password", forgotPassword);

router.post("/reset-password", resetPassword);


router.post("/otp/request", requestOtp);

router.post("/otp/verify", verifyOtp);

router.get("/logout", logout);

export default router;
