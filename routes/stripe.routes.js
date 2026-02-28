// routes/stripe.routes.js
import express from "express";
import Stripe from "stripe";
import User from "../models/User.js"; // ✅ adjust if your user model path/name differs

const router = express.Router();
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// POST /api/stripe/connect
router.post("/stripe/connect", async (req, res) => {
  try {
    if (!req.session?.userId) {
      return res.status(401).json({ ok: false, error: "Not logged in" });
    }

    const user = await User.findById(req.session.userId);
    if (!user) {
      return res.status(404).json({ ok: false, error: "User not found" });
    }

    // 1) Create connected account if missing
    if (!user.stripeAccountId) {
      const account = await stripe.accounts.create({
        type: "express",
        email: user.email,
        capabilities: {
          card_payments: { requested: true },
          transfers: { requested: true },
        },
      });

      user.stripeAccountId = account.id;
      await user.save();
    }

    // 2) Create onboarding link
const WEB = process.env.PUBLIC_BASE_URL || "https://www.suiteseat.io";

    const link = await stripe.accountLinks.create({
      account: user.stripeAccountId,
      refresh_url: `${WEB}/course-settings.html?stripe=refresh`,
      return_url: `${WEB}/course-settings.html?stripe=return`,
      type: "account_onboarding",
    });

    return res.json({ ok: true, url: link.url });
  } catch (err) {
    console.error("Stripe connect error:", err);
    return res.status(500).json({ ok: false, error: "Stripe connect failed" });
  }
});

export default router;