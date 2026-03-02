// routes/stripe.routes.js
const express = require("express");
const Stripe = require("stripe");

// ✅ IMPORTANT: use the SAME user model your server uses
// In your server.js you have: const AuthUser = require('./models/AuthUser');
const AuthUser = require("../models/AuthUser");

const router = express.Router();
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, {
  apiVersion: "2024-06-20",
});

// POST /api/stripe/connect  (because server mounts this router at /api)
router.post("/stripe/connect", async (req, res) => {
  try {
    if (!req.session?.userId) {
      return res.status(401).json({ ok: false, error: "Not logged in" });
    }

    const user = await AuthUser.findById(req.session.userId);
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

module.exports = router;