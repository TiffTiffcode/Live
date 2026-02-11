//C:\Users\tiffa\OneDrive\Desktop\Live\models\AuthUser.js
const mongoose = require("mongoose");

const AuthUserSchema = new mongoose.Schema(
  {
    firstName: { type: String, default: "" },
    lastName: { type: String, default: "" },
    name: { type: String, default: "" }, // optional display name

    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },

    passwordHash: { type: String, required: true },

    roles: [{ type: String }], // we'll wire Option Sets later if you want

    phone: { type: String },
    address: { type: String },
    profilePhoto: { type: String },

    profileRecordId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Record",
      default: null,
    }, // optional link to dynamic "User" record

    // =========================
    // ✅ Stripe Connect fields
    // =========================
    stripeAccountId: { type: String, default: "" },
    stripeAccountType: { type: String, default: "express" }, // express | standard | custom (you’re using express)
    stripeOnboarded: { type: Boolean, default: false },

    // add these fields
stripeAccountIdTest: { type: String, default: "" },
stripeAccountIdLive: { type: String, default: "" },
stripeAccountType: { type: String, default: "express" },
stripeOnboarded: { type: Boolean, default: false },

    // Optional cached status (nice for UI / debugging)
    stripeChargesEnabled: { type: Boolean, default: false },
    stripePayoutsEnabled: { type: Boolean, default: false },
    stripeDetailsSubmitted: { type: Boolean, default: false },
  },
  { timestamps: true }
);

// Optional: keep `name` in sync if not provided
AuthUserSchema.pre("save", function (next) {
  if (!this.name) {
    const full = [this.firstName, this.lastName].filter(Boolean).join(" ").trim();
    if (full) this.name = full;
  }
  next();
});

module.exports =
  mongoose.models.AuthUser || mongoose.model("AuthUser", AuthUserSchema);
