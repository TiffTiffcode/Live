//C:\Users\tiffa\OneDrive\Desktop\Live\server.js
require("dotenv").config();
// near the top of server.js
console.log("[boot] cloudinary env check", {
  CLOUDINARY_URL: !!process.env.CLOUDINARY_URL,
  CLOUDINARY_CLOUD_NAME: !!process.env.CLOUDINARY_CLOUD_NAME,
  CLOUDINARY_API_KEY: !!process.env.CLOUDINARY_API_KEY,
  CLOUDINARY_API_SECRET: !!process.env.CLOUDINARY_API_SECRET,
  NODE_ENV: process.env.NODE_ENV,
});

const IS_PROD = process.env.NODE_ENV === "production";
// decide which webhook secret to use
const webhookSecret = IS_PROD
  ? process.env.STRIPE_WEBHOOK_SECRET_LIVE
  : process.env.STRIPE_WEBHOOK_SECRET;

const path = require("path");


const express = require('express');
const app = express();  
const BUILD_TAG = `serverjs-${Date.now()}`;

app.get("/api/version", (req, res) => {
  return res.json({
    ok: true,
    buildTag: BUILD_TAG,
    nodeEnv: process.env.NODE_ENV || null,
    renderCommit: process.env.RENDER_GIT_COMMIT || process.env.GIT_COMMIT || null,
    serviceId: process.env.RENDER_SERVICE_ID || null,
    time: new Date().toISOString(),
  });
});


const cors = require("cors");

const allowedOrigins = [
  "http://localhost:3000",
  "http://127.0.0.1:3000",
  "http://127.0.0.1:5500",
  "http://localhost:5173",
  "http://localhost:8400",
  "https://suiteseat.io",
  "https://www.suiteseat.io",
  ...(process.env.CORS_ORIGIN || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean),
];

app.set('trust proxy', 1);


const mongoose = require('mongoose');
const fs = require('fs');
const multer = require("multer");
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
});

const session = require('express-session');
const cookieParser = require('cookie-parser');
const MongoStore = require('connect-mongo');

const { connectDB } = require('./utils/db');
const AuthUser = require('./models/AuthUser');
const Record   = require('./models/Record');
const DataType = require('./models/DataType'); 
const Field = require('./models/Field');
const OptionSet = require('./models/OptionSet');
const OptionValue = require("./models/OptionValue");
const Hold   = require('./models/Hold');
const recordsCtrl = require('./controllers/records.js'); // keep .js explicit
const holdsRouter  = require('./routes/holds');          // routes/holds.js exports a router
const bcrypt = require('bcryptjs');

const { createRecord } = require('./controllers/records');



const { ensureAuthenticated, ensureRole } = require('./middleware/auth');

const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const { v4: uuid } = require('uuid');



// Guard: fail fast if export shape is wrong
if (!recordsCtrl || typeof recordsCtrl.createRecord !== 'function') {
  console.error('controllers/records.js export is', recordsCtrl);
  process.exit(1);
}
const PUBLIC_DIR = path.join(__dirname, "public");



const corsOptions = {
  origin(origin, cb) {
    if (!origin) return cb(null, true); // postman/curl
    if (allowedOrigins.includes(origin)) return cb(null, true);
    console.log("CORS blocked origin:", origin);
    return cb(new Error("Not allowed by CORS: " + origin));
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Accept", "Authorization", "X-Requested-With"],
};

// IMPORTANT for preflight
app.options("*", cors(corsOptions));
app.use(cors(corsOptions));
//////////////// Stripe

const Stripe = require("stripe");
const stripeSecretKey = process.env.STRIPE_SECRET_KEY;

if (!stripeSecretKey) {
  console.error("❌ Missing STRIPE_SECRET_KEY");
  process.exit(1);
}

const stripeRoutes = require("./routes/stripe.routes");

const stripe = new Stripe(stripeSecretKey, { apiVersion: "2024-06-20" });

// Sessions
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  proxy: true,
  store: MongoStore.create({ mongoUrl: process.env.MONGO_URI }), // ✅ add this
  cookie: {
    httpOnly: true,
    secure: IS_PROD,
    sameSite: IS_PROD ? "none" : "lax",
    domain: IS_PROD ? ".suiteseat.io" : undefined,
  },
}));


if (!webhookSecret) {
  console.warn("⚠️ Missing Stripe webhook secret for this environment.");
}

// ✅ Stripe webhook MUST be BEFORE express.json()
app.post("/api/webhooks/stripe", express.raw({ type: "application/json" }), async (req, res) => {
  let event;

  try {
    const sig = req.headers["stripe-signature"];
    event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
  } catch (err) {
    console.error("[stripe webhook] signature verify failed:", err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    // =========================
    // INVOICE FLOW (send_invoice)
    // =========================
    if (event.type === "invoice.paid") {
      const inv = event.data.object;
      const invoiceRecordId = inv?.metadata?.invoiceRecordId;

      if (invoiceRecordId) {
        await Record.findByIdAndUpdate(invoiceRecordId, {
          $set: {
            "values.Status": "paid",
            "values.Paid At": new Date().toISOString(),
            "values.Stripe Invoice Id": inv.id,
            "values.Stripe Payment Intent": inv.payment_intent || "",
            "values.Stripe Hosted Invoice Url": inv.hosted_invoice_url || "",
            "values.Stripe Invoice Pdf": inv.invoice_pdf || "",
          },
        });
      }
    }

    if (event.type === "invoice.payment_failed") {
      const inv = event.data.object;
      const invoiceRecordId = inv?.metadata?.invoiceRecordId;

      if (invoiceRecordId) {
        await Record.findByIdAndUpdate(invoiceRecordId, {
          $set: {
            "values.Status": "payment_failed",
            "values.Payment Failed At": new Date().toISOString(),
            "values.Stripe Invoice Id": inv.id,
          },
        });
      }
    }

    // =========================
    // UNIVERSAL PAYMENTS (for later orders, appointments, etc.)
    // =========================
    if (event.type === "payment_intent.succeeded") {
      const pi = event.data.object;

      // Use metadata.kind to route:
      // - suite_rent
      // - order_payment
      // - appointment_fee
      // etc.
      // Example:
      // if (pi?.metadata?.kind === "order_payment") { ... }
    }

    return res.json({ received: true });
  } catch (err) {
    console.error("[stripe webhook] handler error:", err);
    return res.status(500).json({ received: true });
  }
});

app.use("/api", stripeRoutes);
//Bookin Payment intent 

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.get("/api/stripe/ping", (_req, res) => res.json({ ok: true, t: Date.now() }));


// S3 client (only constructed if you have creds)
const s3 = (process.env.AWS_REGION && process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY)
  ? new S3Client({
      region: process.env.AWS_REGION,
      credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
      },
    })
  : null;




  
// ---------- middleware BEFORE routes ----------

//Images
// Images
const cloudinary = require("cloudinary").v2;

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

console.log("Cloudinary ready:", {
  cloud: process.env.CLOUDINARY_CLOUD_NAME,
  hasKey: !!process.env.CLOUDINARY_API_KEY,
  hasSecret: !!process.env.CLOUDINARY_API_SECRET,
});




// sanity test route
// pick from whatever env var you actually have set
const mongoSessionUrl =
  process.env.MONGO_URI ||
  process.env.MONGODB_URI ||               // Render / Atlas often uses this
  process.env.DB_URI ||                    // just in case
  'mongodb://127.0.0.1:27017/suiteseat';   // local fallback






// after body parsers & session middleware:
app.use("/api", require("./routes/auth"));

app.use("/api/holds", holdsRouter);




// ----------hold helper ----------

// helper: HH:MM → minutes
const toMin = (hhmm) => {
  const [h,m] = String(hhmm).split(':').map(Number);
  return (h||0)*60 + (m||0);
};
// add minutes, return Date
function combine(dateISO, hhmm) {
  const d = new Date(`${dateISO}T00:00:00.000Z`);
  const [h,m] = hhmm.split(':').map(Number);
  d.setUTCHours(h||0, m||0, 0, 0);
  return d;
}
function overlap(aStart, aEnd, bStart, bEnd) {
  return aStart < bEnd && bStart < aEnd;
}

app.post('/availability/validate', async (req, res) => {
  try {
    const { calendarId, dateISO, startHHMM, durationMin, ignoreAppointmentId } = req.body;
    if (!calendarId || !dateISO || !startHHMM || !Number.isFinite(durationMin)) {
      return res.status(400).json({ error: 'missing_fields' });
    }

    const slotStart = combine(dateISO, startHHMM);
    const slotEnd   = new Date(slotStart.getTime() + durationMin*60*1000);

    // 1) check active holds on same calendar
    const now = new Date();
    const holds = await Hold.find({
      calendarId: String(calendarId),
      expiresAt: { $gt: now },
      ...(ignoreAppointmentId ? { appointmentId: { $ne: String(ignoreAppointmentId) } } : {})
    }).lean();

    if (holds.some(h => overlap(new Date(h.start), new Date(h.end), slotStart, slotEnd))) {
      return res.status(409).json({ error: 'slot_held' });
    }

    // 2) check existing appointments on same date/calendar
    //    (adapt fields to your schema)
    const sameDayAppts = await Record.find({
      dataType: 'Appointment',
      $or: [{ 'values.Calendar': calendarId }, { 'values.calendarId': calendarId }],
      $expr: { $eq: [ { $substr: ['$values.Date', 0, 10] }, dateISO ] },
      ...(ignoreAppointmentId ? { _id: { $ne: ignoreAppointmentId } } : {})
    }, { values: 1 }).lean();

    const taken = sameDayAppts.some(a => {
      const v = a.values || {};
      const cancelled = String(v['is Canceled'] ?? v.canceled ?? v.cancelled ?? false).toLowerCase() === 'true';
      if (cancelled) return false;
      const s = v.Time || v['Start Time'] || v.start || v.Start;
      const d = Number(v.Duration ?? v.duration ?? v['Duration (min)'] ?? v.Minutes ?? v['Service Duration'] ?? 0);
      if (!s || !d) return false;
      const aStart = combine(dateISO, s);
      const aEnd   = new Date(aStart.getTime() + d*60*1000);
      return overlap(slotStart, slotEnd, aStart, aEnd);
    });

    if (taken) return res.status(409).json({ error: 'slot_taken' });

    return res.json({ ok: true });
  } catch (e) {
    console.error('[validate] error', e);
    return res.status(500).json({ error: 'internal' });
  }
});



function stampCreatedBy(req, _res, next) {
  if (req.method === 'POST' && (req.originalUrl||'').includes('/api/records')) {
    const uid = req.session?.userId || req.session?.user?._id;
    req.body ||= {};
    if (uid && !req.body.createdBy) req.body.createdBy = String(uid);
  }
  next();
}
app.use(stampCreatedBy);



// Make sure this is AFTER app.use(session(...)) and BEFORE any routes using it.
function requireLogin(req, res, next) {
  const uid = req.session?.userId || req.session?.user?._id || null;
  if (!uid) return res.status(401).json({ error: 'Unauthorized' });
  req.session.userId = uid;
  next();
}






// ---- add this near the top of server.js ----
const TYPE = Object.freeze({
  Business: 'Business',
  Calendar: 'Calendar',
  Category: 'Category',
  Service: 'Service',
  Appointment: 'Appointment',
});

app.post('/api/_ping', (req, res) => {
  res.json({ ok: true, got: req.body, t: Date.now() });
});



// simple request logger (optional)
app.use((req, _res, next) => {
  if (req.method === 'POST' && req.path.startsWith('/api/records')) {
    const uid = req?.session?.userId || req?.user?._id || req?.body?.createdBy || null;
    req.body ||= {};
    if (uid && !req.body.createdBy) req.body.createdBy = String(uid);
  }
  next();
});

app.use(async (req, res, next) => {
  const id = req.session?.userId;
  if (!id) return next();
  try {
    const user = await AuthUser.findById(id).lean();
    if (!user) {
      // session cookie points to deleted user; clear it
      req.session.destroy(() => {});
      return next();
    }
    req.user = { _id: user._id, email: user.email, roles: user.roles };
  } catch (_) {}
  next();
});

app.use((req, res, next) => {
  // prevent stale JSON in back/forward cache
  res.setHeader('Cache-Control', 'no-store');
  // make it easy for the front-end to detect account flips
  if (req.session?.userId) res.setHeader('X-User-Id', String(req.session.userId));
  next();
});









////////////////////////////

const _dataTypeIdCache = new Map();

async function getDataTypeIdByName(name) {
  const key = String(name || "").trim();
  if (!key) return "";

  if (_dataTypeIdCache.has(key)) return _dataTypeIdCache.get(key);

  const row = await DataType.findOne({ name: key }).lean();
  const id = row?._id ? String(row._id) : "";
  if (id) _dataTypeIdCache.set(key, id);
  return id;
}
///////////////////////////////////////




// ---------- routes ----------
app.get('/api/health', (_req, res) => res.json({ ok: true, t: Date.now() }));

app.get('/api/whoami', (req, res) => {
  res.json({
    userId: req.session?.userId || null,
    roles:  req.session?.roles  || [],
    user:   req.session?.user   || null
  });
});

// put this near your other routes
app.get('/_whoami', (req, res) => {
  res.json({ ok: true, tag: 'DEC-TEST-1' });
});

function requireAuth(req, res, next) {
  const uid = req.session && req.session.userId;
  if (!uid) return res.status(401).json({ error: 'Not logged in' });
  req.user = { id: String(uid) };
  next();
}

// ---------- static / assets ----------

app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));
app.use('/qassets', express.static(path.join(__dirname, 'qassets')));



// --- View engine (only if you actually render EJS views) ---
app.set("view engine", "ejs");
app.set('views', path.join(__dirname, 'views'));
const nodemailer = require('nodemailer');


const mailer = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: String(process.env.SMTP_SECURE) === 'true',
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
});
// server.js
const { Resend } = require('resend');
const { createEvent } = require('ics');

const resend = new Resend(process.env.RESEND_API_KEY);


const publicRoutes = require('./routes/public');
app.use(publicRoutes);



// Multer in-memory (NO local disk)
const uploadMemory = multer({
  storage: multer.memoryStorage(),
 limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
});

// Helper: upload a buffer to Cloudinary
function uploadBufferToCloudinary(buffer, { folder = "suiteseat", public_id } = {}) {
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      {
        folder,
        public_id,
        resource_type: "image",
      },
      (err, result) => {
        if (err) return reject(err);
        resolve(result); // result.secure_url is what we want to store
      }
    );

    stream.end(buffer);
  });
}

























//////////////////////////////////////////////////////////////////////
// Records Stuff — visibility / permissions (ONE version only)

// -----------------------------
// helpers
// -----------------------------
function canonName(s) {
  return String(s || "").trim().toLowerCase();
}

function isObjectIdLike(x) {
  return mongoose.isValidObjectId(String(x || ""));
}

function toObjId(x) {
  if (!isObjectIdLike(x)) return null;
  return new mongoose.Types.ObjectId(String(x));
}

// Return dot paths we should check for a given field name.
// Includes both values.* and top-level, plus common Id aliases.
function refCandidatePaths(fieldName) {
  const safe = String(fieldName || "").trim();
  if (!safe) return [];

  return [
    // top-level
    `${safe}`,
    `${safe}._id`,

    // values
    `values.${safe}`,
    `values.${safe}._id`,

    // id aliases
    `values.${safe}Id`,
    `values['${safe} Id']`,
  ];
}

// Heuristic: treat these field names as "AuthUser id fields"
const USER_ID_FIELD_NAMES = new Set(
  [
    "pro", "pro ref", "staff", "staff ref",
    "client", "client ref",
    "user", "user ref",
    "owner", "owneruser", "owner user", "owneruserid", "owner user id",
    "assigned to",
    "linked user",
  ].map(s => s.toLowerCase())
);



//////////////////////////////////////////////////////////////////////////////////////////////////
// ------------------------------------------------------------
// RECORDS: CREATE / UPDATE / DELETE (aligned with visibility)
// ------------------------------------------------------------
app.post("/api/records/:typeName", ensureAuthenticated, async (req, res) => {
  try {
    const sid = String(req.session?.userId || "");
    if (!sid) return res.status(401).json({ items: [] });

    const typeName = decodeURIComponent(req.params.typeName || "").trim();

    const dt = await getDataTypeByNameLoose(typeName);
    if (!dt?._id) return res.status(404).json({ items: [] });

    const rawValues = (req.body && req.body.values) || {};
    const values = await normalizeValuesForType(dt._id, rawValues);

    // ✅ universal ownership stamp (ALL types)
    values.ownerUserId = sid;

    const doc = await Record.create({
      dataTypeId: dt._id,
      values,
      createdBy: sid,
      updatedBy: sid,
      deletedAt: null,
    });
    console.log("[email automations] about to run", {
      typeName,
      eventKey: `${canonName(typeName)}.created`,
      recordId: String(doc._id),
      actorUserId: sid,
      values: doc.values,
    });

    // 🔥 generic automation hook
try {
  await runEmailAutomations({
    eventKey: `${canonName(typeName)}.created`,
    record: doc,
    actorUserId: sid,
  });

        console.log("[email automations] finished ok", {
        eventKey: `${canonName(typeName)}.created`,
        recordId: String(doc._id),
      });

} catch (err) {
  console.error("[email automations] run failed:", err);
}
    return res.status(201).json({ items: [doc] });
  } catch (e) {
    console.error("POST /api/records/:typeName failed:", e);
    return res.status(500).json({ items: [] });
  }
});

app.patch("/api/records/:typeName/:id", ensureAuthenticated, async (req, res) => {
  try {
    const me = String(req.session.userId || "");
    const typeName = decodeURIComponent(req.params.typeName || "").trim();
    const recordId = String(req.params.id || "").trim();
    if (!me) return res.status(401).json({ items: [] });
    if (!mongoose.isValidObjectId(recordId)) return res.status(400).json({ items: [] });

    const dt = await getDataTypeByNameLoose(typeName);
    if (!dt?._id) return res.status(404).json({ items: [] });

    const roles = req.session?.roles || [];
    const isAdmin = roles.includes("admin");
    const isPro = roles.includes("pro");

    const rawValues = req.body?.values || {};
    const values = await normalizeValuesForType(dt._id, rawValues);

    // turn { a:1, b:2 } into { "values.a":1, "values.b":2 }
    const setOps = Object.fromEntries(
      Object.entries(values).map(([k, v]) => [`values.${k}`, v])
    );

    // Base constraints for the doc
    const baseQ = { _id: recordId, dataTypeId: dt._id, deletedAt: null };

    let q;

    if (isAdmin) {
      // admin: can update anything
      q = baseQ;
    } else if (isPro) {
      // pro: can update anything they can SEE (connected visibility)
      const vis = await enforcedWhereForUser({ dataTypeId: String(dt._id), userId: me });
      q = { $and: [baseQ, vis] };
    } else {
      // client: can only update what they created (safe default)
      q = { ...baseQ, createdBy: me };
    }

    const updated = await Record.findOneAndUpdate(
      q,
      { $set: { ...setOps, updatedBy: me }, $currentDate: { updatedAt: true } },
      { new: true }
    ).lean();

    return res.json({ items: updated ? [updated] : [] });
  } catch (e) {
    console.error("PATCH /api/records/:typeName/:id failed:", e);
    return res.status(500).json({ items: [] });
  }
});

app.delete("/api/records/:typeName/:id", ensureAuthenticated, async (req, res) => {
  try {
    const me = String(req.session.userId || "");
    const typeName = decodeURIComponent(req.params.typeName || "").trim();
    const recordId = String(req.params.id || "").trim();
    if (!me) return res.status(401).json({ items: [] });
    if (!mongoose.isValidObjectId(recordId)) return res.status(400).json({ items: [] });

    const dt = await getDataTypeByNameLoose(typeName);
    if (!dt?._id) return res.status(404).json({ items: [] });

    const roles = req.session?.roles || [];
    const isAdmin = roles.includes("admin");
    const isPro = roles.includes("pro");

    const baseQ = { _id: recordId, dataTypeId: dt._id, deletedAt: null };

    let q;

    if (isAdmin) {
      q = baseQ;
    } else if (isPro) {
      const vis = await enforcedWhereForUser({ dataTypeId: String(dt._id), userId: me });
      q = { $and: [baseQ, vis] };
    } else {
      q = { ...baseQ, createdBy: me };
    }

    console.log("[DELETE] typeName:", typeName);
console.log("[DELETE] recordId:", recordId);
console.log("[DELETE] me:", me);
console.log("[DELETE] roles:", roles);

console.log("[DELETE] dt._id:", String(dt._id));

// show the final query we use
console.log("[DELETE] final q:", JSON.stringify(q, null, 2));

// 🔍 IMPORTANT: read the record ignoring permissions to compare
const raw = await Record.findById(recordId).lean();
console.log("[DELETE] raw record (by id):", raw && {
  _id: String(raw._id),
  dataTypeId: String(raw.dataTypeId),
  deletedAt: raw.deletedAt,
  createdBy: raw.createdBy,
  updatedBy: raw.updatedBy,
});

    const updated = await Record.findOneAndUpdate(
      q,
      { $set: { deletedAt: new Date(), updatedBy: me }, $currentDate: { updatedAt: true } },
      { new: true }
    ).lean();

    return res.json({ items: updated ? [updated] : [] });
  } catch (e) {
    console.error("DELETE /api/records/:typeName/:id failed:", e);
    return res.status(500).json({ items: [] });
  }
});

////////////////////////////////////////////////////////////////////////////////////////////////////////
app.get("/api/records", ensureAuthenticated, async (req, res) => {
  try {
    const me = String(req.session?.userId || "");
    if (!me) return res.status(401).json({ items: [] });

    const dataTypeId = String(req.query?.dataTypeId || "").trim();
    if (!mongoose.isValidObjectId(dataTypeId)) return res.json({ items: [] });

    const dt = await DataType.findById(dataTypeId).lean();
    if (!dt?._id) return res.json({ items: [] });

    // logs (optional)
    console.log("[api/records] dt found:", {
      id: String(dt._id),
      name: dt.name,
      canon: dt.nameCanonical,
      isPublicReadable: dt.isPublicReadable,
    });
    console.log("[api/records] db:", mongoose.connection.db?.databaseName);

    const count = await Record.countDocuments({ dataTypeId: dt._id, deletedAt: null });
    console.log("[api/records] countInThisDB:", count, "dtId:", String(dt._id));

    // match your existing GET /api/records/:typeName behavior
    const nameCanon = String(dt.nameCanonical || "").toLowerCase();

    // ✅ include client here too (fixes Client list issues)
    const TOP_LEVEL = new Set([
      "business", "calendar", "category", "service",
      "client", // ✅ ADD
      "course", "coursesection", "courselesson", "coursechapter",
      "storetheme", "store_theme", "store theme",
    ]);

    const enforcedWhere = TOP_LEVEL.has(nameCanon)
      ? {
          $or: [
            { createdBy: me },
            { "values.ownerUserId": me },
            { "values.ownerUserId._id": me },
            { owners: me },
            { members: me },
          ],
        }
      : await enforcedWhereForUser({ dataTypeId: String(dt._id), userId: me });

    const limit = Math.min(Number(req.query.limit || 200), 2000);
    const sort = String(req.query.sort || "-createdAt");
    const sortObj = sort.startsWith("-") ? { [sort.slice(1)]: -1 } : { [sort]: 1 };

    // ✅ ownerUserId filter (FIXED — no mongoWhere undefined)
    const ownerParam = String(req.query.ownerUserId || "").trim();

    const findQuery = {
      dataTypeId: dt._id,
      deletedAt: null,
      ...enforcedWhere,
    };

    if (ownerParam) {
      findQuery["values.ownerUserId"] = ownerParam;
      console.log("[api/records] enforced ownerUserId:", ownerParam);
    }

    console.log("[public/records] FINAL findQuery:", JSON.stringify(findQuery, null, 2));

const sampleRows = await Record.find({
  dataTypeId: dt._id,
  deletedAt: null,
}).limit(5).lean();

console.log("[api/records] sample raw rows for type:", dt.name);
console.log(JSON.stringify(sampleRows.map(r => ({
  _id: String(r._id),
  values: r.values
})), null, 2));

const rows = await Record.find(findQuery)
  .sort({ updatedAt: -1, createdAt: -1 })
  .limit(limit)
  .lean();

console.log("[public/records] MATCHED rows count:", rows.length);

return res.json({ items: rows });
  } catch (e) {
    console.error("GET /api/records (alias) failed:", e);
    return res.status(500).json({ items: [] });
  }
});

app.get("/api/records/:typeName/:id", ensureAuthenticated, async (req, res) => {
  try {
    const me = String(req.session.userId || "");
    const typeName = decodeURIComponent(req.params.typeName || "").trim();
    const id = String(req.params.id || "").trim();

    if (!me) return res.status(401).json({ message: "Not logged in" });
    if (!mongoose.isValidObjectId(id)) return res.status(400).json({ message: "Invalid id" });

    const dt = await DataType.findOne({ nameCanonical: typeName.toLowerCase() }).lean();
    if (!dt) return res.status(404).json({ message: "DataType not found" });

    const enforcedWhere = await enforcedWhereForUser({
      dataTypeId: String(dt._id),
      userId: me,
    });

    const row = await Record.findOne({
      dataTypeId: dt._id,
      deletedAt: null,
      $and: [
        { _id: id },
        enforcedWhere,
      ],
    }).lean();

    return res.json({ items: row ? [row] : [] });
  } catch (e) {
    console.error("GET /api/records/:typeName/:id failed:", e);
    return res.status(500).json({ message: "Failed to load record" });
  }
});
                                        
app.get("/api/records/:typeName", ensureAuthenticated, async (req, res) => {
  try {
    const me = String(req.session.userId || "");
    const typeName = decodeURIComponent(req.params.typeName || "").trim();
    if (!me) return res.status(401).json({ message: "Not logged in" });

    const dt = await DataType.findOne({
      nameCanonical: typeName.toLowerCase(),
    }).lean();

    if (!dt) return res.json({ items: [] });

    // -----------------------------
    // 1) Parse JSON ?where=...
    // -----------------------------
    let clientWhere = {};
    if (req.query.where) {
      try {
        clientWhere = JSON.parse(String(req.query.where));
      } catch {}
    }

    // -----------------------------
    // 2) ALSO support simple query params:
    //    /api/records/Service?Business=...&Calendar=...
    //
    // We'll convert them into "values.<field>" matches.
    // Handles common shapes:
    // - values.Business === "id"
    // - values.Business._id === "id"
    // - values.businessId === "id"
    // - values["Business Id"] === "id"
    // -----------------------------
    const RESERVED = new Set(["where", "limit", "ts", "cache", "_", "page"]);
    const simpleFilters = [];

    for (const [rawKey, rawVal] of Object.entries(req.query || {})) {
      const key = String(rawKey || "").trim();
      if (!key || RESERVED.has(key)) continue;

      // allow repeated params (?x=1&x=2) -> treat as IN
      const vals = Array.isArray(rawVal) ? rawVal : [rawVal];
      const cleanVals = vals
        .map(v => String(v ?? "").trim())
        .filter(Boolean);

      if (!cleanVals.length) continue;

      // If only one value -> equality, else -> $in
      const eqOrIn =
        cleanVals.length === 1 ? cleanVals[0] : { $in: cleanVals };

      // Match multiple common storage patterns
      simpleFilters.push({
        $or: [
          { [`values.${key}`]: eqOrIn },
          { [`values.${key}._id`]: eqOrIn },
          { [`values.${key}Id`]: eqOrIn },
          { [`values.${key} Id`]: eqOrIn },

        ],
      });
    }

    // Merge ?where with simple filters (AND them together)
    let mergedClientWhere = clientWhere;
    if (simpleFilters.length) {
      const parts = [];
      if (clientWhere && Object.keys(clientWhere).length) parts.push(clientWhere);
      parts.push(...simpleFilters);
      mergedClientWhere = parts.length === 1 ? parts[0] : { $and: parts };
    }

 // -----------------------------
// 3) Enforce visibility
// -----------------------------
const nameCanon = String(dt.nameCanonical || "").toLowerCase();

// “top-level” types should act like: creator owns it
const TOP_LEVEL = new Set([
  "business", "calendar", "category", "service",
  "client", // ✅ ADD THIS
  "course", "coursesection", "courselesson", "coursechapter"
]);


// If top-level: allow createdBy OR legacy missing createdBy
const enforcedWhere = TOP_LEVEL.has(nameCanon)
  ? {
      $or: [
        { createdBy: me },

        // ✅ also allow your newer universal stamp
        { "values.ownerUserId": me },
        { "values.ownerUserId._id": me },

        // (optional future)
        { owners: me },
        { members: me },
      ],
    }
  : await enforcedWhereForUser({
      dataTypeId: String(dt._id),
      userId: me,
    });

    const finalWhere =
      mergedClientWhere && Object.keys(mergedClientWhere).length
        ? { $and: [mergedClientWhere, enforcedWhere] }
        : enforcedWhere;

    const limit = Math.min(Number(req.query.limit || 200), 2000);

    const rows = await Record.find({
      dataTypeId: dt._id,
      deletedAt: null,
      ...finalWhere,
    })
      .sort({ createdAt: -1 })
      .limit(limit)
      .lean();

    return res.json({ items: rows });
  } catch (e) {
    console.error("GET /api/records/:typeName failed:", e);
    return res.status(500).json({ message: "Failed to load records" });
  }
});




// PUBLIC READ: /public/records?dataType=Upcoming%20Hours&where=...
// - No auth required (public pages can use it)
// - Supports ?where JSON and simple query params
// - Maps filters to values.<Field> because Record stores fields in values
app.get("/public/records", async (req, res) => {
  
  try {
    const dataTypeName = String(req.query.dataType || "").trim();
    if (!dataTypeName) return res.json({ items: [] });

    // 1) parse ?where={}
    let whereObj = {};
    if (req.query.where) {
      try {
        whereObj = JSON.parse(String(req.query.where));
      } catch {
        whereObj = {};
      }
    }

    // 2) also support simple params:
    // /public/records?dataType=Service&Business=...&Calendar=...
    const RESERVED = new Set(["dataType", "where", "limit", "ts", "cache", "_", "page"]);
    const simple = {};
    for (const [k, v] of Object.entries(req.query || {})) {
      const key = String(k || "").trim();
      if (!key || RESERVED.has(key)) continue;

      const vals = Array.isArray(v) ? v : [v];
      const clean = vals.map((x) => String(x ?? "").trim()).filter(Boolean);
      if (!clean.length) continue;

      simple[key] = clean.length === 1 ? clean[0] : { $in: clean };
    }

    // merge where + simple (AND)
    const merged = (() => {
      const parts = [];
      if (whereObj && Object.keys(whereObj).length) parts.push(whereObj);
      if (simple && Object.keys(simple).length) parts.push(simple);
      if (!parts.length) return {};
      return parts.length === 1 ? parts[0] : { $and: parts };
    })();

    // ---- LOGS ----
    console.log("[public/records] dataType:", dataTypeName);
    console.log("[public/records] where raw:", req.query.where || null);
    console.log("[public/records] merged where:", merged);
    console.log("[public/records] ownerUserId query:", req.query.ownerUserId || null);

    // find the datatype
    // ✅ find the datatype (loose match like /api/records/:typeName)
const dt = await getDataTypeByNameLoose(dataTypeName);
if (!dt?._id) return res.json({ items: [] });

console.log("[public/records] RESOLVED DT:", {
  queryName: dataTypeName,
  dtId: String(dt._id),
  dtName: dt.name,
  dtCanon: dt.nameCanonical,
});
console.log("[public/records] dt found:", {
  id: String(dt._id),
  name: dt.name,
  canon: dt.nameCanonical,
  isPublicReadable: dt.isPublicReadable,
});

console.log("[DB inside route] using db:", mongoose.connection.db?.databaseName);

const count = await Record.countDocuments({
  dataTypeId: dt._id,
  deletedAt: null,
});

console.log("[public/records] countInThisDB:", count, "dtId:", String(dt._id));

// ✅ dynamic public permission check
const publicTypeNames = new Set([
  "business",
  "calendar",
  "category",
  "service",
  "upcoming hours",
  "upcominghours",
  "appointment"
]);

const dtCanon = String(dt.nameCanonical || dt.name || "").toLowerCase().trim();

if (!dt.isPublicReadable && !publicTypeNames.has(dtCanon)) {
  console.log("[public/records] blocked by dt.isPublicReadable:", dataTypeName);
  return res.json({ items: [] });
}

console.log("[public/records] dt found:", { id: String(dt._id), name: dt.name, canon: dt.nameCanonical });

    // -----------------------------
    // Convert merged filters into Mongo filters
    // - Scalars go to values.<field>
    // - Other fields get "ref-or-scalar" matching via buildRefOrScalarMatch()
    // -----------------------------
    // ✅ Fields that are ALWAYS plain scalar matches in values (not reference-matching)
    const ALWAYS_SCALAR = new Set([
      "ownerUserId",
      "Created By",
      "createdBy",
      "submittedByUserId",
      "suiteOwnerId",
      "locationOwnerId",
    ]);

    function rewriteNode(node) {
      if (!node || typeof node !== "object") return node;
      if (Array.isArray(node)) return node.map(rewriteNode);

      const out = {};
      for (const [k, v] of Object.entries(node)) {
        if (k === "$and" || k === "$or") {
          out[k] = rewriteNode(v);
          continue;
        }

        if (k === "_id" || k === "id" || k === "recordId") {
          out["_id"] = v;
          continue;
        }

        const isOperatorObject =
          v &&
          typeof v === "object" &&
          !Array.isArray(v) &&
          Object.keys(v).some((key) => key.startsWith("$"));

        if (isOperatorObject) {
          out[`values.${k}`] = v;
        } else if (ALWAYS_SCALAR.has(k)) {
          // ✅ force scalar match (so ownerUserId becomes values.ownerUserId)
          out[`values.${k}`] = v;
        } else {
          // ref-or-scalar match
          out[`__REFMATCH__${k}`] = v;
        }
      }
      return out;
    }

    const rewritten = rewriteNode(merged);

    // Now convert __REFMATCH__ entries into $and items
    const andParts = [];
    for (const [k, v] of Object.entries(rewritten || {})) {
      if (k === "$and" || k === "$or") continue;

      if (k.startsWith("__REFMATCH__")) {
        const field = k.replace("__REFMATCH__", "");
        andParts.push(buildRefOrScalarMatch(field, v));
      } else {
        andParts.push({ [k]: v });
      }
    }

    if (rewritten?.$and) andParts.push({ $and: rewritten.$and });
    if (rewritten?.$or) andParts.push({ $or: rewritten.$or });

  const mongoWhere = andParts.length ? { $and: andParts } : {};

    console.log("[public/records] mongoWhere BEFORE owner:", mongoWhere);

    const limit = Math.min(Number(req.query.limit || 200), 2000);

    // ✅ HARD ENFORCE: if ownerUserId is provided, ALWAYS filter by values.ownerUserId
    // IMPORTANT: do NOT merge into mongoWhere object in a way that can be lost.
    // Build the FINAL findQuery and query with that.
    const ownerParam = String(req.query.ownerUserId || "").trim();

    const findQuery = {
      dataTypeId: dt._id,
      deletedAt: null,
      ...(mongoWhere && Object.keys(mongoWhere).length ? mongoWhere : {}),
    };

    if (ownerParam) {
      findQuery["values.ownerUserId"] = ownerParam;
      console.log("[public/records] enforced ownerUserId:", ownerParam);
    }




console.log("[public/records] FINAL findQuery:", JSON.stringify(findQuery, null, 2));

const rawRows = await Record.find({
  dataTypeId: dt._id,
  deletedAt: null,
}).limit(5).lean();

console.log("[public/records] RAW rows count for dt:", rawRows.length);
console.log("[public/records] RAW rows sample:", JSON.stringify(rawRows.map(r => ({
  _id: String(r._id),
  values: r.values
})), null, 2));

const rows = await Record.find(findQuery)
  .sort({ updatedAt: -1, createdAt: -1 })
  .limit(limit)
  .lean();

console.log("[public/records] MATCHED rows count:", rows.length);
console.log("[public/records] MATCHED rows sample:", JSON.stringify(rows.map(r => ({
  _id: String(r._id),
  values: r.values
})), null, 2));

return res.json({ items: rows });
  } catch (e) {
    console.error("GET /public/records failed:", e);
    return res.status(500).json({ items: [] });
  }
});


// ------------------------------------------------------------
// UNIVERSAL VISIBILITY: user can see records that are:
// - created by them
// - owned by them
// - reference them via ANY "user-ish" field name (Pro, Client, Assigned To, etc.)
// ------------------------------------------------------------
async function enforcedWhereForUser({ dataTypeId, userId }) {
  const me = String(userId || "").trim();

  // Base: always allow own-created / own-owned
  const baseOr = [
    { createdBy: me },
    { "values.ownerUserId": me },
    { "values.ownerUserId._id": me },
  ];

  // If we don't have datatype, fall back to base
  if (!dataTypeId || !mongoose.isValidObjectId(dataTypeId)) {
    return { $or: baseOr };
  }

  const dt = await DataType.findById(dataTypeId).lean();
  if (!dt) return { $or: baseOr };

  const fields = Array.isArray(dt.fields) ? dt.fields : [];

  // Fields that "look like" user refs (based on name heuristics)
  const candidateFieldNames = fields
    .map((f) => String(f?.name || f?.label || f?.key || "").trim())
    .filter(Boolean)
    .filter((nm) => USER_ID_FIELD_NAMES.has(nm.toLowerCase()));

  // ✅ Always include these common user-ref fields (universal, not business-specific)
  const fallbackNames = [
    "Pro",
    "Client",
    "User",
    "Owner",
    "Assigned To",
    "proUserId",
    "clientId",
  ];

  for (const n of fallbackNames) {
    if (!candidateFieldNames.some((x) => x.toLowerCase() === n.toLowerCase())) {
      candidateFieldNames.push(n);
    }
  }

  // Build OR clauses for “record references me”
  const refOrs = [];
  for (const fieldName of candidateFieldNames) {
    for (const path of refCandidatePaths(fieldName)) {
      refOrs.push({ [path]: me });

      if (mongoose.isValidObjectId(me)) {
        refOrs.push({ [path]: new mongoose.Types.ObjectId(me) });
      }
    }
  }

  // Final: base OR any reference match
  return {
    $or: [
      ...baseOr,
      ...refOrs, // if empty, harmless
    ],
  };
}









function oid(x) {
  if (!x) return null;
  try { return new mongoose.Types.ObjectId(String(x)); } catch { return null; }
}


const requireAuthIfYouHaveIt = (req, _res, next) => next(); // temporary pass-through


const toObjectId = (v) => {
  if (!v) return undefined;
  try { return new mongoose.Types.ObjectId(String(v)); }
  catch { return undefined; }
};

function buildRefOrScalarMatch(field, value) {
  const ids = Array.isArray(value) ? value : [value];
  const strIds = ids.map(v => String(v ?? "").trim()).filter(Boolean);

  const objIds = strIds
    .filter(v => mongoose.isValidObjectId(v))
    .map(v => new mongoose.Types.ObjectId(v));

  if (!strIds.length && !objIds.length) return { _id: { $exists: true } };

  // 🔁 Generic paths we’ll try (values + top-level)
  const paths = [
    `values.${field}`,
    `values.${field}._id`,
    `values.${field}Id`,
    `values.${field} Id`,

    `${field}`,
    `${field}._id`,
    `${field}Id`,
    `${field} Id`,
  ];

  // 🔥 Common aliases
  const f = String(field || "").toLowerCase();

  if (f === "category") paths.push(
    "categoryId",
    "values.categoryId",
    "values.Category",
    "values.Category._id"
  );

  if (f === "business") paths.push(
    "businessId",
    "values.businessId",
    "values.Business",
    "values.Business._id"
  );

  if (f === "calendar") paths.push(
    "calendarId",
    "values.calendarId",
    "values.Calendar",
    "values.Calendar._id"
  );

  const orParts = [];

  for (const p of paths) {
    for (const s of strIds) {
      orParts.push({ [p]: s });                 // scalar string
      orParts.push({ [p]: { $in: [s] } });     // array of strings
    }

    for (const o of objIds) {
      orParts.push({ [p]: o });                // scalar ObjectId
      orParts.push({ [p]: { $in: [o] } });     // array of ObjectIds
    }
  }

  return { $or: orParts };
}


 app.get('/appointment-settings',
  ensureAuthenticated,
  ensureRole('pro'),
  (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'appointment-settings.html'));
  }
);

// 1) Upload a single file, return a URL
const uploadMem = multer({ storage: multer.memoryStorage() });

app.post("/api/upload", uploadMem.single("file"), async (req, res) => {
    console.log("[upload] cloudinary env check", {
    CLOUDINARY_URL: !!process.env.CLOUDINARY_URL,
    CLOUDINARY_CLOUD_NAME: !!process.env.CLOUDINARY_CLOUD_NAME,
    CLOUDINARY_API_KEY: !!process.env.CLOUDINARY_API_KEY,
    CLOUDINARY_API_SECRET: !!process.env.CLOUDINARY_API_SECRET,
  });
  try {
    if (!req.file) return res.status(400).json({ ok: false, error: "No file uploaded" });

    const folder = req.query.folder || "suiteseat/uploads";

    const result = await new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream(
        {
          folder,
          resource_type: "image",
        },
        (err, out) => (err ? reject(err) : resolve(out))
      );
      stream.end(req.file.buffer);
    });

    // ✅ IMPORTANT: return secure_url
// ✅ IMPORTANT: return a consistent shape
return res.json({
  ok: true,
  handler: "cloudinary_image_upload",
  url: result.secure_url,        // ✅ what your front-end wants
  secure_url: result.secure_url, // optional compatibility
  publicId: result.public_id,
  width: result.width,
  height: result.height,
});


  } catch (err) {
    console.error("Upload error:", err);
    return res.status(500).json({ ok: false, error: "Upload failed" });
  }
});



app.post("/api/uploads/video", upload.single("file"), async (req, res) => {
  try {
    console.log("✅ HIT VIDEO UPLOAD /api/uploads/video", {
      folder: req.query.folder,
      name: req.file?.originalname,
      bytes: req.file?.size,
      mimetype: req.file?.mimetype,
    });

    if (!req.file) return res.status(400).json({ error: "No file uploaded" });

    const folder = req.query.folder ? String(req.query.folder) : "suiteseat/videos";

    const b64 = req.file.buffer.toString("base64");
    const dataUri = `data:${req.file.mimetype};base64,${b64}`;

    const result = await cloudinary.uploader.upload(dataUri, {
      folder,
      resource_type: "video",
    });

    return res.json({
      ok: true,
      handler: "cloudinary_video_upload",
      url: result.secure_url,
      publicId: result.public_id,
    });
  } catch (err) {
    console.error("Cloudinary video upload failed", err);
    return res.status(500).json({ error: "Video upload failed" });
  }
});

const uploadImage = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB images
});

const uploadVideo = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 200 * 1024 * 1024 }, // 200MB videos
});

// ✅ Signed upload signature for Cloudinary (direct-to-cloud)
app.get("/api/cloudinary/sign", (req, res) => {
  try {
    const timestamp = Math.round(Date.now() / 1000);

    // folder you want uploads to go into
    const folder = req.query.folder ? String(req.query.folder) : "suiteseat/course";

    // Create signature
    const signature = cloudinary.utils.api_sign_request(
      { timestamp, folder },
      process.env.CLOUDINARY_API_SECRET
    );

    return res.json({
      ok: true,
      timestamp,
      folder,
      signature,
      cloudName: process.env.CLOUDINARY_CLOUD_NAME,
      apiKey: process.env.CLOUDINARY_API_KEY,
    });
  } catch (e) {
    console.error("[cloudinary] sign failed", e);
    return res.status(500).json({ ok: false, error: "sign_failed" });
  }
});


///////////////////////////
/////Record Stuff for themes 
// =====================================================
// COMPAT ROUTES for Admin UI (/api/records?dataTypeId=...)
// Keeps your existing /api/records/:typeName routes intact
// =====================================================


// CREATE by dataTypeId: POST /api/records { dataTypeId, values }
app.post("/api/records", ensureAuthenticated, async (req, res) => {
  try {
    const sid = String(req.session?.userId || "");
    if (!sid) return res.status(401).json({ items: [] });

    const dataTypeId = String(req.body?.dataTypeId || "").trim();
    if (!mongoose.isValidObjectId(dataTypeId)) return res.status(400).json({ items: [] });

    const dt = await DataType.findById(dataTypeId).lean();
    if (!dt?._id) return res.status(404).json({ items: [] });

    const rawValues = req.body?.values || {};
    const values = await normalizeValuesForType(dt._id, rawValues);

    // keep your universal stamp
    values.ownerUserId = sid;

    const doc = await Record.create({
      dataTypeId: dt._id,
      values,
      createdBy: sid,
      updatedBy: sid,
      deletedAt: null,
    });

    return res.status(201).json({ items: [doc] });
  } catch (e) {
    console.error("POST /api/records (alias) failed:", e);
    return res.status(500).json({ items: [] });
  }
});

// UPDATE by record id: PATCH /api/records/:id { values: {...} }
app.patch("/api/records/:id", ensureAuthenticated, async (req, res) => {
  try {
    const me = String(req.session.userId || "");
    const recordId = String(req.params.id || "").trim();
    if (!me) return res.status(401).json({ items: [] });
    if (!mongoose.isValidObjectId(recordId)) return res.status(400).json({ items: [] });

    const rec = await Record.findById(recordId).lean();
    if (!rec || rec.deletedAt) return res.status(404).json({ items: [] });

    const dt = await DataType.findById(rec.dataTypeId).lean();
    if (!dt?._id) return res.status(404).json({ items: [] });

    const roles = req.session?.roles || [];
    const isAdmin = roles.includes("admin");
    const isPro = roles.includes("pro");

    const rawValues = req.body?.values || {};
    const values = await normalizeValuesForType(dt._id, rawValues);

    const setOps = Object.fromEntries(
      Object.entries(values).map(([k, v]) => [`values.${k}`, v])
    );

    const baseQ = { _id: recordId, dataTypeId: dt._id, deletedAt: null };

    let q;
    if (isAdmin) {
      q = baseQ;
    } else if (isPro) {
      const vis = await enforcedWhereForUser({ dataTypeId: String(dt._id), userId: me });
      q = { $and: [baseQ, vis] };
    } else {
      q = { ...baseQ, createdBy: me };
    }

    const updated = await Record.findOneAndUpdate(
      q,
      { $set: { ...setOps, updatedBy: me }, $currentDate: { updatedAt: true } },
      { new: true }
    ).lean();

    return res.json({ items: updated ? [updated] : [] });
  } catch (e) {
    console.error("PATCH /api/records/:id (alias) failed:", e);
    return res.status(500).json({ items: [] });
  }
});

// DELETE by record id: DELETE /api/records/:id
app.delete("/api/records/:id", ensureAuthenticated, async (req, res) => {
  try {
    const me = String(req.session.userId || "");
    const recordId = String(req.params.id || "").trim();
    if (!me) return res.status(401).json({ items: [] });
    if (!mongoose.isValidObjectId(recordId)) return res.status(400).json({ items: [] });

    const rec = await Record.findById(recordId).lean();
    if (!rec || rec.deletedAt) return res.status(404).json({ items: [] });

    const dt = await DataType.findById(rec.dataTypeId).lean();
    if (!dt?._id) return res.status(404).json({ items: [] });

    const roles = req.session?.roles || [];
    const isAdmin = roles.includes("admin");
    const isPro = roles.includes("pro");

    const baseQ = { _id: recordId, dataTypeId: dt._id, deletedAt: null };

    let q;
    if (isAdmin) {
      q = baseQ;
    } else if (isPro) {
      const vis = await enforcedWhereForUser({ dataTypeId: String(dt._id), userId: me });
      q = { $and: [baseQ, vis] };
    } else {
      q = { ...baseQ, createdBy: me };
    }

    const updated = await Record.findOneAndUpdate(
      q,
      { $set: { deletedAt: new Date(), updatedBy: me }, $currentDate: { updatedAt: true } },
      { new: true }
    ).lean();

    return res.json({ items: updated ? [updated] : [] });
  } catch (e) {
    console.error("DELETE /api/records/:id (alias) failed:", e);
    return res.status(500).json({ items: [] });
  }
});
















///////////////////////////////////////////////////////////////////////////////////////////////////////
                                  //Helpers 
function to12h(hhmm = '00:00') {
  const [H, M='0'] = String(hhmm).split(':');
  let h = parseInt(H, 10), m = parseInt(M, 10);
  const ap = h >= 12 ? 'PM' : 'AM';
  h = h % 12; if (h === 0) h = 12;
  return `${h}:${String(m).padStart(2,'0')} ${ap}`;
}
function prettyDate(ymd = '2025-01-01') {
  try {
    const d = new Date(`${ymd}T00:00:00`);
    return d.toLocaleDateString(undefined, { weekday:'short', month:'short', day:'numeric', year:'numeric' });
  } catch { return ymd; }
}
function objIdFromRef(ref) {
  if (!ref) return null;
  const id = (typeof ref === 'object') ? (ref._id || ref.id) : ref;
  try { return id ? new mongoose.Types.ObjectId(String(id)) : null; }
  catch { return null; }
}

function makeIcsBuffer({ title, description='', location='', startISO, durationMin=60, organizerName='', organizerEmail='' }) {
  const d = new Date(startISO);
  return new Promise((resolve, reject) => {
    createEvent({
      start: [d.getFullYear(), d.getMonth()+1, d.getDate(), d.getHours(), d.getMinutes()],
      duration: { minutes: durationMin },
      title,
      description,
      location,
      organizer: organizerEmail ? { name: organizerName || '', email: organizerEmail } : undefined,
      status: 'CONFIRMED',
      busyStatus: 'BUSY',
    }, (err, value) => err ? reject(err) : resolve(Buffer.from(value)));
  });
}

async function sendBookingEmailWithResend({ to, subject, html, icsBuffer, cc=[], bcc=[], replyTo='' }) {
  const from = process.env.MAIL_FROM; // e.g. "Your Biz <bookings@yourdomain.com>"
  const attachments = icsBuffer ? [{ filename: 'appointment.ics', content: icsBuffer }] : undefined;

  return resend.emails.send({
    from,
    to,
    subject,
    html,
    attachments,
    cc: cc.length ? cc : undefined,
    bcc: bcc.length ? bcc : undefined,
    reply_to: replyTo || undefined,
  });
}
// server.js (or routes file on 8400)
app.post('/api/booking/notify', async (req, res) => {
  try {
    // TODO: send email/SMS here (Resend/Nodemailer/Twilio etc.)
    console.log('[notify] payload:', req.body);
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error('[notify] failed', e);
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});





                       //Slug stuff and business stuff
                       // server.js (top of file, before routes)
function escapeRegex(s = '') {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
// 1) JSON data for a business booking slug, e.g. /HairEverywhere.json
// ---- helper once (near top) ----
function normSlug(s = '') {
  return String(s).trim().toLowerCase()
    .replace(/\s+/g, '-')        // spaces -> dashes
    .replace(/[^a-z0-9\-]/g, ''); // strip weird chars
}

// GET /:slug.json  — robust business resolver
// GET /:slug.json  — resolve Business OR Location/Suite Location by slug
app.get('/:slug.json', async (req, res, next) => {
  const raw = (req.params.slug || '').trim();
  if (!raw || raw.includes('.') || RESERVED.has(raw)) return next();

  const wanted = normSlug(raw);

  try {
    // Find all relevant datatypes (Business + Suite/Location variants)
    const dts = await DataType.find({}).lean();
    const wantedTypes = dts.filter(dt => {
      const n = (dt.name || '').toLowerCase();
      return (
        n.includes('business') ||
        n.includes('location') ||
        n.includes('suite location') ||
        n.includes('suite')        // 👈 NEW: this catches "Suite"
      );
    });

    const typeIds = wantedTypes.map(dt => String(dt._id));

    // For safety also look at explicit dataType string
    const candidates = await Record.find({
      deletedAt: null,
      $or: [
        { dataTypeId: { $in: typeIds } },
        { dataType: { $in: ['Business', 'Location', 'Suite', 'Suite Location'] } }, // 👈 add "Suite"
      ],
    }).lean();

    const pick = candidates.find(doc => {
      const v = doc?.values || {};
      const fields = [
        v.slug,
        v.Slug,
        v['slug '],
        v['Slug '],
        v.businessSlug,
        v['Business Slug'],
        v.bookingSlug,
        v.locationSlug,
        v['Location Slug'],
        v['Suite Location Slug'],
        v.name,
        v.Name,
        v['Business Name'],
        v['Location Name'],
        v['Suite Location Name'],
      ];
      return fields.some(f => f && normSlug(f) === wanted);
    });

    if (!pick) {
      return res.status(404).json({ message: 'Record not found', slug: raw });
    }

    const dtype =
      pick.dataType ||
      (wantedTypes.find(dt => String(dt._id) === String(pick.dataTypeId))?.name) ||
      '';

    return res.json({
      _id: pick._id,
      values: pick.values || {},
      dataTypeName: dtype,  // used by page.tsx
    });
  } catch (e) {
    console.error('GET /:slug.json error:', e);
    return res.status(500).json({ message: 'Server error' });
  }
});



// GET /api/public/booking-page-by-slug/:slug
app.get('/api/public/booking-page-by-slug/:slug', async (req, res) => {
  try {
    const rawSlug = String(req.params.slug || '').trim();
    const slugLower = rawSlug.toLowerCase();
    if (!slugLower) {
      return res.status(400).json({ error: 'slug required' });
    }

    // 1) Resolve Business DataType
    const bizDT = await getDataTypeByNameLoose('Business');

    // First, try a direct Mongo query with a flexible slug match
    const slugMatchOr = [
      { 'values.slug': rawSlug },
      { 'values.slug': slugLower },
      { 'values.Slug': rawSlug },
      { 'values.Slug': slugLower },
      { 'values.Business Slug': rawSlug },
      { 'values.Business Slug': slugLower },
    ];

    const baseAnd = [{ $or: slugMatchOr }, { deletedAt: null }];

    if (bizDT?._id) {
      baseAnd.push({ dataTypeId: bizDT._id });
    } else {
      // fallback for any older records that used typeName / dataType
      baseAnd.push({
        $or: [{ typeName: 'Business' }, { dataType: 'Business' }],
      });
    }

    let biz = await Record.findOne({ $and: baseAnd }).lean();

    //  🔁 If that still didn't find anything, do a broader fetch
    //  and manually match slug like your React code does.
    if (!biz) {
      const broadQuery = { deletedAt: null };
      if (bizDT?._id) {
        broadQuery.dataTypeId = bizDT._id;
      } else {
        broadQuery.$or = [{ typeName: 'Business' }, { dataType: 'Business' }];
      }

      const candidates = await Record.find(broadQuery)
        .limit(200)
        .lean();

      biz =
        candidates.find((r) => {
          const v = r?.values || {};
          const s1 = String(v.slug ?? '').trim().toLowerCase();
          const s2 = String(v.Slug ?? '').trim().toLowerCase();
          const s3 = String(r.slug ?? '').trim().toLowerCase();
          return s1 === slugLower || s2 === slugLower || s3 === slugLower;
        }) || null;
    }

    if (!biz) {
      return res.status(404).json({ error: 'Business not found' });
    }

    const bizId = biz._id.toString();
    const selectedId = biz.values?.selectedBookingPageId || '';

    // 2) Resolve CustomBookingPage DataType
    const pageDT = await getDataTypeByNameLoose('CustomBookingPage');

    const pageQuery = {
      deletedAt: null,
      $or: [
        { 'values.businessId': bizId },
        { 'values.Business': bizId },
        { 'values.ownerId': bizId },
      ],
    };

    if (pageDT?._id) {
      pageQuery.dataTypeId = pageDT._id;
    } else {
      pageQuery.$or.push(
        { typeName: 'CustomBookingPage' },
        { dataType: 'CustomBookingPage' }
      );
    }

    const pages = await Record.find(pageQuery).lean();

    const isPublished = (v = {}) =>
      v.published === true ||
      v.Published === true ||
      v['is Published'] === true ||
      String(v.status || '').toLowerCase() === 'published';

    const pickTime = (v = {}) =>
      new Date(
        v.updatedAt || v.createdAt || biz.updatedAt || biz.createdAt || 0
      ).getTime();

    const pickJson = (v = {}) =>
      v.pageJson || v.PageJson || v.json || v.JSON || '';

    // 1) Prefer selected + published
    let chosen = pages.find(
      (p) =>
        String(p._id) === String(selectedId) && isPublished(p.values || {})
    );

    // 2) Else newest published
    if (!chosen) {
      chosen = pages
        .filter((p) => isPublished(p.values || {}))
        .sort((a, b) => pickTime(b.values || {}) - pickTime(a.values || {}))[0];
    }

    if (chosen) {
      const jsonStr = pickJson(chosen.values || {});
      return res.json({
        kind: 'custom',
        businessId: bizId,
        pageId: chosen._id,
        json: jsonStr,
      });
    }

    // 3) Fallback to template key if no custom page found
    return res.json({
      kind: 'template',
      businessId: bizId,
      templateKey: biz.values?.templateKey || 'basic',
    });
  } catch (e) {
    console.error('booking-page-by-slug failed:', e);
    res.status(500).json({ error: 'Resolver failed' });
  }
});


// 2) Page render for the booking page (EJS). Front-end JS will call /:slug.json
app.get('/:slug', (req, res, next) => {
  const { slug } = req.params;
  if (!slug || slug.includes('.') || RESERVED.has(slug)) return next();
  res.render('booking-page', { slug });
});

//app.get('/:slug', (req, res, next) => {
  //const slug = String(req.params.slug || '');
  // let real API paths/assets pass through
  //if (slug === 'api' || slug.includes('.')) return next();
  // redirect to Next frontend
//  res.redirect(302, `https://www.suiteseat.io/${slug}`);
//});

// 2) Public records (GET)
const {
  getDataTypeByNameLoose,
  normalizeValuesForType,
  normalizeWhereForType,
  normalizeSortForType,
} = require('./utils/normalize');

// --- Auth helpers (optional) ---



// 2) Compute a unique slug for a type, scoped to current user
app.post('/api/slug/:typeName', ensureAuthenticated, async (req, res) => {
  try {
    const typeName = decodeURIComponent(req.params.typeName || '').trim();
    const baseRaw  = String(req.body.base || '');
    const excludeId = req.body.excludeId || null;

    console.log('[slug] request', { typeName, baseRaw, excludeId, userId: req.session.userId });

    const dt = await getDataTypeByName(typeName);
    if (!dt) return res.status(404).json({ error: `Data type "${typeName}" not found` });

    const base = baseRaw
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '');

    let slug = base || 'item';
    let i = 1;

const baseQuery = {
  dataTypeId: dt._id,
  'values.slug': slug,
  deletedAt: null
};

    if (excludeId) baseQuery._id = { $ne: excludeId };

    while (await Record.exists(baseQuery)) {
      slug = `${base}${i++}`;
      baseQuery['values.slug'] = slug;
    }

    console.log('[slug] response', { typeName, slug });
    return res.json({ slug });

  } catch (e) {
    console.error('[slug] error', e);
    return res.status(500).json({ error: e.message });
  }
});

// Debug: list normalized slugs for all Business records
app.get('/debug/business-slugs', async (_req, res) => {
  try {
    const dt = await DataType.findOne({ name: /Business/i, deletedAt: null }).lean();
    const rows = await Record.find({
      deletedAt: null,
      $or: [{ dataTypeId: dt?._id || null }, { dataType: 'Business' }, { typeName: 'Business' }],
    }).select({ values: 1, _id: 1 }).lean();

    const norm = s => String(s||'').trim().toLowerCase()
      .replace(/\s+/g, '-').replace(/[^a-z0-9\-]/g, '');

    const list = rows.map(r => {
      const v = r.values || {};
      const candidates = [
        v.slug, v.Slug, v['slug '], v['Slug '],
        v.businessSlug, v['Business Slug'], v.bookingSlug,
        v.name, v.Name, v['Business Name']
      ].filter(Boolean);
      return {
        _id: String(r._id),
        raw: candidates,
        normalized: candidates.map(norm),
      };
    });

    res.json({ count: list.length, list });
  } catch (e) {
    console.error('/debug/business-slugs failed', e);
    res.status(500).json({ error: 'debug_failed' });
  }
});
// One-time helper: set values.slug from Name/Business Name if missing
app.post('/debug/fix-business-slugs', async (_req, res) => {
  try {
    const dt = await DataType.findOne({ name: /Business/i, deletedAt: null }).lean();
    const rows = await Record.find({
      deletedAt: null,
      $or: [{ dataTypeId: dt?._id || null }, { dataType: 'Business' }, { typeName: 'Business' }],
    }).lean();

    const slugify = s => String(s||'').trim().toLowerCase()
      .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'business';

    let fixed = 0;
    for (const r of rows) {
      const v = r.values || {};
      const hasSlug = v.slug || v.Slug || v['Business Slug'] || v.bookingSlug;
      if (hasSlug) continue;

      const name = v['Business Name'] || v.Name || v.name || '';
      if (!name) continue;

      const slug = slugify(name);
      await Record.updateOne({ _id: r._id }, { $set: { 'values.slug': slug } });
      fixed++;
    }
    res.json({ ok: true, fixed });
  } catch (e) {
    console.error('fix-business-slugs failed', e);
    res.status(500).json({ error: 'fix_failed' });
  }
});
// --- in server.js (near the other admin/public helpers) ---
app.post('/admin/fix-business-slugs', async (_req, res) => {
  try {
    const bizDT = await DataType.findOne({ name: /Business/i }).lean();
    if (!bizDT) return res.status(404).json({ fixed: 0, note: 'Business datatype not found' });

    const rows = await Record.find({ dataTypeId: bizDT._id, deletedAt: null }).lean();
    let fixed = 0;

    const slugify = (s='') =>
      String(s).trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'business';

    for (const r of rows) {
      const v = r.values || {};
      const existing =
        v.slug || v.Slug || v['Business Slug'] || v.businessSlug || v.bookingSlug || v['slug '] || v['Slug '];

      if (existing) continue;

      const name =
        v['Business Name'] || v['Name'] || v['businessName'] || v['name'] || '';
      if (!name) continue;

      let slug = slugify(name);

      // ensure uniqueness among Businesses
      let n = 2;
      const collides = async (s) => !!(await Record.exists({
        _id: { $ne: r._id },
        dataTypeId: bizDT._id,
        deletedAt: null,
        $or: [
          { 'values.slug': s }, { 'values.Slug': s }, { 'values.businessSlug': s },
          { 'values.bookingSlug': s }, { 'values.Business Slug': s }
        ]
      }));

      while (await collides(slug)) slug = `${slug}-${n++}`;

      await Record.updateOne({ _id: r._id }, { $set: { 'values.slug': slug } });
      fixed++;
    }

    res.json({ ok: true, fixed });
  } catch (e) {
    console.error('fix-business-slugs failed:', e);
    res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// POST /admin/set-business-slug { name: "trafe", slug: "trafe" }
app.post('/admin/set-business-slug', async (req, res) => {
  try {
    const name = String(req.body?.name || '').trim();
    const slug = String(req.body?.slug || '').trim().toLowerCase();
    if (!name || !slug) return res.status(400).json({ ok:false, error:'name and slug required' });

    const bizDT = await DataType.findOne({ name: /Business/i, deletedAt: null }).lean();
    if (!bizDT) return res.status(404).json({ ok:false, error:'Business datatype not found' });

    const biz = await Record.findOne({
      dataTypeId: bizDT._id,
      deletedAt: null,
      $or: [
        { 'values.Name': name },
        { 'values.businessName': name },
        { 'values["Business Name"]': name }
      ]
    }).lean();

    if (!biz) return res.status(404).json({ ok:false, error:'Business not found by name' });

    await Record.updateOne({ _id: biz._id }, { $set: { 'values.slug': slug } });
    res.json({ ok:true, id: String(biz._id), slug });
  } catch (e) {
    console.error('set-business-slug failed', e);
    res.status(500).json({ ok:false, error:String(e?.message||e) });
  }
});


// Return { slug: "business-slug" } for a Business record by its _id
// --- Public: get a Business slug by its Record _id ---
// Return { slug: "business-slug" } for a Business record by its _id
app.get('/api/public/business-slug/:id', async (req, res) => {
  try {
    const id = String(req.params.id || '').trim();
    if (!id) return res.json({ slug: '' });

    const biz = await Record.findOne({ _id: id, deletedAt: null })
      .select({ values: 1 })
      .lean();

    if (!biz) return res.status(404).json({ slug: '' });

    // 1) Try existing slug fields
    let slug =
      biz?.values?.slug ||
      biz?.values?.Slug ||
      biz?.values?.['Business Slug'] ||
      '';

    // 2) If missing, derive from a name and persist
    if (!slug) {
      const name =
        biz.values?.businessName ||
        biz.values?.name ||
        biz.values?.['Business Name'] ||
        '';

      if (!name) return res.json({ slug: '' }); // no name to derive from

      slug = slugify(name);

      // Optional: ensure uniqueness among Businesses (simple suffix)
      const conflict = await Record.findOne({
        _id: { $ne: biz._id },
        deletedAt: null,
        'values.slug': slug
      }).lean();

      if (conflict) slug = `${slug}-${biz._id.toString().slice(-4)}`;

      // Save back so next lookups are instant
      await Record.updateOne(
        { _id: biz._id },
        { $set: { 'values.slug': slug } }
      );
    }

    res.json({ slug });
  } catch (e) {
    console.error('GET /api/public/business-slug failed:', e);
    res.json({ slug: '' });
  }
});

app.get('/api/public/booking-slug/by-business/:id', async (req, res) => {
  try {
    const bizId = String(req.params.id || '').trim();
    if (!bizId) return res.json({ slug: '' });

    // helpers to resolve datatypes by name
    async function getDT(name) {
      if (typeof getDataTypeByNameLoose === 'function') {
        const dt = await getDataTypeByNameLoose(name);
        return dt?._id || null;
      }
      return null;
    }

    const businessDT = await getDT('Business');
    const pageDT     = await getDT('CustomBookingPage');

    // fetch the Business to read selectedBookingPageId (if present)
    const biz = await Record.findOne({
      _id: bizId, deletedAt: null,
      ...(businessDT ? { dataTypeId: businessDT } : {})
    }).lean();

    const selectedId = biz?.values?.selectedBookingPageId || '';

    // find pages tied to this business by any of the common keys
    const pages = await Record.find({
      deletedAt: null,
      ...(pageDT ? { dataTypeId: pageDT } : {}),
      $or: [
        { 'values.businessId': bizId },
        { 'values.Business': bizId },
        { 'values.ownerId': bizId }
      ]
    }).lean();

    const isPublished = (v = {}) =>
      v.published === true || v.Published === true ||
      v['is Published'] === true ||
      String(v.status || '').toLowerCase() === 'published';

    // Prefer the selected + published one, else newest published
    let chosen = pages.find(p => String(p._id) === String(selectedId) && isPublished(p.values));
    if (!chosen) {
      chosen = pages
        .filter(p => isPublished(p.values))
        .sort((a, b) => new Date(b.updatedAt || b.createdAt) - new Date(a.updatedAt || a.createdAt))[0];
    }

    const slug = chosen?.values?.slug || chosen?.values?.Slug || '';
    return res.json({ slug: slug || '' });
  } catch (e) {
    console.error('GET /api/public/booking-slug/by-business failed:', e);
    res.json({ slug: '' });
  }
});
// GET /api/public/business/by-slug/:slug  -> { business: {...} }
app.get('/api/public/business/by-slug/:slug', async (req, res) => {
  try {
    const slug = String(req.params.slug || '').trim();
    if (!slug) return res.status(400).json({ error: 'missing slug' });

    // find a "Business" record by slug (your values may be under different keys)
    const biz = await Record.findOne({
      deletedAt: null,
      $or: [
        { 'values.slug': slug },
        { 'values.Slug': slug },
        { 'values.Business Slug': slug }
      ]
    })
    .select({ values: 1, _id: 1, createdAt: 1, updatedAt: 1 })
    .lean();

    if (!biz) return res.status(404).json({ error: 'not_found' });

    const v = biz.values || {};
    res.json({
      business: {
        id: String(biz._id),
        name: v.businessName || v.name || '',
        slug: v.slug || v.Slug || v['Business Slug'] || slug,
        logoUrl: v.logoUrl || v.logo || '',
        phone: v.phone || v.Phone || '',
        email: v.email || v.Email || '',
        address: v.address || v.Address || '',
      }
    });
  } catch (e) {
    console.error('GET /api/public/business/by-slug failed:', e);
    res.status(500).json({ error: 'server_error' });
  }
});


























async function enrichAppointment(rawValues) {
  // Attach Business Owner + Pro Name from Business
  const businessId = objIdFromRef(rawValues['Business']);
  if (businessId) {
    const bizDT = await DataType.findOne({ name: /Business/i, deletedAt: null }).lean();
    if (bizDT) {
      const biz = await Record.findOne({ _id: businessId, dataTypeId: bizDT._id, deletedAt: null }).lean();
      if (biz) {
        if (biz.createdBy && !rawValues['Business Owner']) {
          rawValues['Business Owner'] = { _id: String(biz.createdBy) };
        }
        const pn = biz.values?.['Pro Name'] || biz.values?.proName || biz.values?.stylistName;
        if (pn && !rawValues['Pro Name']) rawValues['Pro Name'] = pn;
      }
    }
  }

  // Attach Pro from Calendar if client didn't provide it
  const calId = objIdFromRef(rawValues['Calendar']);
  if (calId && !rawValues['Pro']) {
    const calDT = await DataType.findOne({ name: /Calendar/i, deletedAt: null }).lean();
    if (calDT) {
      const cal = await Record.findOne({ _id: calId, dataTypeId: calDT._id, deletedAt: null }).lean();
      const v = cal?.values || {};
      const proLike = v.Pro || v['Pro Ref'] || v.Staff || v['Staff Ref'] || v.Professional || v.Provider || v.Owner;
      const proId = proLike?._id || proLike?.id || (typeof proLike === 'string' ? proLike : null);
      if (proId) rawValues['Pro'] = { _id: String(proId) };
    }
  }

  return rawValues;
}

















//////////////////////////////////////////////
                                 //User Authentication

// Save profile updates (name, phone, etc.) + optional file upload
app.post(
  "/update-user-profile",
  ensureAuthenticated,
 upload.single("profilePhoto")
,
  async (req, res) => {
    try {
      const userId = req.session.userId;

      const prev = await AuthUser.findById(userId).lean();

      const { firstName, lastName, phone, address, email } = req.body;
      const update = { firstName, lastName, phone, address, email };

      // ✅ upload to Cloudinary instead of /uploads
      if (req.file?.buffer) {
        const uploaded = await uploadBufferToCloudinary(req.file.buffer, {
          folder: "suiteseat/users",
          public_id: `user_${userId}_profile`,
        });

        update.profilePhoto = uploaded.secure_url; // store full https URL
      }

      const user = await AuthUser.findByIdAndUpdate(userId, update, { new: true, lean: true });
      if (!user) return res.status(404).json({ message: "User not found" });

      const stats = await propagateProfileToCRM(
        { userId, firstName: user.firstName, lastName: user.lastName, email: user.email, phone: user.phone },
        prev?.email
      );

      res.json({ user, propagated: stats });
    } catch (e) {
      console.error("POST /update-user-profile failed:", e);
      res.status(500).json({ message: "Server error saving profile" });
    }
  }
);




// Returns { user: { _id, firstName, lastName, email, phone, address, profilePhoto } }
app.get('/api/users/me', ensureAuthenticated, async (req, res) => {
  try {
    const u = await AuthUser.findById(req.session.userId).lean();
    if (!u) return res.status(404).json({ error: 'User not found' });

    res.json({
      user: {
        _id: String(u._id),
        firstName:   u.firstName   || '',
        lastName:    u.lastName    || '',
        email:       u.email       || '',
        phone:       u.phone       || '',
        address:     u.address     || '',   // string is fine; if you store an object, serialize as needed
        profilePhoto:u.profilePhoto|| ''    // e.g. "/uploads/169..._avatar.png"
      }
    });
  } catch (e) {
    console.error('GET /api/users/me failed:', e);
    res.status(500).json({ error: e.message });
  }
});


app.get('/api/me/records', ensureAuthenticated, async (req, res) => {
  try {
    const userId = String(req.session.userId || '');
    if (!userId) return res.status(401).json({ error: 'Not logged in' });

    const {
      dataType,
      where: whereStr,
      sort: sortStr,
      includeCreatedBy = '1',
      includeRefField = '1',
      myRefField = 'Client',
      limit = '100',
      skip  = '0',
    } = req.query;

    if (!dataType) return res.status(400).json({ error: 'dataType required' });

    const dt = await getDataTypeByNameLoose(dataType);
    if (!dt) return res.json({ data: [] });

    let whereRaw = {};
    if (whereStr) { try { whereRaw = JSON.parse(whereStr); } catch {} }
    const where = await normalizeWhereForType(dt._id, whereRaw);

    const ors = [];

    if (includeCreatedBy === '1' || includeCreatedBy === 'true') {
      ors.push({ createdBy: req.session.userId });
    }

    if (includeRefField === '1' || includeRefField === 'true') {
      // ✅ allow values.* filters
      if (String(myRefField).startsWith('values.')) {
        ors.push({ [myRefField]: userId });
      } else {
        const mineByRef = await normalizeWhereForType(dt._id, { [myRefField]: userId });
        ors.push(mineByRef);
      }
    }

    const q = { dataTypeId: dt._id, deletedAt: null, ...where };
    if (ors.length) q.$or = ors;

    let mongoSort = { createdAt: -1 };
    if (sortStr) { try { mongoSort = await normalizeSortForType(dt._id, JSON.parse(sortStr)); } catch {} }

    const lim = Math.min(parseInt(limit, 10) || 100, 500);
    const skp = Math.max(parseInt(skip, 10) || 0, 0);

    const rows = await Record.find(q)
      .sort(mongoSort).skip(skp).limit(lim)
      .populate({ path: 'createdBy', select: 'firstName lastName name' })
      .lean();

    res.json({
      data: rows.map(r => ({
        _id: r._id,
        values: r.values || {},
        createdBy: r.createdBy ? {
          firstName: r.createdBy.firstName || '',
          lastName:  r.createdBy.lastName  || '',
          name:      r.createdBy.name      || ''
        } : null
      }))
    });

  } catch (e) {
    console.error('GET /api/me/records failed:', e);
    res.status(500).json({ error: e.message });
  }
});




// CLIENT signup (customers)
app.post("/signup", async (req, res) => {
  try {
    const { firstName, lastName, email, password, phone } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ message: "Email & password required" });
    }

    const emailNorm = String(email).toLowerCase().trim();

    const existing = await AuthUser.findOne({ email: emailNorm });
    if (existing) return res.status(409).json({ message: "Email already in use" });

    const passwordHash = await bcrypt.hash(password, 10);

    const user = await AuthUser.create({
      firstName: firstName || "",
      lastName: lastName || "",
      email: emailNorm,
      phone: phone || "",
      passwordHash,
      roles: ["client"],
    });

    // ✅ ALWAYS store as string + keep session shape consistent
    req.session.userId = String(user._id);
    req.session.roles = user.roles || ["client"];
    req.session.user = {
      _id: String(user._id),
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      roles: req.session.roles,
    };

    return res.json({
      ok: true,
      user: req.session.user,
    });
  } catch (e) {
    console.error("[signup client] failed:", e);
    return res.status(500).json({ message: "Signup failed" });
  }
});


// PRO signup (service providers)
app.post("/signup/pro", async (req, res) => {
  try {
    const { firstName, lastName, email, password, phone } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ message: "Missing email/password" });
    }

    const emailNorm = String(email).toLowerCase().trim();

    const existing = await AuthUser.findOne({ email: emailNorm });
    if (existing) return res.status(409).json({ message: "Email already in use" });

    const passwordHash = await bcrypt.hash(password, 10);

    const user = await AuthUser.create({
      firstName: firstName || "",
      lastName: lastName || "",
      email: emailNorm,
      phone: phone || "",
      passwordHash,
      roles: ["pro"],
    });

    // ✅ same session shape as client
    req.session.userId = String(user._id);
    req.session.roles = user.roles || ["pro"];
    req.session.user = {
      _id: String(user._id),
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      roles: req.session.roles,
    };

    return res.status(201).json({
      ok: true,
      user: req.session.user,
      redirect: "/appointment-settings",
    });
  } catch (e) {
    console.error("[signup pro] failed:", e);
    return res.status(500).json({ message: "Signup failed" });
  }
});

// POST /api/guest-signup
app.post("/api/guest-signup", async (req, res) => {
  try {
    const { email, password, firstName = "", lastName = "" } = req.body || {};
    if (!email || !password) return res.status(400).json({ message: "Email & password required" });

    const existing = await AuthUser.findOne({ email: String(email).toLowerCase().trim() });
    if (existing) return res.status(409).json({ message: "Email already in use. Please log in." });

    const passwordHash = await bcrypt.hash(String(password), 10);
    const user = await AuthUser.create({
      email: String(email).toLowerCase().trim(),
      passwordHash,
      firstName,
      lastName,
      roles: ["client"],
    });

    req.session.userId = String(user._id);
    req.session.user = {
      _id: String(user._id),
      email: user.email,
      firstName: user.firstName || "",
      lastName: user.lastName || "",
    };
    await req.session.save();

    return res.json({ ok: true, user: req.session.user });
  } catch (e) {
    console.error("[guest-signup] error", e);
    return res.status(500).json({ message: "Guest signup failed" });
  }
});

// ✅ Debug + compatibility aliases for booking page login (ADD ONLY)
app.post("/auth/login", (req, res, next) => {
  // if anything calls /auth/login, reuse /api/login
  req.url = "/api/login";
  next();
});

app.get("/auth/login", (_req, res) => {
  // prevents "Cannot GET /auth/login" confusion
  res.status(405).json({ ok: false, message: "Use POST /api/login" });
});

// ✅ DEBUG route so you can see what the server receives
app.post("/api/login-debug", (req, res) => {
  res.json({
    ok: true,
    got: req.body,
    cookie: req.headers.cookie || null,
    origin: req.headers.origin || null,
  });
});

// ✅ Alias so both /check-login and /api/check-login work
app.get("/api/check-login", (req, res) => {
  req.url = "/check-login";
  app.handle(req, res);
});

app.post('/api/login', async (req, res) => {
  console.log("[login] incoming", {
    email: req.body?.email,
    hasPassword: !!req.body?.password,
    origin: req.headers.origin,
    cookieIn: req.headers.cookie || null,
  });

  const { email, password } = req.body || {};
  const e = String(email).toLowerCase().trim();

  const user = await AuthUser.findOne({ email: e });
  console.log("[login] foundUser:", !!user, "emailNorm:", e);

  if (!user) return res.status(401).json({ message: "Invalid credentials" });

  const ok = await bcrypt.compare(String(password || ""), user.passwordHash);
  console.log("[login] passwordMatch:", ok);

  if (!ok) return res.status(401).json({ message: "Invalid credentials" });

  req.session.regenerate(async (err) => {
    if (err) return res.status(500).json({ message: "Session error" });

    req.session.userId = String(user._id);
    req.session.roles  = Array.isArray(user.roles) ? user.roles : [];
    req.session.user   = {
      _id: String(user._id),
      email: user.email,
      firstName: user.firstName || "",
      lastName: user.lastName || "",
    };

    await req.session.save();

    console.log("[login] session set", {
      sessionID: req.sessionID,
      userId: req.session.userId,
      roles: req.session.roles,
    });

    res.json({ ok: true, user: req.session.user });
  });
});



// --- DEV ONLY: turn on admin/pro in the session ---
app.post('/dev/admin-on', (req, res) => {
  // use a stable fake ObjectId
  const fakeId = '000000000000000000000001';
  req.session.userId = req.session.userId || fakeId;
  const roles = new Set(req.session.roles || []);
  roles.add('pro'); roles.add('admin');
  req.session.roles = [...roles];
  res.json({ ok: true, userId: req.session.userId, roles: req.session.roles });
});

// Dev toggle to become admin quickly
app.get('/dev/admin-on', (req, res) => {
  if (!req.session?.userId) return res.status(401).json({ ok: false, message: 'Login first' });
  const roles = new Set(req.session.roles || []);
  roles.add('pro'); roles.add('admin');
  req.session.roles = [...roles];
  res.json({ ok: true, roles: req.session.roles, userId: String(req.session.userId) });
});



// ME (session probe)
app.get('/api/me', (req, res) => {
  const id = req.session?.userId || null;
  const u  = req.session?.user   || null;

  if (!id || !u) {
    return res.json({ ok: false, user: null });
  }

  res.json({
    ok: true,
    user: {
      _id: String(id),
      email:     u.email     || '',
      firstName: u.firstName || '',
      lastName:  u.lastName  || '',
    },
  });
});


// server.js (or routes/auth.js)
app.post('/api/logout', (req, res) => {
  try {
    // destroy server session
    req.session?.destroy?.(() => {});
    // clear the session cookie
    res.clearCookie('connect.sid'); // or your custom cookie name
    return res.status(200).json({ ok: true });
  } catch (e) {
    return res.status(200).json({ ok: true });
  }
});


app.get('/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});


                                    

// --- helpers ---

async function getDataTypeByName(typeName) {
  return DataType.findOne({ name: typeName, deletedAt: null });
}


// --- CREATE a record: POST /api/records/:typeName ---
const { isValidObjectId } = mongoose;


// Ensure /check-login isn’t cached (so tabs don’t get stale)
app.get("/check-login", async (req, res) => {
  res.set("Cache-Control", "no-store");

  try {
    const userId = req.session?.userId;
    if (!userId) return res.json({ loggedIn: false });

    const u = await AuthUser.findById(userId).lean();
    if (!u) return res.json({ loggedIn: false });

    let first = String(u.firstName || u.first_name || "").trim();
    let last  = String(u.lastName  || u.last_name  || "").trim();

    // Optional enrich from Record if missing (keep your logic if you want)
    if (!first || !last) {
      try {
        const profile = await Record.findOne({
          deletedAt: { $exists: false },
          dataType: { $in: ["User", "Client", "Profile"] },
          $or: [
            { "values.userId": String(u._id) },
            { createdBy: u._id },
            { "values.Email": u.email },
            { "values.email": u.email },
          ],
        }).lean();

        const pv = profile?.values || {};
        const pfFirst = String(pv["First Name"] || pv.firstName || pv.first_name || "").trim();
        const pfLast  = String(pv["Last Name"]  || pv.lastName  || pv.last_name  || "").trim();

        if (!first && pfFirst) first = pfFirst;
        if (!last  && pfLast)  last  = pfLast;
      } catch {}
    }

    const name = [first, last].filter(Boolean).join(" ").trim();

    // Keep session cache in sync (optional)
    req.session.user = req.session.user || {};
    req.session.user.email = req.session.user.email || u.email || "";
    req.session.user.firstName = first;
    req.session.user.lastName  = last;

    res.json({
      loggedIn: true,
      userId: String(u._id),
      user: {
        id: String(u._id),
        email: u.email || "",
        firstName: first || "",
        lastName: last || "",
        name: name || "",
      },
      roles: req.session.roles || [],
    });
  } catch (e) {
    console.error("check-login error:", e);
    res.status(500).json({ loggedIn: false });
  }
});






















/////////////////////////////////////////////////////////////////////
   
                          //Datatype Stuff
//helper 
async function resolveDataTypeId(input) {
  if (!input) throw new Error('dataType or dataTypeId is required');

  // if already a valid ObjectId, just return it
  if (mongoose.isValidObjectId(input)) return new mongoose.Types.ObjectId(input);

  // otherwise treat as a name; look up by nameCanonical
  const dt = await DataType.findOne({ nameCanonical: canon(String(input)) }, { _id: 1 }).lean();
  if (!dt) throw new Error(`Unknown DataType: ${input}`);
  return dt._id;
}


app.get('/api/datatypes', async (req, res) => {
  const list = await DataType.find().sort({ createdAt: 1 }).lean();
  res.json(list);
});

// Create
app.post('/api/datatypes', async (req, res) => {
  const { name, description = '' } = req.body || {};
  if (!name) return res.status(400).json({ error: 'Name required' });
  try {
    const doc = await DataType.create({ name, description });
    res.status(201).json(doc);
  } catch (e) {
    if (e.code === 11000) return res.status(409).json({ error: 'Name already exists' });
    console.error(e);
    res.status(500).json({ error: 'Failed to create' });
  }
});

// Read one
app.get('/api/datatypes/:id', async (req, res) => {
  const { id } = req.params;
  if (!mongoose.isValidObjectId(id)) return res.status(400).json({ error: 'Invalid id' });
  const doc = await DataType.findById(id).lean();
  if (!doc) return res.status(404).json({ error: 'Not found' });
  res.json(doc);
});

// Update
app.patch('/api/datatypes/:id', async (req, res) => {
  const { id } = req.params;
  const { name, description } = req.body || {};
  if (!mongoose.isValidObjectId(id)) return res.status(400).json({ error: 'Invalid id' });
  if (name === undefined && description === undefined) {
    return res.status(400).json({ error: 'Nothing to update' });
  }
  try {
    const update = {};
    if (typeof name === 'string' && name.trim()) update.name = name.trim();
    if (description !== undefined) update.description = String(description ?? '');

    const doc = await DataType.findByIdAndUpdate(id, update, {
      new: true,
      runValidators: true,
      context: 'query',
    });
    if (!doc) return res.status(404).json({ error: 'Not found' });
    res.json(doc);
  } catch (e) {
    if (e.code === 11000) return res.status(409).json({ error: 'Name already exists' });
    console.error(e);
    res.status(500).json({ error: 'Failed to update' });
  }
});

// Delete
app.delete('/api/datatypes/:id', async (req, res) => {
  const { id } = req.params;
  if (!mongoose.isValidObjectId(id)) return res.status(400).json({ error: 'Invalid id' });
  const doc = await DataType.findByIdAndDelete(id);
  if (!doc) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});



//Field
// ----- Fields -----
app.get('/api/fields', async (req, res) => {
  try {
    const { dataTypeId } = req.query;
    const q = { deletedAt: null };
    if (dataTypeId) q.dataTypeId = dataTypeId;

    const items = await Field.find(q)
      .sort({ createdAt: -1 })
      .populate('referenceTo', 'name')     // <-- add this
      .populate('optionSetId', 'name');    // <-- optional, for "Dropdown → SetName"

    res.json(items);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

//app.post('/api/fields',ensureAuthenticated, async (req, res) => {
    app.post('/api/fields', async (req, res) => {
  try {
    const { dataTypeId, name, type, allowMultiple, referenceTo, optionSetId } = req.body || {};
    if (!dataTypeId || !name || !type) {
      return res.status(400).json({ error: 'dataTypeId, name, type are required' });
    }
    if (!mongoose.isValidObjectId(dataTypeId)) {
      return res.status(400).json({ error: 'Invalid dataTypeId' });
    }
    if (type === 'Reference' && referenceTo && !mongoose.isValidObjectId(referenceTo)) {
      return res.status(400).json({ error: 'Invalid referenceTo' });
    }
    if (type === 'Dropdown' && optionSetId && !mongoose.isValidObjectId(optionSetId)) {
      return res.status(400).json({ error: 'Invalid optionSetId' });
    }

    const nameCanonical = canon(name);

    // Optional pre-check (your unique index will also enforce this)
    const dupe = await Field.findOne({ dataTypeId, nameCanonical, deletedAt: null });
    if (dupe) return res.status(409).json({ error: 'Field already exists (ignoring case/spaces)' });

    const created = await Field.create({
      dataTypeId,
      name,
      nameCanonical,
      type,
      allowMultiple: !!allowMultiple,
      referenceTo: referenceTo || null,
      optionSetId: optionSetId || null
    });
    res.status(201).json(created);
  } catch (e) {
    if (e.code === 11000) {
      return res.status(409).json({ error: 'Field already exists (unique index)' });
    }
    res.status(500).json({ error: e.message });
  }
});
//app.patch('/api/fields/:id', ensureAuthenticated, async (req, res) => {
app.patch('/api/fields/:id', async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.isValidObjectId(id)) return res.status(400).json({ error: 'Invalid id' });

    const setOps = {};
    if (req.body?.name) {
      setOps.name = String(req.body.name).trim();
      setOps.nameCanonical = canon(setOps.name);
    }
    if ('defaultOptionValueId' in req.body) {
      setOps.defaultOptionValueId = req.body.defaultOptionValueId || null;
    }
    if ('allowMultiple' in req.body) {
      setOps.allowMultiple = !!req.body.allowMultiple; // optional, matches your UI if you add a toggle later
    }

    if (!Object.keys(setOps).length) {
      return res.status(400).json({ error: 'Nothing to update' });
    }

    const updated = await Field.findOneAndUpdate(
      { _id: id, deletedAt: null },
      { $set: setOps },
      { new: true, runValidators: true, context: 'query' }
    );
    if (!updated) return res.status(404).json({ error: 'Not found' });
    res.json(updated);
  } catch (e) {
    if (e.code === 11000) {
      return res.status(409).json({ error: 'Field already exists (unique index)' });
    }
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/fields/:id', async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.isValidObjectId(id)) return res.status(400).json({ error: 'Invalid id' });

    const updated = await Field.findByIdAndUpdate(
      id,
      { deletedAt: new Date() },
      { new: true }
    );
    if (!updated) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Optional: server-side canon fallback (same as client helper)
function canon(s) {
  return String(s || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
}
//OptionSet

// ---------- Option Sets ----------
app.get('/api/optionsets', async (req, res) => {
  try {
    const sets = await OptionSet.find({ deletedAt: null }).sort({ createdAt: 1 }).lean();
    return res.json(sets); // keep as array since your frontend expects array
  } catch (e) {
    console.error("GET /api/optionsets error:", e);
    return res.status(500).json({ error: e.message });
  }
});

app.post('/api/optionsets', /*ensureAuthenticated,*/ async (req, res) => {
  try {
    const { name, kind = 'text' } = req.body || {};
    if (!name) return res.status(400).json({ error: 'name required' });
    const created = await OptionSet.create({ name, nameCanonical: canon(name), kind });
    res.status(201).json(created);
  } catch (e) {
    if (e.code === 11000) return res.status(409).json({ error: 'Set name already exists' });
    res.status(500).json({ error: e.message });
  }
});

app.patch('/api/optionsets/:id', /*ensureAuthenticated,*/ async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.isValidObjectId(id)) return res.status(400).json({ error: 'Invalid id' });

    const setOps = {};
    if (req.body?.name) setOps.name = String(req.body.name).trim();
    if (req.body?.kind) setOps.kind = req.body.kind;

    if (!Object.keys(setOps).length) return res.status(400).json({ error: 'Nothing to update' });

    if (setOps.name) setOps.nameCanonical = canon(setOps.name);

    const updated = await OptionSet.findOneAndUpdate(
      { _id: id, deletedAt: null },
      { $set: setOps },
      { new: true, runValidators: true, context: 'query' }
    );
    if (!updated) return res.status(404).json({ error: 'Not found' });
    res.json(updated);
  } catch (e) {
    if (e.code === 11000) return res.status(409).json({ error: 'Set name already exists' });
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/optionsets/:id', /*ensureAuthenticated,*/ async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.isValidObjectId(id)) return res.status(400).json({ error: 'Invalid id' });

    const set = await OptionSet.findOneAndUpdate(
      { _id: id, deletedAt: null },
      { $set: { deletedAt: new Date() } },
      { new: true }
    );
    if (!set) return res.status(404).json({ error: 'Not found' });

    // soft-delete its values too
    await OptionValue.updateMany({ optionSetId: id, deletedAt: null }, { $set: { deletedAt: new Date() } });

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});


// ---------- Option Values ----------
app.get('/api/optionsets/:id/values', async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.isValidObjectId(id)) return res.json([]);
    const vals = await OptionValue.find({ optionSetId: id, deletedAt: null })
      .sort({ order: 1, createdAt: 1 })
      .lean();
    return res.json(vals);
  } catch (e) {
    console.error("GET /api/optionsets/:id/values error:", e);
    return res.status(500).json({ error: e.message });
  }
});

app.post('/api/optionsets/:id/values', /*ensureAuthenticated,*/ async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.isValidObjectId(id)) return res.status(400).json({ error: 'Invalid optionSetId' });

    const { label, order = 0, imageUrl=null, numberValue=null, boolValue=null, colorHex=null } = req.body || {};
    if (!label) return res.status(400).json({ error: 'label required' });

    const created = await OptionValue.create({
      optionSetId: id,
      label,
      labelCanonical: canon(label),
      order,
      imageUrl, numberValue, boolValue, colorHex
    });
    res.status(201).json(created);
  } catch (e) {
    if (e.code === 11000) return res.status(409).json({ error: 'Value already exists in this set' });
    res.status(500).json({ error: e.message });
  }
});

app.patch('/api/optionvalues/:id', /*ensureAuthenticated,*/ async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.isValidObjectId(id)) return res.status(400).json({ error: 'Invalid id' });

    const setOps = {};
    if ('label' in req.body) {
      setOps.label = String(req.body.label).trim();
      setOps.labelCanonical = canon(setOps.label);
    }
    ['imageUrl','numberValue','boolValue','colorHex','order'].forEach(k => {
      if (k in req.body) setOps[k] = req.body[k];
    });

    if (!Object.keys(setOps).length) return res.status(400).json({ error: 'Nothing to update' });

    const updated = await OptionValue.findOneAndUpdate(
      { _id: id, deletedAt: null },
      { $set: setOps },
      { new: true, runValidators: true, context: 'query' }
    );
    if (!updated) return res.status(404).json({ error: 'Not found' });
    res.json(updated);
  } catch (e) {
    if (e.code === 11000) return res.status(409).json({ error: 'Duplicate value in set' });
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/optionvalues/:id', /*ensureAuthenticated,*/ async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.isValidObjectId(id)) return res.status(400).json({ error: 'Invalid id' });

    const updated = await OptionValue.findOneAndUpdate(
      { _id: id, deletedAt: null },
      { $set: { deletedAt: new Date() } },
      { new: true }
    );
    if (!updated) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});


















////////////////////////////////////////////////////////////////////////////////////////////////////////

                                     //Accept Appointments 
                                     // helper near the top of server.js (once)
 // ---------- helpers ----------
 //create slug 
// --- Slug helpers ---
function slugify(s = '') {
  return String(s).trim().toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')   // spaces & junk -> dashes
    .replace(/^-+|-+$/g, '') || 'business';
}

async function ensureUniqueBusinessSlug(base, excludeId = null) {
  const dt = await DataType.findOne({ name: /Business/i }).lean();
  if (!dt) return base || 'business';

  let slug = base || 'business';
  let n = 2;

  const collides = async (s) => {
    const q = {
      dataTypeId: dt._id,
      deletedAt: null,
      $or: [{ 'values.slug': s }, { 'values.businessSlug': s }],
    };
    if (excludeId) q._id = { $ne: excludeId };
    return !!(await Record.exists(q));
  };

  while (await collides(slug)) slug = `${base}-${n++}`;
  return slug;
}

// 1) JSON for a booking slug: /HairEverywhere.json
// Put this NEAR THE BOTTOM, after your /api, /qassets, /uploads, and
// explicit page routes like /admin, /signup, etc.
// Put this near the BOTTOM of server.js, after static + API + explicit page routes
const RESERVED = new Set([
  'api','public','uploads','qassets',
  'admin','signup','login','logout','availability',
  'appointment-settings','appqointment-settings',
  'favicon.ico','robots.txt','sitemap.xml'
]);

function normSlug(s = "") {
  return String(s)
    .trim()
    .toLowerCase()
    .replace(/\s+/g, "-")
    .replace(/[^a-z0-9\-]/g, "");
}

// ✅ PUBLIC: check if a slug is taken globally (any user)
// GET /public/slug-check?type=Business&slug=my-slug
app.get("/public/slug-check", async (req, res) => {
  try {
    const typeName = String(req.query.type || "").trim();
    const rawSlug  = String(req.query.slug || "").trim();

    if (!typeName || !rawSlug) {
      return res.json({ ok: true, taken: false });
    }

    const wanted = normSlug(rawSlug);

    const dt = await DataType.findOne({
      $or: [{ name: typeName }, { nameCanonical: typeName.toLowerCase() }],
      deletedAt: null,
    }).lean();

    if (!dt?._id) return res.json({ ok: true, taken: false });

    // check common slug storage patterns (yours is values.slug)
    const exists = await Record.exists({
      dataTypeId: dt._id,
      deletedAt: null,
      $or: [
        { "values.slug": wanted },
        { "values.Slug": wanted },
        { "values.bookingSlug": wanted },
        { "values.businessSlug": wanted },
        { "values.locationSlug": wanted },
        { "values['Business Slug']": wanted },
        { "values['Location Slug']": wanted },
      ],
    });

    return res.json({ ok: true, taken: !!exists });
  } catch (e) {
    console.error("[public/slug-check] error", e);
    return res.status(500).json({ ok: false, taken: false });
  }
});



function slugify(str = "") {
  return String(str)
    .toLowerCase()
    .trim()
    .replace(/['"]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
}

async function generateSlugForType(typeName, base, excludeId = null) {
  const resp = await fetch(`/api/slug/${encodeURIComponent(typeName)}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify({
      base: String(base || ""),
      excludeId: excludeId || null, // keep null on create
    }),
  });

  const out = await resp.json().catch(() => ({}));
  return out?.slug || "";
}






























// --- GET one record: GET /api/records/:typeName/:id ---
// GET one record by id (pros/admins can read any)
// GET one record by id (pros/admins can read any)
// helper to pull an id out of {_id} / {id} / string
function xId(val) {
  if (!val) return null;
  if (typeof val === 'string') return val;
  if (val._id) return String(val._id);
  if (val.id)  return String(val.id);
  return null;
}

async function canReadAppointment(session, apptRec) {
  const uid   = String(session.userId || '');
  const roles = session.roles || [];
  if (!uid) return false;
  if (String(apptRec.createdBy) === uid) return true;
  if (roles.includes('admin')) return true;

  // Pro on the appointment
  const proId = xId(
    apptRec.values?.Pro ||
    apptRec.values?.['Pro Ref'] ||
    apptRec.values?.Staff ||
    apptRec.values?.['Staff Ref']
  );
  if (proId && proId === uid) return true;

  // Pro via the Calendar
  const calId = xId(apptRec.values?.Calendar);
  if (calId) {
    const calDT = await DataType.findOne({ name: /Calendar/i, deletedAt: null }).lean();
    if (calDT) {
      const cal = await Record.findOne({ _id: calId, dataTypeId: calDT._id, deletedAt: null }).lean();
      const calProId = xId(
        cal?.values?.Pro ||
        cal?.values?.['Pro Ref'] ||
        cal?.values?.Staff ||
        cal?.values?.['Staff Ref']
      );
      if (calProId && calProId === uid) return true;
    }
  }

  // Business owner
  const bizId = xId(apptRec.values?.Business);
  if (bizId) {
    const bizDT = await DataType.findOne({ name: /Business/i, deletedAt: null }).lean();
    if (bizDT) {
      const biz = await Record.findOne({ _id: bizId, dataTypeId: bizDT._id, deletedAt: null }).lean();
      if (biz && String(biz.createdBy) === uid) return true;
    }
  }
  return false;
}


async function propagateProfileToCRM({ userId, firstName, lastName, email, phone }, prevEmail = '') {
  try {
    const clientDT = await DataType.findOne({ name: /Client/i, deletedAt: null }).lean();
    const apptDT   = await DataType.findOne({ name: /Appointment/i, deletedAt: null }).lean();
    const userDT   = await DataType.findOne({ name: /User/i,    deletedAt: null }).lean();
    if (!clientDT) return { clients: 0, appts: 0 };

    const norm = s => (s || '').trim();
    const em   = norm(email).toLowerCase();
    const pem  = norm(prevEmail).toLowerCase();

    // 🔎 Resolve the "User" DataType record(s) by email (not AuthUser _id)
    let userRecIds = [];
    if (userDT && (em || pem)) {
      const userRecs = await Record.find({
        dataTypeId: userDT._id,
        deletedAt: null,
        'values.Email': { $in: [em, pem].filter(Boolean) }
      }, { _id: 1 }).lean();
      userRecIds = userRecs.map(r => r._id);
    }

    // 1) Find Client records via Linked User (User record id) OR Email (old/new)
    const clientMatch = {
      dataTypeId: clientDT._id,
      deletedAt: null,
      $or: [
        // Linked User references a User record (all shapes)
        ...(userRecIds.length ? [
          { 'values.Linked User':      { $in: userRecIds } },
          { 'values.Linked User._id':  { $in: userRecIds.map(String) } },
          { 'values.Linked User':      { $in: userRecIds.map(String) } },
        ] : []),
        // Email match (old/new)
        ...(em  ? [{ 'values.Email': em  }] : []),
        ...(pem ? [{ 'values.Email': pem }] : []),
      ]
    };

    const clients = await Record.find(clientMatch).lean();
    if (!clients.length) return { clients: 0, appts: 0 };

    const clientIds = clients.map(c => c._id);

    // 2) Update Clients if different
    for (const c of clients) {
      const v = c.values || {};
      const setOps = {};
      if (firstName && norm(v['First Name'])   !== norm(firstName)) setOps['values.First Name']   = firstName;
      if (lastName  && norm(v['Last Name'])    !== norm(lastName))  setOps['values.Last Name']    = lastName;
      if (phone     && norm(v['Phone Number']) !== norm(phone))     setOps['values.Phone Number'] = phone;
      if (em        && norm(v['Email']).toLowerCase() !== em)       setOps['values.Email']        = em;

      const full = [firstName, lastName].filter(Boolean).join(' ').trim();
      if (full && norm(v['Client Name']) !== norm(full))            setOps['values.Client Name']  = full;

      if (Object.keys(setOps).length) {
        await Record.updateOne({ _id: c._id }, { $set: setOps });
      }
    }

    // 3) Update denormalized fields on Appointments that reference those clients
    if (!apptDT) return { clients: clients.length, appts: 0 };

    const setAppt = {
      ...(firstName ? { 'values.Client First Name': firstName } : {}),
      ...(lastName  ? { 'values.Client Last Name':  lastName  } : {}),
      ...(em        ? { 'values.Client Email':      em        } : {}),
    };
    const full = [firstName, lastName].filter(Boolean).join(' ').trim();
    if (full) setAppt['values.Client Name'] = full;

    if (Object.keys(setAppt).length) {
      const r = await Record.updateMany(
        {
          dataTypeId: apptDT._id,
          deletedAt: null,
          $or: [
            { 'values.Client':       { $in: clientIds } },                 // ObjectId stored directly
            { 'values.Client._id':   { $in: clientIds.map(String) } },     // {_id:"..."}
            { 'values.Client':       { $in: clientIds.map(String) } },     // plain string id
          ]
        },
        { $set: setAppt }
      );
      return { clients: clients.length, appts: r.modifiedCount || r.nModified || 0 };
    }

    return { clients: clients.length, appts: 0 };
  } catch (e) {
    console.error('[propagateProfileToCRM] error:', e);
    return { clients: 0, appts: 0 };
  }
}






  


//send email confirmation to clients after booking an appointment
// POST /api/appointments/:id/send-confirmation  (Resend)
app.post('/api/appointments/:id/send-confirmation', async (req, res) => {
  try {
    const id = String(req.params.id || '');
    if (!id) return res.status(400).json({ message: 'Missing id' });

    const appt = await Record.findById(id).lean();
    if (!appt) return res.status(404).json({ message: 'Appointment not found' });
    const v = appt.values || {};

    // pull related labels
    const bizId  = objIdFromRef(v['Business']);
    const serv   = Array.isArray(v['Service(s)']) ? v['Service(s)'][0] : v['Service(s)'];
    const servId = objIdFromRef(serv);

    const clientEmail = (v['Client Email'] || v['Email'] || '').trim();
    const clientName  = (v['Client Name']
                      || [v['Client First Name'], v['Client Last Name']].filter(Boolean).join(' ').trim()
                      || '').trim();
    if (!clientEmail) return res.status(400).json({ message: 'No client email on record' });

    let businessName = '';
    let locationText = '';
    if (bizId) {
      const biz = await Record.findById(bizId).lean();
      const bv  = biz?.values || {};
      businessName = bv['Business Name'] || bv['Name'] || bv['businessName'] || '';
      locationText = bv['Address'] || bv['Location'] || '';
    }

    let serviceName = 'Appointment';
    if (servId) {
      const srec = await Record.findById(servId).lean();
      const sv   = srec?.values || {};
      serviceName = sv['Service Name'] || sv['Name'] || serviceName;
    }

    const date = v['Date'];        // "YYYY-MM-DD"
    const time = v['Time'];        // "HH:MM" 24h
    const dur  = Number(v['Duration'] ?? 60) || 60;

    const subject = `Your ${serviceName} on ${prettyDate(date)} at ${to12h(time)}`;
    const manageUrl = `${process.env.PUBLIC_BASE_URL || ''}/manage/${appt._id}`; // adjust if you have a real page

    const html = `
      <div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;line-height:1.45">
        <p>Hi ${clientName || 'there'},</p>
        <p>Thanks for booking <strong>${serviceName}</strong> with <strong>${businessName}</strong>.</p>
        <p><strong>When:</strong> ${prettyDate(date)} at ${to12h(time)} (${dur} min)<br/>
           ${locationText ? `<strong>Where:</strong> ${locationText}<br/>` : ''}
           <a href="${manageUrl}">Manage your appointment</a>
        </p>
        <p>We attached a calendar invite so you can add this to your calendar.</p>
        <p>See you soon!</p>
      </div>
    `;

    let icsBuffer = null;
    try {
      icsBuffer = await makeIcsBuffer({
        title: `${serviceName} — ${businessName}`,
        description: v['Note'] || '',
        location: locationText,
        startISO: new Date(`${date}T${time}:00`),
        durationMin: dur,
        organizerName: businessName,
        organizerEmail: (process.env.MAIL_FROM || '').match(/<([^>]+)>/)?.[1] || process.env.MAIL_FROM
      });
    } catch (e) {
      console.warn('ICS generation failed:', e);
    }

    await sendBookingEmailWithResend({
      to: clientEmail,
      subject,
      html,
      icsBuffer,
      // cc: ['pro@yourdomain.com'],       // optional
      // replyTo: 'replies@yourdomain.com' // optional
    });

    res.json({ ok: true });
  } catch (e) {
    console.error('send-confirmation (Resend) failed:', e);
    res.status(500).json({ message: 'Email failed' });
  }
});


app.post('/api/appointments/book', async (req, res) => {
  try {
    const values = req.body?.values || {};
    if (!values['Business'] || !values['Calendar'] || !values['Date'] || !values['Time']) {
      return res.status(400).json({ message: 'Missing required fields' });
    }

    // keep your enrichment
    await enrichAppointment(values);

    const apptDT = await getDataTypeByNameLoose('Appointment');
    const rec = await Record.create({
      dataTypeId: apptDT?._id,
      values,
      createdBy: req.session.userId || null
    });

    // reuse the sender above:
    req.params.id = String(rec._id);
    await (async () => {
      // call the same logic inline instead of HTTP hopping
      const fakeReq = { params:{ id: req.params.id } };
      const fakeRes = { json:()=>{}, status:()=>({ json:()=>{} }) };
      // Easiest: directly call the function body from the other route,
      // or extract that logic into a helper and call it here.
    })();

    res.status(201).json(rec);
  } catch (e) {
    console.error('book route failed:', e);
    res.status(500).json({ message: 'Booking failed' });
  }
});




////////////////////////////////////////////////////
                         ///Stipe
                         function ymdToUnixEndOfDay(ymd) {
  // ymd = "YYYY-MM-DD"
  // Force 23:59:59 UTC to avoid timezone “past” issues
  const dt = new Date(`${ymd}T23:59:59.000Z`);
  return Math.floor(dt.getTime() / 1000);
}

app.post("/api/connect/create", ensureAuthenticated, async (req, res) => {
  try {
    const me = String(req.session.userId || "");
    if (!me) return res.status(401).json({ error: "Unauthorized" });

    const user = await AuthUser.findById(me);
    if (!user) return res.status(404).json({ error: "user_not_found" });

    // reuse if exists
    if (user.stripeAccountId) {
      return res.json({ accountId: user.stripeAccountId, reused: true });
    }

    const account = await stripe.accounts.create({
      type: "express",
      email: user.email || undefined,
      capabilities: {
        card_payments: { requested: true },
        transfers: { requested: true },
      },
    });

    user.stripeAccountId = account.id;
    user.stripeAccountType = "express";
    user.stripeOnboarded = false;
    await user.save();

    return res.json({ accountId: account.id, reused: false });
  } catch (e) {
    console.error("connect/create failed", e?.raw || e);
    return res.status(500).json({
      error: "connect_create_failed",
      message: e?.raw?.message || e?.message || "unknown_error",
      type: e?.raw?.type || e?.type || "",
      code: e?.raw?.code || e?.code || "",
    });
  }
});


   
app.post("/api/rent/create-payment-intent", ensureAuthenticated, async (req, res) => {
  try {
    const payerId = String(req.session.userId || "");
    if (!payerId) return res.status(401).json({ error: "Unauthorized" });

    const { ownerUserId, amountCents, currency = "usd", rentId } = req.body || {};

    if (!ownerUserId || !Number.isInteger(amountCents) || amountCents < 50) {
      return res.status(400).json({ error: "missing_or_invalid_fields" });
    }

    // get owner's connected stripe account
    const owner = await AuthUser.findById(String(ownerUserId)).lean();
    const destination = owner?.stripeAccountId;
    if (!destination) {
      return res.status(400).json({ error: "owner_not_connected" });
    }

    // OPTIONAL: ensure owner completed onboarding (recommended)
    // const acct = await stripe.accounts.retrieve(destination);
    // if (!acct.charges_enabled) return res.status(400).json({ error: "owner_not_ready" });

    // your fee (example: 3% + 30¢) — change this to what you want
    const fee = Math.max(30, Math.round(amountCents * 0.03));

    const intent = await stripe.paymentIntents.create({
      amount: amountCents,
      currency,
      automatic_payment_methods: { enabled: true },

      // ✅ Route money to owner + take platform fee
      application_fee_amount: fee,
      transfer_data: { destination },

      metadata: {
        kind: "suite_rent",
        rentId: rentId ? String(rentId) : "",
        ownerUserId: String(ownerUserId),
        payerUserId: payerId,
      },
    });

    // Return clientSecret to the frontend
    return res.json({
      clientSecret: intent.client_secret,
      paymentIntentId: intent.id,
      fee,
    });
  } catch (e) {
    console.error("rent/create-payment-intent failed", e);
    return res.status(500).json({ error: "rent_pi_failed" });
  }
});
  

//Checkout items 
app.get("/api/public/checkout/:checkoutId", async (req, res) => {
  try {
    const checkoutId = String(req.params.checkoutId || "");
    if (!checkoutId) return res.status(400).json({ error: "missing_checkoutId" });

    const checkoutDT = await DataType.findOne({ name: /Checkout/i, deletedAt: null }).lean();
    const itemDT     = await DataType.findOne({ name: /Checkout Item/i, deletedAt: null }).lean();
    if (!checkoutDT || !itemDT) return res.status(400).json({ error: "missing_datatypes" });

    const checkout = await Record.findOne({
      _id: checkoutId,
      dataTypeId: checkoutDT._id,
      deletedAt: null,
    }).lean();

    if (!checkout) return res.status(404).json({ error: "checkout_not_found" });

    const rows = await Record.find({
      dataTypeId: itemDT._id,
      deletedAt: null,
      "values.Checkout": checkoutId,
    }).lean();

    // 👇 user preference for list endpoints
    return res.json({ items: rows, checkout });
  } catch (e) {
    console.error("[public checkout get] error", e);
    return res.status(500).json({ error: "checkout_load_failed" });
  }
});
 
app.post("/api/public/checkout/:checkoutId/create-payment-intent", async (req, res) => {
  try {
    const checkoutId = String(req.params.checkoutId || "");
    if (!checkoutId) return res.status(400).json({ error: "missing_checkoutId" });

    const checkoutDT = await DataType.findOne({ name: /Checkout/i, deletedAt: null }).lean();
    const itemDT     = await DataType.findOne({ name: /Checkout Item/i, deletedAt: null }).lean();
    if (!checkoutDT || !itemDT) return res.status(400).json({ error: "missing_datatypes" });

    const checkout = await Record.findOne({
      _id: checkoutId,
      dataTypeId: checkoutDT._id,
      deletedAt: null,
    }).lean();
    if (!checkout) return res.status(404).json({ error: "checkout_not_found" });

    const items = await Record.find({
      dataTypeId: itemDT._id,
      deletedAt: null,
      "values.Checkout": checkoutId,
    }).lean();

    if (!items.length) return res.status(400).json({ error: "checkout_empty" });

    // total in cents
    const totalCents = items.reduce((sum, r) => {
      const v = r.values || {};
      return sum + Number(v["Total Amount"] || 0);
    }, 0);

    if (!Number.isInteger(totalCents) || totalCents < 50) {
      return res.status(400).json({ error: "invalid_total" });
    }

    // Put a readable label in Stripe (shows in Stripe dashboard)
    const firstLabel = String(items[0].values?.Label || "Checkout");
    const description =
      items.length === 1 ? firstLabel : `${firstLabel} + ${items.length - 1} more`;

    const pi = await stripe.paymentIntents.create({
      amount: totalCents,
      currency: "usd",
      automatic_payment_methods: { enabled: true },
      description,
      metadata: {
        kind: "checkout",
        checkoutId,
        itemsCount: String(items.length),
      },
    });

    // (optional) store on checkout record
    await Record.updateOne(
      { _id: checkoutId },
      { $set: { "values.Stripe Payment Intent Id": pi.id } }
    );

    return res.json({
      clientSecret: pi.client_secret,
      paymentIntentId: pi.id,
      amount: totalCents,
    });
  } catch (e) {
    console.error("[checkout create PI] error", e);
    return res.status(500).json({ error: "pi_create_failed" });
  }
});
app.post("/api/checkout/:id/create-payment-intent", requireLogin, async (req, res) => {
  try {
    const customerId = String(req.session.userId);
    const checkoutId = String(req.params.id || "");
    if (!checkoutId) return res.status(400).json({ error: "missing_checkoutId" });

    const checkoutDT = await DataType.findOne({ nameCanonical: "checkout" }).lean();
    if (!checkoutDT) return res.status(400).json({ error: "missing_checkout_datatype" });

    const checkout = await Record.findOne({
      _id: checkoutId,
      dataTypeId: checkoutDT._id,
      deletedAt: null,
      "values.Customer": customerId,
      "values.status": { $in: ["open", "draft"] },
    }).lean();

    if (!checkout) return res.status(404).json({ error: "checkout_not_found" });

    const v = checkout.values || {};
    const totalCents = Number(v["Total Amount"] || 0);
    const feeCents   = Number(v["Platform Fee"] || 0);
    const currency   = (v["Currency"] || "usd").toLowerCase();
    const destination = String(v["Payee Stripe Account ID"] || "");

    if (!totalCents || totalCents < 50) return res.status(400).json({ error: "invalid_total" });
    if (!destination) return res.status(400).json({ error: "missing_payee_stripe" });

    const intent = await stripe.paymentIntents.create({
      amount: totalCents,
      currency,
      automatic_payment_methods: { enabled: true },

      // ✅ send money to payee, keep platform fee
      application_fee_amount: feeCents,
      transfer_data: { destination },

      metadata: {
        kind: "checkout",
        checkoutId,
        customerId,
      },
    });

    return res.json({
      clientSecret: intent.client_secret,
      paymentIntentId: intent.id,
    });
} catch (e) {
  const raw = e?.raw || e;
  console.error("[checkout/create-payment-intent] error:", raw);

  return res.status(raw?.statusCode || 500).json({
    error: "stripe_error",
    message: raw?.message || e?.message || "unknown_error",
    type: raw?.type || "",
    code: raw?.code || "",
    param: raw?.param || "",
    requestId: raw?.requestId || "",
    decline_code: raw?.decline_code || "",
  });
}

});

function toCents(n) {
  const x = Number(n || 0);
  return Math.round(x * 100);
}

function xId(val) {
  if (!val) return null;
  if (typeof val === "string") return val;
  if (val._id) return String(val._id);
  if (val.id) return String(val.id);
  return null;
}

app.get("/api/checkout/current", requireLogin, async (req, res) => {
  try {
    const customerId = String(req.session.userId);

    const checkoutDT = await DataType.findOne({ nameCanonical: "checkout" }).lean();
    const itemDT     = await DataType.findOne({ nameCanonical: "checkout item" }).lean();
    if (!checkoutDT || !itemDT) return res.status(400).json({ error: "missing_datatypes" });

    // find an open checkout for this customer
    let checkout = await Record.findOne({
      dataTypeId: checkoutDT._id,
      deletedAt: null,
      "values.Customer": customerId,
      "values.status": { $in: ["open", "draft", "", null] },
    }).sort({ _id: -1 }).lean();

    // if none, create one
    if (!checkout) {
      checkout = await Record.create({
        dataTypeId: checkoutDT._id,
        dataType: "Checkout",
        createdBy: customerId,
        values: {
          Customer: customerId,
          status: "open",
          Currency: "usd",
          Subtotal: 0,
          "Total Amount": 0,
          "Platform Fee": 0,
        }
      });
      checkout = checkout.toObject();
    }

    const items = await Record.find({
      dataTypeId: itemDT._id,
      deletedAt: null,
      "values.Checkout": String(checkout._id),
    }).sort({ _id: -1 }).lean();

    return res.json({ items: [{ checkout, items }] });
  } catch (e) {
    console.error("[checkout/current] error", e);
    return res.status(500).json({ error: "internal" });
  }
});

app.post("/api/checkout/items/add-course", requireLogin, async (req, res) => {
  try {
    const customerId = String(req.session.userId);
    const { courseId, quantity = 1 } = req.body || {};
    if (!courseId) return res.status(400).json({ error: "missing_courseId" });

    const checkoutDT = await DataType.findOne({ nameCanonical: "checkout" }).lean();
    const itemDT     = await DataType.findOne({ nameCanonical: "checkout item" }).lean();
    const courseDT   = await DataType.findOne({ nameCanonical: "course" }).lean();
    if (!checkoutDT || !itemDT || !courseDT) return res.status(400).json({ error: "missing_datatypes" });

    // Load the course record (to get title + price + createdBy/payee)
    const course = await Record.findOne({
      _id: courseId,
      dataTypeId: courseDT._id,
      deletedAt: null
    }).lean();

    if (!course) return res.status(404).json({ error: "course_not_found" });

    const cv = course.values || {};
    const title = cv["Course Title"] || cv["Title"] || "Course";
    const unitAmount = Number(cv["Price"] ?? 0); // dollars in your data
    const unitAmountCents = toCents(unitAmount);

    // Who gets paid for this course?
    const payeeUserId = String(course.createdBy || cv["Created By"] || "");
    if (!payeeUserId) return res.status(400).json({ error: "course_missing_payee" });

    const payee = await AuthUser.findById(payeeUserId).lean();
    const payeeStripeAccountId = String(payee?.stripeAccountId || "");
    if (!payeeStripeAccountId) {
      return res.status(400).json({ error: "payee_not_connected" });
    }

    // Find an OPEN checkout for this customer AND this payee (Rule A)
    let checkout = await Record.findOne({
      dataTypeId: checkoutDT._id,
      deletedAt: null,
      "values.Customer": customerId,
      "values.status": { $in: ["open", "draft", "", null] },
      "values.Payee": payeeUserId,
    }).sort({ _id: -1 }).lean();

    if (!checkout) {
      checkout = await Record.create({
        dataTypeId: checkoutDT._id,
        dataType: "Checkout",
        createdBy: customerId,
        values: {
          Customer: customerId,
          Payee: payeeUserId,
          "Payee Stripe Account ID": payeeStripeAccountId,
          status: "open",
          Currency: "usd",
          Subtotal: 0,
          "Total Amount": 0,
          "Platform Fee": 0,
        }
      });
      checkout = checkout.toObject();
    }

    const qty = Math.max(1, Number(quantity || 1));
    const totalAmountCents = unitAmountCents * qty;

    const item = await Record.create({
      dataTypeId: itemDT._id,
      dataType: "Checkout Item",
      createdBy: customerId,
      values: {
        "Course(s)": [courseId],         // you allowed multiple
        "Kind": "course",
        "Label": title,
        "Quantity": qty,
        "Unit Amount": unitAmountCents,  // ✅ store cents in DB
        "Total Amount": totalAmountCents,
        "Currency": "usd",
        "Reference Id": String(courseId),
        "Reference Type": "Course",
        "Checkout": String(checkout._id),
      }
    });

    // Recalc checkout totals from all its items
    const allItems = await Record.find({
      dataTypeId: itemDT._id,
      deletedAt: null,
      "values.Checkout": String(checkout._id),
    }, { values: 1 }).lean();

    const subtotalCents = allItems.reduce((sum, r) => sum + Number(r.values?.["Total Amount"] || 0), 0);

    // platform fee example: 5% (change later)
    const platformFeeCents = Math.round(subtotalCents * 0.05);
    const totalCents = subtotalCents + platformFeeCents;

    await Record.updateOne(
      { _id: checkout._id },
      {
        $set: {
          "values.Subtotal": subtotalCents,
          "values.Platform Fee": platformFeeCents,
          "values.Total Amount": totalCents,
        }
      }
    );

    return res.json({ item });
  } catch (e) {
    console.error("[checkout/items/add-course] error", e);
    return res.status(500).json({ error: "internal" });
  }
});

app.post("/api/connect/onboard", ensureAuthenticated, async (req, res) => {
  try {
    const me = String(req.session.userId || "");
    if (!me) return res.status(401).json({ ok:false, error: "Unauthorized" });

    const user = await AuthUser.findById(me).lean();
    if (!user) return res.status(404).json({ ok:false, error: "user_not_found" });

    const accountId = user.stripeAccountId || req.body?.accountId;
    if (!accountId) return res.status(400).json({ ok:false, error: "missing_accountId" });

    // ✅ IMPORTANT: make sure account matches your key mode
    // (If you're using LIVE key, the account MUST be a live account)
    const account = await stripe.accounts.retrieve(accountId);

    const link = await stripe.accountLinks.create({
      account: accountId,
      type: "account_onboarding",
      refresh_url: "https://www.suiteseat.io/suite-settings.html?stripe=refresh",
      return_url: "https://www.suiteseat.io/suite-settings.html?stripe=return",
    });

    return res.json({ ok:true, url: link.url, accountId });
  } catch (e) {
    // ✅ DO NOT swallow details
    console.error("[connect/onboard] failed:", e);

    return res.status(500).json({
      ok: false,
      error: "connect_onboard_failed",
      message: e?.raw?.message || e?.message || "unknown_error",
      type: e?.raw?.type || e?.type || "",
      code: e?.raw?.code || e?.code || "",
      statusCode: e?.statusCode || "",
    });
  }
});

app.delete("/api/checkout/items/:id", requireLogin, async (req, res) => {
  try {
    const customerId = String(req.session.userId || "");
    const itemId = String(req.params.id || "");
    if (!itemId) return res.status(400).json({ error: "missing_itemId" });

    const checkoutDT = await DataType.findOne({ nameCanonical: "checkout" }).lean();
    const itemDT     = await DataType.findOne({ nameCanonical: "checkout item" }).lean();
    if (!checkoutDT || !itemDT) return res.status(400).json({ error: "missing_datatypes" });

    // Find item owned by this customer
    const item = await Record.findOne({
      _id: itemId,
      dataTypeId: itemDT._id,
      deletedAt: null,
      createdBy: customerId,
    }).lean();

    if (!item) return res.status(404).json({ error: "item_not_found" });

    const checkoutId = String(item.values?.Checkout || "");
    if (!checkoutId) return res.status(400).json({ error: "item_missing_checkout" });

    // Soft delete
    await Record.updateOne({ _id: itemId }, { $set: { deletedAt: new Date() } });

    // Recalc totals from remaining items
    const remaining = await Record.find({
      dataTypeId: itemDT._id,
      deletedAt: null,
      "values.Checkout": checkoutId,
      createdBy: customerId,
    }).lean();

    const subtotalCents = remaining.reduce((sum, r) => sum + Number(r.values?.["Total Amount"] || 0), 0);
    const platformFeeCents = Math.round(subtotalCents * 0.05);
    const totalCents = subtotalCents + platformFeeCents;

    await Record.updateOne(
      { _id: checkoutId, dataTypeId: checkoutDT._id, deletedAt: null },
      {
        $set: {
          "values.Subtotal": subtotalCents,
          "values.Platform Fee": platformFeeCents,
          "values.Total Amount": totalCents,
        }
      }
    );

    return res.json({ items: remaining });
  } catch (e) {
    console.error("[checkout item delete] error", e);
    return res.status(500).json({ error: "internal" });
  }
});


app.get("/api/connect/status", ensureAuthenticated, async (req, res) => {
  try {
    const me = String(req.session?.userId || "");
    if (!me) return res.status(401).json({ ok: false, error: "Unauthorized" });

    const user = await AuthUser.findById(me).lean();
    if (!user) return res.status(404).json({ ok: false, error: "user_not_found" });

    const acctId =
      user.stripeAccountId ||
      user.stripeConnectAccountId ||
      user.values?.stripeAccountId ||
      "";

    // ✅ not connected is NOT an error
    if (!acctId) {
      return res.json({
        ok: true,
        connected: false,
        chargesEnabled: false,
        payoutsEnabled: false,
        detailsSubmitted: false,
      });
    }

    const acct = await stripe.accounts.retrieve(acctId);

    return res.json({
      ok: true,
      connected: true,
      chargesEnabled: !!acct.charges_enabled,
      payoutsEnabled: !!acct.payouts_enabled,
      detailsSubmitted: !!acct.details_submitted,
      accountId: acct.id,
    });
  } catch (e) {
    // ✅ show real Stripe error info so we can fix it
    console.error("[connect/status] failed:", e);

    return res.status(200).json({
      ok: false,
      connected: false,
      error: "connect_status_failed",
      message: e?.message || "unknown_error",
      type: e?.type || "",
      code: e?.code || "",
      rawType: e?.rawType || "",
    });
  }
});



const crypto = require("crypto");

function generatePublicToken() {
  return crypto.randomBytes(24).toString("hex"); // 48-char token
}


// IMPORTANT: make sure you have this somewhere near the top of server.js
// const { Resend } = require("resend");
// const resend = new Resend(process.env.RESEND_API_KEY);








app.get("/pay/invoice/:token", (req, res) => {
  return res.sendFile(path.join(__dirname, "public", "pay-invoice.html"));
});
function toCents(n) {
  const x = Number(n || 0);
  return Math.round(x * 100);
}

function normRef(ref) {
  if (!ref) return "";
  if (Array.isArray(ref)) ref = ref[0];
  if (typeof ref === "object") return String(ref._id || ref.id || "");
  return String(ref);
}

async function getOrCreateStripeCustomerId({ email, name, suitieRecordId }) {
  // You can store this on the Suitie Record later (recommended),
  // but for Step 1 we’ll do a simple create/find by email.
  if (!email) return "";

  // Try finding existing customer by email (Stripe doesn’t have perfect search, but this works for many cases)
  // Safer long-term: save customerId in your DB once created.
  const existing = await stripe.customers.search({
    query: `email:'${String(email).replace(/'/g, "\\'")}'`,
    limit: 1,
  });

  if (existing.data?.length) return existing.data[0].id;

  const created = await stripe.customers.create({
    email,
    name: name || undefined,
    metadata: { kind: "suitie", suitieRecordId: String(suitieRecordId || "") },
  });

  return created.id;
}
app.post("/api/rent/invoice/send", requireLogin, async (req, res) => {
  try {
    const senderUserId = String(req.session.userId || "");

    const {
      suitieId,
      amount,              // dollars (Number)
      dueDate,             // ISO string or empty (optional)
      dueDateYmd,          // "YYYY-MM-DD" (recommended)
      processingFee,       // dollars (Number)
      memo,                // optional
    } = req.body || {};

    if (!suitieId) return res.status(400).json({ error: "missing_suitieId" });
    if (!Number.isFinite(Number(amount)) || Number(amount) <= 0) {
      return res.status(400).json({ error: "invalid_amount" });
    }

    const amountCents = toCents(amount);
    const feeCents = toCents(processingFee || 0);

    // ----- Load Suitie (for email, suite reference) -----
    const suitie = await Record.findOne({ _id: suitieId, deletedAt: null }).lean();
    if (!suitie) return res.status(404).json({ error: "suitie_not_found" });

    const sv = suitie.values || {};
    const suitieEmail = String(sv.Email || sv["Email"] || "").trim();
    const suitieName =
      String(sv.Name || sv["Name"] || sv["Full Name"] || sv["Full name"] || "").trim();

    if (!suitieEmail) return res.status(400).json({ error: "suitie_missing_email" });

    // ----- Resolve Suite from Suitie -----
    const suiteId = normRef(sv.Suite || sv["Suite"]);
    if (!suiteId) return res.status(400).json({ error: "suitie_missing_suite_ref" });

    const suite = await Record.findOne({ _id: suiteId, deletedAt: null }).lean();
    if (!suite) return res.status(404).json({ error: "suite_not_found" });

    const suiteV = suite.values || {};

    // ----- Resolve Location from Suite (and Payee from Location) -----
    const locationId = normRef(suiteV.Location || suiteV["Location"]);
    let payeeUserId = "";

    if (locationId) {
      const location = await Record.findOne({ _id: locationId, deletedAt: null }).lean();
      const lv = location?.values || {};
      payeeUserId = normRef(lv.Payee || lv["Payee"]);
    }

    // fallback to suite ownerUserId if no Payee set
    if (!payeeUserId) payeeUserId = String(suiteV.ownerUserId || suiteV["ownerUserId"] || "");
    if (!payeeUserId) return res.status(400).json({ error: "missing_payee_user" });

    // ----- Get suite owner's connected account -----
    const payee = await AuthUser.findById(payeeUserId).lean();
    const destination = String(payee?.stripeAccountId || "");
    if (!destination) return res.status(400).json({ error: "owner_not_connected" });

    // Optional: require onboarding complete
    const acct = await stripe.accounts.retrieve(destination);
    if (!acct?.payouts_enabled) {
      return res.status(400).json({
        error: "owner_not_ready",
        message: "Owner must finish Stripe onboarding.",
      });
    }

    // ----- Create/Get Stripe Customer for Suitie -----
    const customerId = await getOrCreateStripeCustomerId({
      email: suitieEmail,
      name: suitieName,
      suitieRecordId: suitieId,
    });
    if (!customerId) return res.status(400).json({ error: "customer_create_failed" });

    // ✅ Ensure Stripe customer definitely has email (so Stripe can email invoices)
    await stripe.customers.update(customerId, {
      email: suitieEmail,
      name: suitieName || undefined,
    });

    // ----- Decide Due Date (Stripe + Record) -----
    let dueDateUnix = null;

    if (dueDateYmd) {
      dueDateUnix = ymdToUnixEndOfDay(String(dueDateYmd));
      const nowUnix = Math.floor(Date.now() / 1000);
      if (dueDateUnix <= nowUnix) dueDateUnix = nowUnix + 86400; // bump 24h safety
    } else if (dueDate) {
      const unix = Math.floor(new Date(dueDate).getTime() / 1000);
      const nowUnix = Math.floor(Date.now() / 1000);
      dueDateUnix = unix > nowUnix ? unix : nowUnix + 86400;
    }

    // ✅ Save this date on your Record (ISO) for your app UI
    const dueDateForRecord = dueDateYmd
      ? new Date(`${dueDateYmd}T00:00:00.000Z`).toISOString()
      : (dueDate ? new Date(dueDate).toISOString() : null);

    // ----- Create your internal Invoice record FIRST -----
    const publicToken = require("crypto").randomBytes(24).toString("hex");
    const baseUrl = process.env.APP_BASE_URL || "https://app.suiteseat.io";
    const publicUrl = `${baseUrl}/pay/invoice/${publicToken}`;

    const invoiceDataTypeId = await getDataTypeIdByName("Invoice");
    if (!invoiceDataTypeId) {
      return res.status(400).json({
        error: "missing_invoice_datatype",
        message: "Invoice data type not found. Create a DataType named 'Invoice' first.",
      });
    }

    const invoiceRecord = await Record.create({
      dataType: "Invoice",
      dataTypeId: invoiceDataTypeId,
      createdBy: senderUserId,
      values: {
        Sender: senderUserId,
        Suitie: suitieId,
        Amount: Number(amount),
        "Due Date": dueDateForRecord ? new Date(dueDateForRecord) : null,
        "Sent To Email": suitieEmail,
        Status: "draft",
        "Public Token": publicToken,
        "Public Url": publicUrl,
      },
    });

    // ----- Create invoice items (visible lines) -----
    await stripe.invoiceItems.create({
      customer: customerId,
      currency: "usd",
      amount: amountCents,
      description: "Suite Rent",
      metadata: {
        kind: "suite_rent",
        invoiceRecordId: String(invoiceRecord._id),
        suitieId: String(suitieId),
        suiteId: String(suiteId),
        locationId: String(locationId || ""),
        payeeUserId: String(payeeUserId),
      },
    });

    if (feeCents > 0) {
      await stripe.invoiceItems.create({
        customer: customerId,
        currency: "usd",
        amount: feeCents,
        description: "Processing Fee",
        metadata: {
          kind: "suite_rent_fee",
          invoiceRecordId: String(invoiceRecord._id),
        },
      });
    }

    // ----- Create Stripe invoice -----
// 1) Create the Stripe invoice FIRST (draft)
const stripeInvoice = await stripe.invoices.create({
  customer: customerId,
  collection_method: "send_invoice",
  ...(dueDateUnix ? { due_date: dueDateUnix } : { days_until_due: 3 }),
  auto_advance: false, // we'll finalize manually
  transfer_data: { destination },
  application_fee_amount: feeCents,
  on_behalf_of: destination,
  metadata: {
    kind: "suite_rent_invoice",
    invoiceRecordId: String(invoiceRecord._id),
    suitieId: String(suitieId),
    payeeUserId: String(payeeUserId),
  },
  description: memo ? String(memo).slice(0, 500) : undefined,
});

// 2) Add invoice items directly to THIS invoice
await stripe.invoiceItems.create({
  customer: customerId,
  invoice: stripeInvoice.id,
  currency: "usd",
  amount: amountCents,
  description: "Suite Rent",
  metadata: { invoiceRecordId: String(invoiceRecord._id) },
});

if (feeCents > 0) {
  await stripe.invoiceItems.create({
    customer: customerId,
    invoice: stripeInvoice.id,
    currency: "usd",
    amount: feeCents,
    description: "Processing Fee",
    metadata: { invoiceRecordId: String(invoiceRecord._id) },
  });
}

// 3) Finalize + Send
const finalized = await stripe.invoices.finalizeInvoice(stripeInvoice.id);
const sent = await stripe.invoices.sendInvoice(finalized.id);

    console.log("[invoice] sendInvoice result:", {
      id: sent.id,
      status: sent.status,
      hosted_invoice_url: sent.hosted_invoice_url,
      customer_email: sent.customer_email,
    });

    // Save Stripe info on your internal record
    await Record.findByIdAndUpdate(invoiceRecord._id, {
      $set: {
        "values.Status": "sent",
        "values.stripeInvoiceId": sent.id,
        "values.stripeHostedInvoiceUrl": sent.hosted_invoice_url || "",
        "values.stripeInvoicePdf": sent.invoice_pdf || "",
        "values.Stripe Customer Email": sent.customer_email || "",
      },
    });

    const updated = await Record.findById(invoiceRecord._id).lean();

    // ✅ Return extra fields so frontend can open the invoice immediately
    return res.json({
      items: [updated],
      hostedInvoiceUrl: sent.hosted_invoice_url || "",
      stripeInvoiceId: sent.id,
      stripeCustomerEmail: sent.customer_email || "",
    });
  } catch (err) {
    const raw = err?.raw || null;
    console.error("[rent/invoice/send] error:", raw || err);

    return res.status(raw?.statusCode || 500).json({
      error: "invoice_send_failed",
      message: raw?.message || err?.message || "unknown_error",
      type: raw?.type || "",
      code: raw?.code || "",
      param: raw?.param || "",
      requestId: raw?.requestId || "",
      decline_code: raw?.decline_code || "",
    });
  }
});
















 
app.get("/api/public/invoice/:token", async (req, res) => {
  try {
    const token = String(req.params.token || "");

    const invoice = await Record.findOne({
      deletedAt: null,
      dataType: "Invoice",
      "values.Public Token": token,
    }).lean();

    if (!invoice) return res.status(404).json({ message: "Invoice not found" });

    return res.json({ item: invoice });
  } catch (e) {
    console.error("[public invoice] error", e);
    return res.status(500).json({ message: "Failed to load invoice" });
  }
});

app.post("/api/stripe/connect/start", requireLogin, async (req, res) => {
  try {
    const userId = req.session.userId;

    // 1) load user (however you do it)
  const user = await AuthUser.findById(userId);

    if (!user) return res.status(404).json({ ok: false, message: "User not found" });

    // 2) create Stripe account if missing
    let acctId = user.stripeAccountId;
    if (!acctId) {
      const account = await stripe.accounts.create({
        type: "express",
        // email helps Stripe prefill
        email: user.email || undefined,
        capabilities: {
          card_payments: { requested: true },
          transfers: { requested: true },
        },
      });

      acctId = account.id;
      user.stripeAccountId = acctId;
      await user.save();
    }

    // 3) create onboarding link
    const accountLink = await stripe.accountLinks.create({
      account: acctId,
      refresh_url: `${APP_URL}/suite-settings.html?tab=settings&stripe=refresh`,
      return_url: `${APP_URL}/suite-settings.html?tab=settings&stripe=return`,
      type: "account_onboarding",
    });

    return res.json({ ok: true, url: accountLink.url });
  } catch (err) {
    console.error("[stripe connect start]", err);
    return res.status(500).json({ ok: false, message: "Stripe connect start failed" });
  }
});

app.get("/api/stripe/connect/status", requireLogin, async (req, res) => {
  try {
    const userId = req.session.userId;
  const user = await AuthUser.findById(userId);

    if (!user) return res.status(404).json({ ok: false, message: "User not found" });

    if (!user.stripeAccountId) {
      return res.json({
        ok: true,
        connected: false,
        chargesEnabled: false,
        payoutsEnabled: false,
        detailsSubmitted: false,
      });
    }

    const acct = await stripe.accounts.retrieve(user.stripeAccountId);

    // store latest
    user.stripeChargesEnabled = !!acct.charges_enabled;
    user.stripePayoutsEnabled = !!acct.payouts_enabled;
    user.stripeDetailsSubmitted = !!acct.details_submitted;
    await user.save();

    return res.json({
      ok: true,
      connected: true,
      chargesEnabled: !!acct.charges_enabled,
      payoutsEnabled: !!acct.payouts_enabled,
      detailsSubmitted: !!acct.details_submitted,
    });
  } catch (err) {
    console.error("[stripe connect status]", err);
    return res.status(500).json({ ok: false, message: "Stripe connect status failed" });
  }
});

//Charge rent as a direct charge on the connected account
async function chargeRent(req, res) {
  const { stripeAccountId, amountCents, currency = "usd" } = req.body;

  const paymentIntent = await stripe.paymentIntents.create(
    {
      amount: amountCents,
      currency,
      // optional: platform fee (only if you charge one)
      // application_fee_amount: 233, // example fee in cents
      automatic_payment_methods: { enabled: true },
    },
    {
      // THIS is what makes it a direct charge on the suite owner's account
      stripeAccount: stripeAccountId,
    }
  );

  res.json({ clientSecret: paymentIntent.client_secret });
}


//////////////////////////////////////////////////////////////////////////////////////////////////
                                    //Email Automation
async function runEmailAutomations({ eventKey, record, actorUserId }) {
  try {
    console.log("[email] runEmailAutomations eventKey:", eventKey);

    const emailDt = await getDataTypeByNameLoose("EmailAutomation");
    console.log("[email] emailDt:", emailDt?._id, emailDt?.name);
    if (!emailDt?._id) return;

    const allAutomations = await Record.find({
      dataTypeId: emailDt._id,
      deletedAt: null,
    }).lean();

    console.log(
      "[email] all automations raw:",
      allAutomations.map(a => ({
        _id: String(a._id),
        values: a.values
      }))
    );

    const automations = allAutomations.filter((a) => {
      const v = a.values || {};

      const enabled =
        v.Enabled === true ||
        String(v.Enabled).toLowerCase() === "true" ||
        String(v.Enabled).toLowerCase() === "yes";

      const triggerRaw =
        v.Trigger?._id ||
        v.Trigger?.value ||
        v.Trigger?.label ||
        v.Trigger ||
        "";

      const trigger = String(triggerRaw).trim();

      return enabled && trigger === eventKey;
    });

    console.log("[email] matching automations:", automations.length);

    if (!automations.length) return;

    for (const a of automations) {
      try {
        const delayMin = Number(a.values?.SendDelayMinutes || 0);
        console.log("[email] automation found:", a._id, a.values);

        const ctx = await buildEmailContext({
          eventKey,
          record,
          actorUserId,
          audience: String(a.values?.Audience || "").toLowerCase(),
        });

        console.log("[email] ctx:", ctx);

        const toEmail = ctx?.recipient?.email;
        console.log("[email] recipient email:", toEmail);
        if (!toEmail) continue;

        const subjectTpl = String(
          a.values?.SubjectTemplate ||
          a.values?.["Subject Templae"] ||
          ""
        );

        const bodyTpl = String(a.values?.BodyHtmlTemplate || "");

        const subject = renderTemplate(subjectTpl, ctx);
        const html = renderTemplate(bodyTpl, ctx);

        console.log("[email] rendered subject:", subject);
        console.log("[email] rendered html:", html);

        if (delayMin > 0) {
          console.log("[email automation] delay requested:", delayMin);
        }

        await sendEmailResend({
          to: toEmail,
          subject,
          html,
          replyTo: a.values?.ReplyToEmail || null,
        });

        console.log("[email] sent ok");
      } catch (err) {
        console.error("[email automation] one automation failed1:", err);
      }
    }
  } catch (err) {
    console.error("[runEmailAutomations] failed:", err);
  }
}
function formatDatePretty(dateStr) {
  if (!dateStr) return "";
  const d = new Date(`${String(dateStr).slice(0, 10)}T00:00:00`);
  if (Number.isNaN(d.getTime())) return String(dateStr);

  return d.toLocaleDateString("en-US", {
    month: "long",
    day: "numeric",
    year: "numeric",
  });
}

function formatTimePretty(timeStr) {
  if (!timeStr) return "";

  const s = String(timeStr).trim();
  const parts = s.split(":");
  if (parts.length < 2) return s;

  let hour = Number(parts[0]);
  const minute = Number(parts[1]);

  if (!Number.isFinite(hour) || !Number.isFinite(minute)) return s;

  const suffix = hour >= 12 ? "PM" : "AM";
  hour = hour % 12;
  if (hour === 0) hour = 12;

  return `${hour}:${String(minute).padStart(2, "0")} ${suffix}`;
}
async function fetchRecordValuesByIds(ids = []) {
  const cleanIds = (Array.isArray(ids) ? ids : [ids])
    .map(x => {
      if (!x) return null;
      if (typeof x === "string") return x;
      if (typeof x === "object") return x._id || x.id || null;
      return null;
    })
    .filter(Boolean)
    .filter(id => mongoose.isValidObjectId(String(id)));

  if (!cleanIds.length) return [];

  const rows = await Record.find({
    _id: { $in: cleanIds },
    deletedAt: null,
  }).lean();

  return rows;
}
async function buildEmailContext({ eventKey, record, actorUserId, audience }) {
  const rec = record?.toObject ? record.toObject() : record;
  const values = rec?.values || {};

  const typeId = String(rec?.dataTypeId || "");
  const dt = typeId ? await DataType.findById(typeId).lean() : null;
  const typeName = String(dt?.nameCanonical || "").toLowerCase();

  // generic context
  const ctx = {
    eventKey,
    actorUserId,
    record: values,
    recipient: null,
  };

  // Appointment-created example
if (typeName === "appointment") {
  const businessId =
    values?.Business?._id ||
    values?.businessId ||
    null;

  const clientUserId =
    values?.Client?._id ||
    values?.clientId ||
    null;

  const serviceRefs =
    values?.["Service(s)"] ||
    values?.Services ||
    values?.Service ||
    [];

  let business = null;
  if (businessId && mongoose.isValidObjectId(String(businessId))) {
    const businessRec = await Record.findById(businessId).lean();
    business = businessRec?.values || null;
  }

  let client = null;
  if (clientUserId && mongoose.isValidObjectId(String(clientUserId))) {
    client = await AuthUser.findById(clientUserId).lean();
  }

  // ✅ fetch service records
  const serviceRows = await fetchRecordValuesByIds(serviceRefs);

  const services = serviceRows.map(r => {
    const v = r.values || {};
    return {
      _id: String(r._id),
      name: v.Name || v.name || v["Service Name"] || v.serviceName || "",
      price: v.Price ?? v.price ?? "",
      duration:
        v.DurationMin ??
        v.durationMinutes ??
        v["Duration (min)"] ??
        v.Duration ??
        v.duration ??
        "",
      description: v.Description || v.description || "",
    };
  });

  ctx.appointment = values;
  ctx.business = business;
  ctx.client = client;
  ctx.services = services;
  ctx.serviceNames = services.map(s => s.name).filter(Boolean).join(", ");

  ctx.appointmentDatePretty = formatDatePretty(values?.Date);
  ctx.appointmentTimePretty = formatTimePretty(
    values?.StartTime || values?.Time
  );

  if (audience === "client" || audience === "clients") {
    ctx.recipient = client ? { email: client.email } : null;
  }

  return ctx;
}

  return ctx;
}

//Send Single Email 
app.post("/api/email/send", ensureAuthenticated, async (req, res) => {
  try {
    const { to, subject, html, replyTo } = req.body || {};

    if (!to) return res.status(400).json({ error: "to is required" });
    if (!subject) return res.status(400).json({ error: "subject is required" });
    if (!html) return res.status(400).json({ error: "html is required" });

    console.log("[/api/email/send] payload:", { to, subject, replyTo, htmlLength: html.length });

    const out = await sendEmailResend({
      to,
      subject,
      html,
      replyTo: replyTo || null,
    });

    return res.json({ ok: true, out });
  } catch (e) {
    console.error("POST /api/email/send failed:", e);
    return res.status(500).json({
      error: "Failed to send email",
      detail: e.message,
    });
  }
});

async function sendEmailResend({ to, subject, html, replyTo = null }) {
  if (!process.env.RESEND_API_KEY) {
    throw new Error("RESEND_API_KEY is missing");
  }

  const payload = {
    from: "SuiteSeat <info@suiteseat.io>", // use a verified sender/domain
    to: Array.isArray(to) ? to : [to],
    subject,
    html,
  };

  if (replyTo) {
    payload.reply_to = replyTo;
  }

  const result = await resend.emails.send(payload);
  console.log("[resend] send result:", result);
  return result;
}
// super simple template renderer: {{client.firstName}}
function renderTemplate(template, ctx) {
  return String(template || "").replace(/\{\{\s*([a-zA-Z0-9_.]+)\s*\}\}/g, (_, path) => {
    const val = path.split(".").reduce((acc, key) => (acc ? acc[key] : undefined), ctx);
    return val == null ? "" : String(val);
  });
}
///////////////////////////////////////////////////////////////////////////////////////////////////
//                                 //Page Routes

//Index page 
   app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

//Admin
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html')); 
});

// --- Signup PAGE (serves the HTML file) ---
app.get('/signup', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signup.html'));
}); // ← this closing brace+paren+semicolon fixes the accidental wrapping


// Pretty URLs protected by auth
app.get('/appointment-settings', ensureAuthenticated, (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'appointment-settings.html'));
});

app.get('/appqointment-settings', ensureAuthenticated, (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'appqointment-settings.html'));
});

// (Optional) keep old links working
app.get(['/appointment-settings', '/appointment-settings.html'], (req, res) => {
  res.redirect('/appointment-settings');
});

// Availability Page
app.get('/availability', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'availability.html'));
});

//calendar page 
app.get('/calendar', ensureAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'calendar.html'));
});



//clients page 
app.get('/clients', ensureAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'clients.html'));
});

//menu page 
app.get('/menu', ensureAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'menu.html'));
});

//booking-page page 
app.get('/booking-page', ensureAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'booking-page.html'));
});
////////////////////////////////////
//calendar page 
app.get('/custom-booking', ensureAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'custom-booking.html'));
});


//////////////////////////////////

//Client-board page 
app.get('/client-dashboard', ensureAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'client-dashboard.html'));
});


// Health
app.get('/api/health', (req, res) => res.json({ ok: true }));

app.use('/api', holdsRouter); 

app.use((err, _req, res, _next) => {
  console.error("🔥 UNHANDLED ERROR:", err);
  res.status(500).json({ error: "internal_error", message: err.message });
});


// ---------- sockets / server listen ----------
const http = require('http');
const { Server } = require('socket.io');
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: true, credentials: true } });

io.on('connection', (socket) => {
  console.log('🔌 socket connected', socket.id);
  socket.on('disconnect', () => console.log('🔌 socket disconnected', socket.id));
});

// ✅ DB connect then start server (single place)
connectDB()
  .then(() => {
    const PORT = process.env.PORT || 8400;
    server.listen(PORT, () => console.log(`✅ API listening on http://localhost:${PORT}`));
  })
  .catch(err => {
    console.error('❌ DB connect failed', err);
    process.exit(1);
  });