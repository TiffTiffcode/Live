// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose'); 

const fs = require('fs');
const multer = require('multer');

const { connectDB } = require('./utils/db');
const AuthUser    = require('./models/AuthUser');
const DataType = require('./models/DataType');
const Field = require('./models/Field');
const OptionSet   = require('./models/OptionSet');
const OptionValue = require('./models/OptionValue');
const Record      = require('./models/Record');
const { canon } = require('./utils/canon');

const bcrypt = require('bcryptjs');

const session = require('express-session');
const cookieParser = require('cookie-parser');
const MongoStore = require('connect-mongo');

const app = express();
// Mount uploads at /uploads
app.set('trust proxy', 1); // good for Render/proxies
app.use(express.json());
app.use(cookieParser());
app.use(express.static('public')); 
// Build allowlist from env + known subdomains
const allowFromEnv = (process.env.CORS_ORIGIN || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

const allowStatic = [
  'http://localhost:3000',
  'https://www.suiteseat.io',
  'https://app.suiteseat.io'
];

const ALLOWED_ORIGINS = Array.from(new Set([...allowStatic, ...allowFromEnv]));

const isProd = process.env.NODE_ENV === 'production';

// CORS (single instance)
app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);         // curl/Postman/SSR
    cb(null, ALLOWED_ORIGINS.includes(origin));
  },
  credentials: true
}));

// Session (single instance)
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    ttl: 60 * 60 * 24 * 30
  }),
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: isProd,
    domain: isProd ? '.suiteseat.io' : undefined,
    maxAge: 1000 * 60 * 60 * 24 * 30
  }
}));

// ✅ Health route AFTER CORS/session, BEFORE other routes
app.get('/api/health', (_req, res) => res.json({ ok: true, t: Date.now() }));

const path = require('path');
const servePublic = (name) => (req, res) =>
  res.sendFile(path.join(__dirname, 'public', `${name}.html`));
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));

// Serve CSS and JS from /assets
app.use('/qassets', express.static(path.join(__dirname, 'qassets')));

// at the top with other requires
const http = require('http');
const { Server } = require('socket.io');

// after `const app = express();`
const server = http.createServer(app);

const io = new Server(server, {
  cors: { origin: true, credentials: true }
});

io.on('connection', (socket) => {
  console.log('🔌 socket connected', socket.id);
  socket.on('disconnect', () => console.log('🔌 socket disconnected', socket.id));
});

// simple liveness endpoint
app.get('/health', (_req, res) => {
  res.json({ ok: true, t: Date.now() });
});

// at top of server
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const { v4: uuid } = require('uuid');

const s3 = new S3Client({ region: process.env.AWS_REGION });



// --- Helpers (single copy only) ---
const PUBLIC_TYPES = new Set(["Business","Calendar","Category","Service","Upcoming Hours" ]);

const escapeRegex = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const toObjectIdIfHex = (v) =>
  (typeof v === "string" && /^[0-9a-fA-F]{24}$/.test(v))
    ? new mongoose.Types.ObjectId(v)
    : v;


connectDB().catch(err => {
  console.error('❌ DB connect failed', err);
  process.exit(1);
});


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

app.post('/api/uploads/presign', async (req, res) => {
  try {
    const { filename, contentType } = req.body || {};
    if (!filename || !contentType) return res.status(400).json({ error: 'filename, contentType required' });

    // create a unique key; you can prefix with userId if you want
    const ext = filename.split('.').pop();
    const key = `uploads/${uuid()}.${ext}`;

    const command = new PutObjectCommand({
      Bucket: process.env.S3_BUCKET_NAME,
      Key: key,
      ContentType: contentType,
      ACL: 'public-read', // or keep private and serve via CloudFront / signed URLs
    });

    const url = await getSignedUrl(s3, command, { expiresIn: 60 }); // 60 seconds
    const publicUrl =
      process.env.PUBLIC_BASE_URL
        ? `${process.env.PUBLIC_BASE_URL}/${key}`
        : `https://${process.env.S3_BUCKET_NAME}.s3.${process.env.AWS_REGION}.amazonaws.com/${key}`;

    res.json({ url, key, publicUrl });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'presign failed' });
  }
});





///////////////////////////////////
// --- Uploads (single source of truth) ---
const UPLOADS_DIR = path.join(__dirname, 'public', 'uploads');
fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// Serve uploaded files at /uploads/<filename>
app.use('/uploads', express.static(UPLOADS_DIR));


// Multer storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname || '');
    const name = `${Date.now()}-${Math.round(Math.random()*1e9)}${ext}`;
    cb(null, name);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
});
//////////////////////////////////


function objIdFromRef(ref) {
  if (!ref) return null;
  const id = (typeof ref === 'object') ? (ref._id || ref.id) : ref;
  try { return id ? new mongoose.Types.ObjectId(String(id)) : null; }
  catch { return null; }
}

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
app.post('/update-user-profile',
  ensureAuthenticated,
  upload.single('profilePhoto'),
  async (req, res) => {
    try {
      const userId = req.session.userId;

      // Grab previous values (for prevEmail match)
      const prev = await AuthUser.findById(userId).lean();

      const { firstName, lastName, phone, address, email } = req.body;
      const update = { firstName, lastName, phone, address, email };

      if (req.file) {
        update.profilePhoto = `/uploads/${req.file.filename}`;
      }

      const user = await AuthUser.findByIdAndUpdate(userId, update, { new: true, lean: true });
      if (!user) return res.status(404).json({ message: 'User not found' });

      // 🔁 Propagate to Client & Appointment records
      const stats = await propagateProfileToCRM(
        { userId, firstName: user.firstName, lastName: user.lastName, email: user.email, phone: user.phone },
        prev?.email
      );

      // Return shape expected by the front-end
      res.json({ user, propagated: stats });
    } catch (e) {
      console.error('POST /update-user-profile failed:', e);
      res.status(500).json({ message: 'Server error saving profile' });
    }
  }
);


app.get("/api/me", (req,res)=>{
  if (!req.session?.userId) return res.status(401).json({ loggedIn:false });
  res.json({ 
    id: req.session.userId, 
    ...req.session.user      // set this during /login
  });
}); 
function ensureAuthenticated(req, res, next) {
  if (req.session?.userId) return next();
  return res.status(401).json({ error: 'Not logged in' });
}

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
      const mineByRef = await normalizeWhereForType(dt._id, { [myRefField]: userId });
      ors.push(mineByRef);
    }

    const q = { dataTypeId: dt._id, deletedAt: null, ...where };
    if (ors.length) q.$or = ors;

    let mongoSort = { createdAt: -1 };
    if (sortStr) { try { mongoSort = await normalizeSortForType(dt._id, JSON.parse(sortStr)); } catch {} }

    const lim = Math.min(parseInt(limit, 10) || 100, 500);
    const skp = Math.max(parseInt(skip, 10) || 0, 0);
const rows = await Record.find(q)
  .sort(mongoSort).skip(skp).limit(lim)
  .populate({ path: 'createdBy', select: 'firstName lastName name' })  // <— add this
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
}); } catch (e) {
    console.error('GET /api/me/records failed:', e);
    res.status(500).json({ error: e.message });
  }
});


app.post('/signup', async (req, res) => {
  const { firstName, lastName, email, password, phone } = req.body || {};
  if (!email || !password) return res.status(400).json({ message: 'Email & password required' });

  const existing = await AuthUser.findOne({ email: String(email).toLowerCase().trim() });
  if (existing) return res.status(409).json({ message: 'Email already in use' });

  const passwordHash = await bcrypt.hash(password, 10);
  const user = await AuthUser.create({
    firstName, lastName, email, phone, passwordHash, roles: ['client']
  });

  req.session.userId = user._id;
  req.session.user = { email: user.email, name: user.name, roles: user.roles };

  res.json({
    ok: true,
    user: {  _id: String(user._id), firstName, lastName, email, phone }
  });
});

app.post('/signup/pro', async (req, res) => {
  try {
    const { firstName, lastName, email, password, phone } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ message: 'Missing email/password' });
    }

    const existing = await AuthUser.findOne({ email: email.toLowerCase() });
    if (existing) {
      return res.status(409).json({ message: 'Email already in use' });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const user = await AuthUser.create({
      firstName,
      lastName,
      email: email.toLowerCase(),
      phone,
      passwordHash,
      roles: ['pro']
    });

    req.session.userId = String(user._id);
    req.session.user = {
      _id: String(user._id),
      firstName,
      lastName,
      email: user.email,
      roles: user.roles
    };

    res.status(201).json({
      ok: true,
      user: req.session.user,
      redirect: '/settings'
    });
  } catch (e) {
    res.status(500).json({ message: e.message });
  }
});
app.post('/login', async (req, res) => {
  const { email, password } = req.body || {};
  const user = await AuthUser.findOne({ email: String(email).toLowerCase().trim() });
  if (!user) return res.status(401).json({ message: 'Invalid email or password' });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ message: 'Invalid email or password' });

  req.session.userId = String(user._id);
  req.session.roles  = Array.isArray(user.roles) ? user.roles : [];
  req.session.user   = {
    _id:       String(user._id),
    email:     user.email,
    firstName: user.firstName || '',
    lastName:  user.lastName  || ''
  };

  res.json({
    ok: true,
    user: {
      _id: user._id,
      firstName: user.firstName || '',
      lastName:  user.lastName  || '',
      email:     user.email,
      phone:     user.phone
    }
  });
});


app.get('/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});
app.get('/check-login', async (req, res) => {
  try {
    if (!req.session?.userId) return res.json({ loggedIn: false });

    const u = await AuthUser.findById(req.session.userId).lean();
    if (!u) return res.json({ loggedIn: false });

    let first = (u.firstName || u.first_name || '').trim();
    let last  = (u.lastName  || u.last_name  || '').trim();
    let name  = [first, last].filter(Boolean).join(' ').trim() || (u.name || '').trim();

    // Try to enrich from Records if missing
    if (!first || !name) {
      try {
        const profile = await Record.findOne({
          deletedAt: { $exists: false },
          dataType: { $in: ['User', 'Client', 'Profile'] },
          $or: [
            { 'values.userId': String(u._id) },
            { 'values.createdBy': u._id },     // many of your records use createdBy: auth._id
            { 'values.Email': u.email },
            { 'values.email': u.email }
          ]
        }).lean();

        const pv = profile?.values || {};
        const pfFirst = (pv['First Name'] || pv.firstName || pv.first_name || '').trim();
        const pfLast  = (pv['Last Name']  || pv.lastName  || pv.last_name  || '').trim();
        const pfName  = [pfFirst, pfLast].filter(Boolean).join(' ').trim();

        if (!first && pfFirst) first = pfFirst;
        if (!last  && pfLast)  last  = pfLast;
        if (!name  && pfName)  name  = pfName;
      } catch {}
    }

    if (!name && u.email) name = u.email.split('@')[0]; // last resort
    const safeFirst = (first || name || 'there').split(' ')[0];

   req.session.user = req.session.user || {};
    if (!req.session.user.firstName) req.session.user.firstName = first;
    if (!req.session.user.lastName)  req.session.user.lastName  = last;
    if (!req.session.user.email)     req.session.user.email     = u.email;

    res.json({
      loggedIn: true,
      userId:   String(u._id),
      email:    u.email || '',
      firstName:first || '',
      lastName: last  || '',
      name, // ← include full name, useful if you want it
      roles:   req.session.roles || []
    });
  } catch (e) {
    console.error('check-login error:', e);
    res.status(500).json({ loggedIn: false });
  }
});

// server.js (or routes/auth.js)

// Example login route that your front-end calls via API.login(email, pass)
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const auth = await AuthUser.findOne({ email: String(email).toLowerCase().trim() }).lean();
    if (!auth) return res.status(401).json({ message: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, auth.passwordHash);
    if (!ok) return res.status(401).json({ message: 'Invalid credentials' });

    // ⬇️ THIS is the bit you were asking about
req.session.userId = String(auth._id);
req.session.roles  = Array.isArray(auth.roles) ? auth.roles : [];
req.session.user   = { email: auth.email, firstName: auth.firstName || '', lastName: auth.lastName || '' };


    res.json({
      ok: true,
      userId: String(auth._id),
      email: auth.email,
      firstName: auth.firstName || '',
      lastName:  auth.lastName  || '',
      roles: req.session.roles
    });
  } catch (e) {
    console.error('/auth/login error', e);
    res.status(500).json({ message: 'Login failed' });
  }
});

/////////////////////////////////////////////////////////////////////
   
//Datatypes
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

//OptionSet

// ---------- Option Sets ----------
app.get('/api/optionsets', async (req, res) => {
  const sets = await OptionSet.find({ deletedAt: null }).sort({ createdAt: 1 }).lean();
  res.json(sets);
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
  const { id } = req.params;
  if (!mongoose.isValidObjectId(id)) return res.json([]);
  const vals = await OptionValue.find({ optionSetId: id, deletedAt: null })
    .sort({ order: 1, createdAt: 1 })
    .lean();
  res.json(vals);
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
  'admin','signup','login','logout',
  'appointment-settings','appqointment-settings',
  'favicon.ico','robots.txt','sitemap.xml'
]);


// Public list of records by type, with simple field filters (e.g. &Business=<id>)
// Public list of records by type...
app.get('/public/records', async (req, res) => {
  try {
    const { dataType, limit = '500', skip = '0', sort } = req.query;
    if (!dataType) return res.status(400).json({ error: 'dataType required' });

    const dt = await getDataTypeByNameLoose(dataType);
    if (!dt) return res.json([]);

    const where = { dataTypeId: dt._id, deletedAt: null };

    // Special-case _id
    if (req.query._id) {
      where._id = req.query._id;
    }

    // Treat any other param as values.<Field> filter
    for (const [k, v] of Object.entries(req.query)) {
      if (['dataType','limit','skip','sort','ts','_id'].includes(k)) continue;
      if (v !== undefined && v !== '') where[`values.${k}`] = v;
    }

    let order = { createdAt: -1 };
    if (sort) { try { order = JSON.parse(sort); } catch {} }

    const lim = Math.min(parseInt(limit, 10) || 100, 1000);
    const skp = Math.max(parseInt(skip, 10) || 0, 0);

    const rows = await Record.find(where).sort(order).skip(skp).limit(lim).lean();
    res.json(rows.map(r => ({ _id: String(r._id), values: r.values || {}, deletedAt: r.deletedAt || null })));
  } catch (e) {
    console.error('GET /public/records failed:', e);
    res.status(500).json({ error: e.message });
  }
});


// 1) JSON data for a business booking slug, e.g. /HairEverywhere.json
app.get('/:slug.json', async (req, res, next) => {
  const { slug } = req.params;
  if (!slug || slug.includes('.') || RESERVED.has(slug)) return next();

  try {
    const dt = await DataType.findOne({ name: /Business/i }).lean();
    if (!dt) return res.status(404).json({ message: 'Business type not found' });

    const re = new RegExp(`^${escapeRegex(slug)}$`, 'i');

    const biz = await Record.findOne({
      deletedAt: null,
      $and: [
        { $or: [{ dataTypeId: dt._id }, { dataType: 'Business' }] },
        { $or: [
       { 'values.slug': re },
{ 'values.businessSlug': re },
{ 'values.Slug': re },
{ 'values.bookingSlug': re },
{ 'values.Business Slug': re }, // with space/case
{ 'values.slug ': re },         // trailing space
{ 'values.Slug ': re },
        ]},
      ],
    }).lean();

    if (!biz) return res.status(404).json({ message: 'Business not found' });
    res.json({ _id: biz._id, values: biz.values || {} });
  } catch (e) {
    console.error('GET /:slug.json error:', e);
    res.status(500).json({ message: 'Server error' });
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
function ensureAuthenticated(req, res, next) {
  if (req.session?.userId) return next();
  res.status(401).json({ error: "Not authenticated" });
}
function ensureRole(role) {
  return (req, res, next) => {
    const roles = req.session?.roles || [];
    if (roles.includes(role)) return next();
    res.status(403).json({ error: "Forbidden" });
  };
}

 app.get('/appointment-settings',
  ensureAuthenticated,
  ensureRole('pro'),
  (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'appointment-settings.html'));
  }
);
                                    
app.post('/auth/logout', (req, res) => {
  req.session?.destroy(() => res.json({ ok: true }));
});

//
// --- helpers ---

async function getDataTypeByName(typeName) {
  return DataType.findOne({ name: typeName, deletedAt: null });
}


// --- CREATE a record: POST /api/records/:typeName ---
app.post('/api/records/:typeName', ensureAuthenticated, async (req, res) => {
  try {
    const typeName = req.params.typeName;
    const dt = await getDataTypeByNameLoose(typeName);
    if (!dt) return res.status(404).json({ error: `Data type "${typeName}" not found` });

    const rawValues = req.body?.values;
    if (!rawValues || typeof rawValues !== 'object') {
      return res.status(400).json({ error: 'values (object) is required' });
    }

    // --- BUSINESS: create slug before normalize ---
    if (/^business$/i.test(typeName)) {
      const explicit = String(rawValues.slug || rawValues.businessSlug || '').trim();
      const nameForSlug = (
        rawValues.businessName ||
        rawValues['Business Name'] ||
        rawValues.name || ''
      ).trim();

      const base = slugify(explicit || nameForSlug);
      if (base) {
        const unique = await ensureUniqueBusinessSlug(base);
        rawValues.slug = unique;
        rawValues.businessSlug = unique; // keep both in sync if you store both
      }
    }

    // --- CLIENT: auto-link to a "User" profile (& optionally create login) ---
    if (/^client$/i.test(typeName)) {
      const email = String(rawValues.Email || rawValues.email || '').toLowerCase().trim();
      const first = (rawValues['First Name'] || '').trim();
      const last  = (rawValues['Last Name']  || '').trim();
      const phone = (rawValues['Phone Number'] || '').trim();

      const alreadyLinked =
        rawValues['Linked User'] && (rawValues['Linked User']._id || rawValues['Linked User'].id);

      if (email && !alreadyLinked) {
        const userDT = await DataType.findOne({ name: 'User', deletedAt: null }).lean();

        let userRec = userDT
          ? await Record.findOne({
              dataTypeId: userDT._id,
              'values.Email': email,
              deletedAt: null
            }).lean()
          : null;

        let auth = await AuthUser.findOne({ email }).lean();

        if (!auth && process.env.AUTO_CREATE_CLIENT_ACCOUNTS === 'true') {
          const crypto = await import('node:crypto');
          const tempPass = crypto.randomBytes(9).toString('base64url'); // one-time temp
          const passwordHash = await bcrypt.hash(tempPass, 12);
          auth = await AuthUser.create({
            email,
            passwordHash,
            roles: ['client'],
            firstName: first,
            lastName:  last
          });
          console.log(`[Invite] Created AuthUser for ${email} (id=${auth._id}). Send invite email here.`);
        }

        if (!userRec && userDT) {
          const [created] = await Record.create([{
            dataTypeId: userDT._id,
            values: {
              'First Name':   first,
              'Last Name':    last,
              'Email':        email,
              'Phone Number': phone
            },
            createdBy: (auth && auth._id) || req.session.userId
          }]);
          userRec = created.toObject();
        }

        if (userRec) {
          rawValues['Linked User'] = { _id: String(userRec._id) };
        }
      }
    }
    // Enrich Appointments from Business/Calendar/Client before normalize
    if (/^appointment$/i.test(typeName)) {
      await enrichAppointment(rawValues);
    }
    // Normalize & persist (make sure slug survives normalization)
    const values = await normalizeValuesForType(dt._id, rawValues);
    if (/^business$/i.test(typeName)) {
      if (rawValues.slug) values.slug = rawValues.slug;
      if (rawValues.businessSlug) values.businessSlug = rawValues.businessSlug;
    }

    const created = await Record.create({
      dataTypeId: dt._id,
      values,
      createdBy: req.session.userId
    });

    res.status(201).json(created);
  } catch (e) {
    console.error('POST /api/records error:', e);
    res.status(500).json({ error: e.message });
  }
});




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

// --- GET one record: GET /api/records/:typeName/:id ---
app.get('/api/records/:typeName/:id', ensureAuthenticated, async (req, res) => {
  try {
    const dt = await getDataTypeByName(req.params.typeName);
    if (!dt) return res.status(404).json({ error: `Data type "${req.params.typeName}" not found` });

    // ⚠️ removed createdBy filter here
    const item = await Record.findOne({
      _id: req.params.id,
      dataTypeId: dt._id,
      deletedAt: null
    });

    if (!item) return res.status(404).json({ error: 'Not found' });

    // Only gate by role/ownership for Appointments
    if (/Appointment/i.test(dt.name)) {
      const ok = await canReadAppointment(req.session, item);
      if (!ok) return res.status(403).json({ error: 'Forbidden' });
    } else {
      // for other types keep creator restriction if you want:
      if (String(item.createdBy) !== String(req.session.userId) && !(req.session.roles||[]).includes('admin')) {
        return res.status(403).json({ error: 'Forbidden' });
      }
    }

    res.json(item);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});



app.get('/api/records/:typeName', ensureAuthenticated, async (req, res) => {
  try {
    const dt = await getDataTypeByNameLoose(req.params.typeName);
    if (!dt) return res.status(404).json({ error: `Data type "${req.params.typeName}" not found` });

    const roles  = req.session?.roles || [];
    const isPriv = roles.includes('pro') || roles.includes('admin');

    const base = { dataTypeId: dt._id, deletedAt: null };
    if (!isPriv) base.createdBy = req.session.userId;

    let where = {};
    if (req.query.where) { try { where = JSON.parse(req.query.where); } catch {} }
    where = await normalizeWhereForType(dt._id, where);

    let sort = { createdAt: -1 };
    if (req.query.sort) { try { sort = await normalizeSortForType(dt._id, JSON.parse(req.query.sort)); } catch {} }

    const limit = Math.min(parseInt(req.query.limit || '100', 10), 500);
    const skip  = Math.max(parseInt(req.query.skip  || '0',   10), 0);

    console.log('[GET many]', { type: req.params.typeName, roles, isPriv });
    const items = await Record.find({ ...base, ...where }).sort(sort).skip(skip).limit(limit);
    res.json(items);
  } catch (e) {
    console.error('GET /api/records error:', e);
    res.status(500).json({ error: e.message });
  }
});


function oid(x) {
  if (!x) return null;
  try { return new mongoose.Types.ObjectId(String(x)); } catch { return null; }
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


// --- UPDATE record (replace or merge values): PATCH /api/records/:typeName/:id ---
app.patch('/api/records/:typeName/:id', ensureAuthenticated, async (req, res) => {
  try {
    const typeName = req.params.typeName;
    const dt = await getDataTypeByNameLoose(typeName);
    if (!dt) return res.status(404).json({ error: `Data type "${typeName}" not found` });

    const roles = req.session?.roles || [];
    const isPriv = roles.includes('pro') || roles.includes('admin');

    const rawValues = req.body?.values || {};
    if (/^appointment$/i.test(typeName)) await enrichAppointment(rawValues);
    const values = await normalizeValuesForType(dt._id, rawValues);

    const setOps = Object.fromEntries(Object.entries(values).map(([k,v]) => [`values.${k}`, v]));

    const q = { _id: req.params.id, dataTypeId: dt._id, deletedAt: null };
    if (!isPriv) q.createdBy = req.session.userId;   // gate only non-privileged

    const updated = await Record.findOneAndUpdate(q, { $set: setOps }, { new: true });
    if (!updated) return res.status(404).json({ error: 'Not found' });
    res.json(updated);
  } catch (e) {
    console.error('PATCH error', e);
    res.status(500).json({ error: e.message });
  }
});

// --- SOFT DELETE record: DELETE /api/records/:typeName/:id ---

app.delete('/api/records/:typeName/:id', ensureAuthenticated, async (req, res) => {
  try {
    const dt = await getDataTypeByNameLoose(req.params.typeName);
    if (!dt) return res.status(404).json({ error: `Data type "${req.params.typeName}" not found` });

    const roles = req.session?.roles || [];
    const isPriv = roles.includes('pro') || roles.includes('admin');

    const q = { _id: req.params.id, dataTypeId: dt._id, deletedAt: null };
    if (!isPriv) q.createdBy = req.session.userId;

    const updated = await Record.findOneAndUpdate(q, { $set: { deletedAt: new Date() } }, { new: true });
    if (!updated) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
  } catch (e) {
    console.error('DELETE error', e);
    res.status(500).json({ error: e.message });
  }
});
// 1) Upload a single file, return a URL
app.post('/api/upload', ensureAuthenticated, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'file required' });
  res.json({ url: `/uploads/${req.file.filename}` });
});

// 2) Compute a unique slug for a type, scoped to current user
app.post('/api/slug/:typeName', ensureAuthenticated, async (req, res) => {
  try {
    const dt = await getDataTypeByName(req.params.typeName);
    if (!dt) return res.status(404).json({ error: `Data type "${req.params.typeName}" not found` });

    const base = String(req.body.base || '')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '');
    const excludeId = req.body.excludeId || null;

    let slug = base || 'item';
    let i = 1;

    const baseQuery = {
      dataTypeId: dt._id,
      'values.slug': slug,
      createdBy: req.session.userId,
      deletedAt: null
    };
    if (excludeId) baseQuery._id = { $ne: excludeId };

    // bump suffix until free
    while (await Record.exists(baseQuery)) {
      slug = `${base}${i++}`;
      baseQuery['values.slug'] = slug;
    }

    res.json({ slug });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});



// ---------- GET RECORDS BY TYPE NAME (keeps your old front-end calls working) ----------
app.get('/get-records/:typeName', ensureAuthenticated, async (req, res) => {
  try {
    const dt = await getDataTypeByName(req.params.typeName); // ✅ fixed name
    if (!dt) return res.json([]);

    const q = {
      dataTypeId: dt._id,
      deletedAt: null,
      createdBy: req.session.userId
    };

    // (Optional improvement: resolve the Business datatype and match referenceTo by its _id)

    const rows = await Record.find(q).sort({ createdAt: -1 });
    const out = rows.map(r => ({ _id: r._id, values: r.values || {} }));
    res.json(out);
  } catch (e) {
    console.error('get-records error:', e);
    res.status(500).json({ message: 'Server error' });
  }
});


                               // ----- Records -----
app.get('/api/records', async (req, res) => {
  try {
    const { dataTypeId } = req.query;
    const q = dataTypeId ? { dataTypeId } : {};
    const items = await Record.find(q).sort({ createdAt: -1 });
    res.json(items);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/records', async (req, res) => {
  try {
    const { dataTypeId, values = {} } = req.body;
    if (!dataTypeId) return res.status(400).json({ error: 'dataTypeId required' });
    const created = await Record.create({ dataTypeId, values });
    res.status(201).json(created);
  } catch (e) { res.status(500).json({ error: e.message }); }
});



// GET /api/public/booking-page-by-slug/:slug
app.get('/api/public/booking-page-by-slug/:slug', async (req,res) => {
  try {
    const slug = req.params.slug.trim().toLowerCase();
    const biz = await Records.findOne({ typeName:'Business', 'values.slug': slug, deletedAt: null });
    if (!biz) return res.status(404).json({ error:'Business not found' });

    const bizId = biz._id.toString();
    const selectedId = biz.values?.selectedBookingPageId || '';

    const pages = await Records.find({
      typeName: 'CustomBookingPage',
      deletedAt: null,
      $or: [
        { 'values.businessId': bizId },
        { 'values.Business': bizId },      // flexible keying
        { 'values.ownerId': bizId }
      ]
    }).lean();

    // helpers
    const isPublished = r => !!pickPublishedFlag(r.values||{});
    const byBiz = r => true; // already filtered by biz above
    const byTimeDesc = (a,b) => pickTime(b.values||{}) - pickTime(a.values||{});

    // 1) selected and published?
    let chosen = pages.find(p => p._id.toString() === selectedId && isPublished(p));

    // 2) else latest published
    if (!chosen){
      const published = pages.filter(isPublished).sort(byTimeDesc);
      chosen = published[0] || null;
    }

    if (chosen){
      const jsonStr = pickJson(chosen.values||{});
      return res.json({
        kind: 'custom',
        businessId: bizId,
        pageId: chosen._id,
        json: jsonStr
      });
    }

    // 3/4) fallbacks
    return res.json({
      kind: 'template',
      businessId: bizId,
      templateKey: biz.values?.templateKey || 'basic'
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error:'Resolver failed' });
  }
});


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












                           //Page Routes
//Index page 
   app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

//Admin
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html')); 
});

  //Signup page 
app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signup.html'));


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

});
// Health
app.get('/api/health', (req, res) => res.json({ ok: true }));



///////////////////////////////////////////////////////////////////////////////
//last code
// Connect to database
connectDB();
const PORT = process.env.PORT || 8400;
server.listen(PORT, () => console.log('Server running on ' + PORT));

////////////////////////////////////////////////////////////////////////////////


