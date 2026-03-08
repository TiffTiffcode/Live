// C:\Users\tiffa\OneDrive\Desktop\Live\routes\auth.js
const express = require('express');
const router  = express.Router();

const bcrypt  = require('bcryptjs');
const AuthUser = require('../models/AuthUser');

const norm = s => String(s || '').toLowerCase().trim();

// ✅ add this here
function establishLoginSession(req, user) {
  return new Promise((resolve, reject) => {
    req.session.regenerate((err) => {
      if (err) return reject(err);

      req.session.userId = String(user._id);
      req.session.roles = Array.isArray(user.roles) ? user.roles : [];

      req.session.user = {
        _id: String(user._id),
        email: user.email || "",
        firstName: user.firstName || "",
        lastName: user.lastName || "",
        roles: req.session.roles,
      };

      req.session.save((saveErr) => {
        if (saveErr) return reject(saveErr);
        resolve();
      });
    });
  });
}
/* ------------------------------ LOGIN ------------------------------ */
router.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const user = await AuthUser.findOne({ email: norm(email) });
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    const ok = await bcrypt.compare(String(password || ''), user.passwordHash);
    if (!ok) return res.status(401).json({ message: 'Invalid credentials' });

    await establishLoginSession(req, user);

    res.json({ ok: true, user: req.session.user });
  } catch (e) {
    console.error('[login] error', e);
    res.status(500).json({ message: 'Login failed' });
  }
});

/* Compatibility alias (some pages might call this) */
router.post('/auth/login', async (req, res) => {
  req.url = '/api/login'; // reuse the handler above
  router.handle(req, res);
});

/* ------------------------------ SIGNUP ----------------------------- */
router.post('/signup', async (req, res) => {
  try {
    const { firstName, lastName, email, password, phone } = req.body || {};
    if (!email || !password) return res.status(400).json({ message: 'Email & password required' });

    const existing = await AuthUser.findOne({ email: norm(email) });
    if (existing) return res.status(409).json({ message: 'Email already in use' });

    const passwordHash = await bcrypt.hash(String(password), 10);
    const user = await AuthUser.create({
      firstName,
      lastName,
      email: norm(email),
      phone,
      passwordHash,
      roles: ['client']
    });

    await establishLoginSession(req, user);

    res.status(201).json({ ok: true, user: req.session.user });
  } catch (e) {
    console.error('[signup] error', e);
    res.status(500).json({ message: 'Signup failed' });
  }
});

router.post('/signup/pro', async (req, res) => {
  try {
    const { firstName, lastName, email, password, phone } = req.body || {};
    if (!email || !password) return res.status(400).json({ message: 'Missing email/password' });

    const existing = await AuthUser.findOne({ email: norm(email) });
    if (existing) return res.status(409).json({ message: 'Email already in use' });

    const passwordHash = await bcrypt.hash(String(password), 10);
    const user = await AuthUser.create({
      firstName,
      lastName,
      email: norm(email),
      phone,
      passwordHash,
      roles: ['pro']
    });

    await establishLoginSession(req, user);

    res.status(201).json({
      ok: true,
      user: req.session.user,
      redirect: '/appointment-settings'
    });
  } catch (e) {
    console.error('[signup/pro] error', e);
    res.status(500).json({ message: 'Signup failed' });
  }
});

/* ------------------------------ ME -------------------------------- */
router.get('/api/me', (req, res) => {
  const id = req.session?.userId || null;
  const u  = req.session?.user   || null;
  if (!id || !u) return res.json({ ok: false, user: null });
  res.json({ ok: true, user: u });
});

/* ----------------------------- LOGOUT ------------------------------ */
router.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('[logout] error', err);
    }

    res.clearCookie('connect.sid', {
      path: '/',
      domain: '.suiteseat.io',
      httpOnly: true,
      secure: true,
      sameSite: 'none',
    });

    res.status(200).json({ ok: true });
  });
});

/* Compatibility alias */
router.post('/api/auth/logout', (req, res) => {
  req.url = '/api/logout';
  router.handle(req, res);
});

/* --------------------------- CHECK LOGIN --------------------------- */
router.get('/check-login', async (req, res) => {
  try {
    if (!req.session?.userId) return res.json({ loggedIn: false });
    const u = await AuthUser.findById(req.session.userId).lean();
    if (!u) return res.json({ loggedIn: false });
    res.json({
      loggedIn: true,
      userId:   String(u._id),
      email:    u.email || '',
      firstName: u.firstName || '',
      lastName:  u.lastName  || '',
      roles: req.session.roles || []
    });
  } catch (e) {
    console.error('check-login error:', e);
    res.status(500).json({ loggedIn: false });
  }
});

module.exports = router;
