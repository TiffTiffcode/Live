// C:\Users\tiffa\OneDrive\Desktop\Live\routes\public.js
// C:\Users\tiffa\OneDrive\Desktop\Live\routes\public.js
const express  = require('express');
const router   = express.Router();
const Record   = require('../models/Record');
const DataType = require('../models/DataType');

// helpers
const toId = (x) => {
  if (!x) return '';
  if (typeof x === 'string') return x;
  if (typeof x === 'object') return String(x._id || x.id || '');
  return '';
};
const needsBusinessScope = (name='') =>
  /^(calendar|category|service)$/i.test(String(name).trim());

// Loose lookup: "Calendar", "calendar", etc.
async function getDTLoose(name) {
  if (!name) return null;
  const dt = await DataType.findOne({
    $or: [
      { name: new RegExp(`^${String(name).trim()}$`, 'i') },
      { nameCanonical: String(name).toLowerCase() }
    ],
    deletedAt: null
  }, { _id: 1 }).lean();
  return dt?._id || null;
}

// GET /public/records
// ?dataType=Service&Business=<bizId>&Calendar=<calId>&Date=YYYY-MM-DD
router.get('/public/records', async (req, res) => {
  try {
    const {
      dataType,
      _id,
      Date: dateISO,
      Calendar,
      'Calendar._id': CalendarDot,
      calendarId,
      Business,
      businessId
    } = req.query;

    const q = { deletedAt: null };
    if (_id) q._id = String(_id).trim();

    let dtId = null;
    if (dataType) {
      dtId = await getDTLoose(dataType);
      if (!dtId) return res.json([]);
      q.dataTypeId = dtId;
    }

    const biz = String(Business || businessId || '').trim();
    if (needsBusinessScope(dataType) && !biz) {
      return res.json([]);
    }

    if (biz) {
      q.$and = (q.$and || []).concat([{
        $or: [
          // scalar string
          { 'values.Business': biz },
          { 'values.businessId': biz },
          { 'values.ownerBusinessId': biz },
          { 'values.ownerId': biz },
          { 'values.Business Id': biz },
          { 'values.Business._id': biz },

          // arrays
          { 'values.Business': { $in: [biz] } },
          { 'values.businessId': { $in: [biz] } },
          { 'values.ownerBusinessId': { $in: [biz] } },
          { 'values.ownerId': { $in: [biz] } },
          { 'values.Business Id': { $in: [biz] } },
        ]
      }]);
    }

    const cal = String(Calendar || CalendarDot || calendarId || '').trim();
    if (cal) {
      q.$and = (q.$and || []).concat([{
        $or: [
          // scalar string
          { 'values.calendarId': cal },
          { 'values.CalendarId': cal },
          { 'values.Calendar._id': cal },
          { 'values.Calendar': cal },
          { 'values.Calendar Id': cal },

          // arrays
          { 'values.calendarId': { $in: [cal] } },
          { 'values.CalendarId': { $in: [cal] } },
          { 'values.Calendar': { $in: [cal] } },
          { 'values.Calendar Id': { $in: [cal] } },
        ]
      }]);
    }

    if (dateISO) {
      const d = String(dateISO).slice(0, 10);
      q['values.Date'] = { $regex: `^${d}` };
    }

    const rows = await Record.find(q, { values: 1 }).lean();

    const filtered = rows.filter(r => {
      const v = r.values || {};

      const bizCandidates = [
        ...(Array.isArray(v.Business) ? v.Business : [v.Business]),
        ...(Array.isArray(v.businessId) ? v.businessId : [v.businessId]),
        ...(Array.isArray(v.ownerBusinessId) ? v.ownerBusinessId : [v.ownerBusinessId]),
        ...(Array.isArray(v.ownerId) ? v.ownerId : [v.ownerId]),
        ...(Array.isArray(v['Business Id']) ? v['Business Id'] : [v['Business Id']]),
        v.Business && v.Business._id
      ]
        .filter(Boolean)
        .map(toId)
        .map(String);

      const calCandidates = [
        ...(Array.isArray(v.Calendar) ? v.Calendar : [v.Calendar]),
        ...(Array.isArray(v.calendarId) ? v.calendarId : [v.calendarId]),
        ...(Array.isArray(v.CalendarId) ? v.CalendarId : [v.CalendarId]),
        ...(Array.isArray(v['Calendar Id']) ? v['Calendar Id'] : [v['Calendar Id']]),
        v.Calendar && v.Calendar._id
      ]
        .filter(Boolean)
        .map(toId)
        .map(String);

      if (biz && !bizCandidates.includes(biz)) return false;
      if (cal && !calCandidates.includes(cal)) return false;

      return true;
    });

    console.log('[public/records] dataType:', dataType);
    console.log('[public/records] biz:', biz);
    console.log('[public/records] cal:', cal);
    console.log('[public/records] mongo rows:', rows.length);
    console.log('[public/records] filtered rows:', filtered.length);

    res.json(filtered.map(r => ({
      _id: String(r._id),
      values: r.values || {}
    })));
  } catch (e) {
    console.error('[public/records] error', e);
    res.status(500).json({ error: 'server_error' });
  }
});
module.exports = router;
