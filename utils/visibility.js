// -----------------------------
// enforcedWhereForUser
// -----------------------------
// Builds a query that allows:
// 1) createdBy == me
// 2) OR record has a "user id field" pointing to me (values.Pro / values.Client / etc.)
// 3) OR record references another record that is visible to me (1 hop)
// NOTE: This is generic — no hardcoded "Business" / "Appointment".
async function enforcedWhereForUser({ dataTypeId, userId }, _ctx = {}) {
  const me = String(userId || "");
  if (!me) return { _id: { $in: [] } };

  const dtIdStr = String(dataTypeId || "");
  if (!isObjectIdLike(dtIdStr)) return { _id: { $in: [] } };

  // ---- recursion guards + memo ----
  _ctx.memoWhere = _ctx.memoWhere || new Map();
  _ctx.memoIds   = _ctx.memoIds   || new Map();
  _ctx.stack     = _ctx.stack     || new Set();

  const memoKey = `${dtIdStr}:${me}`;
  if (_ctx.memoWhere.has(memoKey)) return _ctx.memoWhere.get(memoKey);

  // prevent infinite loops if types reference each other
  if (_ctx.stack.has(memoKey)) {
    // safest fallback: only what I created
    return { $or: [{ createdBy: me }] };
  }
  _ctx.stack.add(memoKey);

  // Always allow what I created
  const or = [{ createdBy: me }];

  // Load fields for this datatype
  const fields = await Field.find({ dataTypeId: dtIdStr, deletedAt: null }).lean();

  // (A) direct user-id fields (values.Pro == me, values.Client == me, etc.)
  const meObj = toObjId(me);
  for (const f of fields) {
    const nm = canonName(f.name);
    if (!USER_ID_FIELD_NAMES.has(nm)) continue;

    for (const p of refCandidatePaths(f.name)) {
      or.push({ [p]: me });
      if (meObj) or.push({ [p]: meObj });
    }
  }

  // (B) one-hop: if this record references another record that is visible to me
  // For each Reference field, allow if it points to any "visible parent IDs".
  for (const f of fields) {
    if (String(f.type) !== "Reference") continue;
    if (!f.referenceTo) continue;

    const parentTypeId = String(f.referenceTo);
    if (!isObjectIdLike(parentTypeId)) continue;

    const parentIdsKey = `${parentTypeId}:${me}`;

    let parentIds = _ctx.memoIds.get(parentIdsKey);
    if (!parentIds) {
      const parentVisibleWhere = await enforcedWhereForUser(
        { dataTypeId: parentTypeId, userId: me },
        _ctx
      );

      const parentRows = await Record.find({
        dataTypeId: parentTypeId,
        deletedAt: null,
        ...parentVisibleWhere,
      })
        .select({ _id: 1 })
        .limit(2000)
        .lean();

      parentIds = parentRows.map(r => String(r._id)).filter(Boolean);
      _ctx.memoIds.set(parentIdsKey, parentIds);
    }

    if (!parentIds.length) continue;

    const parentObjIds = parentIds
      .filter(isObjectIdLike)
      .map(id => new mongoose.Types.ObjectId(id));

    for (const p of refCandidatePaths(f.name)) {
      // Works for string ids, object refs, AND arrays (Mongo $in matches array values too)
      or.push({ [p]: { $in: parentIds } });
      if (parentObjIds.length) or.push({ [p]: { $in: parentObjIds } });
    }
  }

  const out = or.length ? { $or: or } : { _id: { $in: [] } };
  _ctx.memoWhere.set(memoKey, out);
  _ctx.stack.delete(memoKey);
  return out;
}

module.exports = { enforcedWhereForUser };
