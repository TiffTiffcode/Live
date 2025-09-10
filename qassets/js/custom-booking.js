

/////////////////////////////////////////////////////////////////
                          //Log in


/* ================== LOGIN WIRING ================== */
document.addEventListener('DOMContentLoaded', () => {
  const loginStatus = document.getElementById('login-status-text');
  const openLoginBtn = document.getElementById('open-login-popup-btn');
  const logoutBtn    = document.getElementById('logout-btn');
  const popup        = document.getElementById('popup-login');
  const overlay      = document.getElementById('popup-overlay');

  async function refreshLoginUI() {
    try {
      const res  = await fetch('/check-login');
      const data = await res.json();
      if (data.loggedIn) {
        loginStatus.textContent = `Hi, ${data.firstName ?? ''} 👋`;
        logoutBtn?.style && (logoutBtn.style.display = 'inline-block');
        openLoginBtn?.style && (openLoginBtn.style.display = 'none');
           // ⬇️ add these:
    
      } else {
     
        loginStatus.textContent = 'Not logged in';
        logoutBtn?.style && (logoutBtn.style.display = 'none');
        openLoginBtn?.style && (openLoginBtn.style.display = 'inline-block');
      }
    } catch {
      loginStatus.textContent = 'Not logged in';
    }
  }

  function openLoginPopup() {
    if (!popup || !overlay) return;
    popup.style.display   = 'block';
    overlay.style.display = 'block';
    document.body.classList.add('popup-open');
  }

  function closeAllPopups() {
    document.querySelectorAll('.popup-add-business').forEach(el => el.style.display = 'none');
    if (popup)   popup.style.display   = 'none';
    if (overlay) overlay.style.display = 'none';
    document.body.classList.remove('popup-open');
  }
  // expose the one we actually use elsewhere if you need it
  window.closeLoginPopup = closeAllPopups;

  // wire buttons
  openLoginBtn?.addEventListener('click', openLoginPopup);
  overlay?.addEventListener('click', closeAllPopups);
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeAllPopups(); });

  // submit login
  document.getElementById('login-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email    = document.getElementById('login-email').value.trim();
    const password = document.getElementById('login-password').value.trim();
    if (!email || !password) return alert('Please enter both email and password.');

    try {
      const res = await fetch('/login', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ email, password })
      });
      const result = await res.json();
      if (res.ok) {
        alert('✅ Logged in!');
        closeAllPopups();
        await refreshLoginUI();
       

      } else {
        alert(result.message || 'Login failed.');
      }
    } catch (err) {
      console.error('Login error:', err);
      alert('Something went wrong.');
    }
  });

  // logout
  logoutBtn?.addEventListener('click', async () => {
    try {
      const res = await fetch('/logout');
      const out = await res.json().catch(() => ({}));
      if (res.ok) {
        alert('👋 Logged out!');
        window.location.href = 'signup.html';
      } else {
        alert(out.message || 'Logout failed.');
      }
    } catch (err) {
      console.error('Logout error:', err);
      alert('Something went wrong during logout.');
    }
  });

  // initial UI
  refreshLoginUI();
});

/* ============== END LOGIN WIRING ============== */

////////////////////////////////////////////////////////////
//Load Business Dropdown

/* ================== BUSINESS DROPDOWN LOADER (diagnostic) ================== */
(function () {
  const group   = document.getElementById('business-dropdown-group');
  const select  = document.getElementById('business-dropdown');
  const refresh = document.getElementById('business-refresh');

  const SS_KEY = 'selectedBusinessId';
const BAD = new Set(['', 'Loading…', 'loading…', 'Loading...', 'loading...']);

  function escapeHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g, m => ({
      '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
    }[m]));
  }

// Robustly pull a display name from a dynamic Record.values
function extractName(values, fallbackId='') {
  if (!values || typeof values !== 'object') return 'Untitled';

  const getText = (v) => {
    if (v == null) return '';
    if (typeof v === 'string') return v.trim();
    if (typeof v === 'number') return String(v);
    if (Array.isArray(v)) return getText(v[0]);          // e.g. single-item arrays
    if (typeof v === 'object') {
      // common shapes like { text: '...' } or { value: '...' }
      return getText(v.text ?? v.value ?? v.label ?? v.name ?? '');
    }
    return '';
  };

  // 1) Strong, explicit keys (most likely in your setup)
  const strongKeys = [
    'Name','name','Business Name','businessName','Business','Title','title','Display Name','displayName','Company','Store Name','Label','label'
  ];
  for (const k of strongKeys) {
    const t = getText(values[k]);
    if (t) return t;
  }

  // 2) Any key that contains "name" (case-insensitive)
  for (const k of Object.keys(values)) {
    if (/name/i.test(k)) {
      const t = getText(values[k]);
      if (t) return t;
    }
  }

  // 3) Other reasonable fallbacks people often store
  const otherKeys = ['Slug','slug','Handle','handle','Username','username'];
  for (const k of otherKeys) {
    const t = getText(values[k]);
    if (t) return t;
  }

  // 4) Last resort: short id
  return fallbackId ? `Untitled (${fallbackId.slice(-6)})` : 'Untitled';
}

  function getSavedSelection() {
    return sessionStorage.getItem(SS_KEY) || '';
  }
  function saveSelection(id) {
    if (id) sessionStorage.setItem(SS_KEY, id);
  }
  function announceChange() {
    const id   = select?.value || '';
    const name = select?.options[select.selectedIndex]?.text || '';
    document.dispatchEvent(new CustomEvent('business:change', { detail: { id, name } }));
  }

  async function loadBusinesses() {
    if (!group || !select) {
      console.warn('[business-dropdown] Missing elements:',
        { hasGroup: !!group, hasSelect: !!select, hasRefresh: !!refresh });
      return;
    }

    // Make sure it’s visible so you can see errors/state
    group.style.display = 'block';

    // UI state
    select.disabled = true;
    select.innerHTML = `<option>Loading…</option>`;

    try {
      const url = `/api/records/Business?ts=${Date.now()}`;
      console.log('[business-dropdown] Fetching:', url);
      const res = await fetch(url, {
        credentials: 'include',
        cache: 'no-store',
        headers: { 'Accept': 'application/json' }
      });

      console.log('[business-dropdown] HTTP status:', res.status);
      if (!res.ok) {
        select.innerHTML = `<option>Error ${res.status} loading businesses</option>`;
        return;
      }

      const json = await res.json();
      console.log('[business-dropdown] Payload:', json);

      const all = Array.isArray(json) ? json.filter(r => !r.deletedAt) : [];
    const items = all
  .map(r => ({ _id: r._id, name: extractName(r.values, r._id) }))
  .sort((a, b) => a.name.localeCompare(b.name));

      if (items.length === 0) {
        select.innerHTML = `<option value="">No businesses yet</option>`;
        select.disabled = true;
        return;
      }

      const saved = getSavedSelection();
      if (BAD.has(saved)) sessionStorage.removeItem(SS_KEY);

      select.innerHTML = items
        .map(b => `<option value="${b._id}">${escapeHtml(b.name)}</option>`)
        .join('');

      const exists = saved && items.some(b => b._id === saved);
      select.value = exists ? saved : items[0]._id;

      saveSelection(select.value);
      select.disabled = false;
      announceChange();
    } catch (err) {
      console.error('[business-dropdown] Fetch error:', err);
      select.innerHTML = `<option>Error loading businesses</option>`;
      select.disabled = true;
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    // Don’t silently return—log instead
    if (!group || !select) {
      console.warn('[business-dropdown] DOM nodes not found on DOMContentLoaded.');
      return;
    }

    // Force-visible early, even before fetch
    group.style.display = 'block';

    refresh?.addEventListener('click', loadBusinesses);
   select.addEventListener('change', () => {
  const v = select.value;
  if (!BAD.has(v)) sessionStorage.setItem(SS_KEY, v);
  announceChange();
});

    loadBusinesses();
  });
})();


//////////////////////////////////
//Save Page
// ============== PUBLISH (save to CustomBookingPage) ==============
function getSelectedBusinessId() {
  const dd = document.getElementById('business-dropdown');
  return (dd && dd.value) || sessionStorage.getItem('selectedBusinessId') || '';
}

// If you used the builder engine earlier, this will serialize it.
// Adjust if your state lives elsewhere.
function getDraftJson() {
  try {
    return JSON.stringify(window.Builder?.elements ?? []);
  } catch {
    return '[]';
  }
}

async function publishCurrentPage() {
  const btn = document.getElementById('publish-btn');
  const businessId = getSelectedBusinessId();
  if (!businessId) {
    alert('Select a business first.');
    return;
  }

  const payloadJson = getDraftJson();
  const now = new Date().toISOString();

  btn.disabled = true;
  const original = btn.textContent;
  btn.textContent = 'Publishing…';

  try {
    // 1) Load existing CustomBookingPage records
    const listRes = await fetch(`/api/records/CustomBookingPage?ts=${Date.now()}`, {
      credentials: 'include',
      headers: { 'Accept': 'application/json' },
      cache: 'no-store'
    });
    if (!listRes.ok) throw new Error(`Load pages failed: ${listRes.status}`);
    const allPages = (await listRes.json()).filter(r => !r.deletedAt);

    // 2) Find page for this business (handles different shapes your API might store)
    const page = allPages.find(p => {
      const v = p.values || {};
      const ref = v.Business;
      return (
        ref === businessId ||
        ref?._id === businessId ||
        v.businessId === businessId
      );
    });

    if (page) {
      // 3a) Update existing page
      const nextVersion = Number(page.values?.Version || 0) + 1;
      const patchBody = {
        values: {
          'Draft JSON': payloadJson,
          'Published JSON': payloadJson,
          'Updated At': now,
          'Published At': now,
          'is Published': true,
          'Version': nextVersion
        }
      };
      const up = await fetch(`/api/records/CustomBookingPage/${page._id}`, {
        method: 'PATCH',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(patchBody)
      });
      if (!up.ok) throw new Error(`PATCH failed: ${up.status}`);
    } else {
      // 3b) Create new page for this business
      // If your API expects references as raw IDs, this is fine:
      // 'Business': businessId
      // If it expects an object (e.g., {_id: ...}), change it accordingly.
const postBody = {
  values: {
    Business: { _id: businessId, recordId: businessId }, // both for resiliency
    'Draft JSON': payloadJson,
    'Published JSON': payloadJson,
    'Created At': now,
    'Updated At': now,
    'Published At': now,
    'is Published': true,
    'Version': 1,
    Title: 'My Custom Page' // if you have a title field, helps the dropdown
  }
};


      const cr = await fetch('/api/records/CustomBookingPage', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(postBody)
      });
      if (!cr.ok) throw new Error(`POST failed: ${cr.status}`);
    }

    alert('Published ✅');
  } catch (err) {
    console.error(err);
    alert('Failed to publish. Check console for details.');
  } finally {
    btn.disabled = false;
    btn.textContent = original;
  }
}

// Hook up the button
document.getElementById('publish-btn')?.addEventListener('click', publishCurrentPage);


////
//Load Booking Page when the business is selected 
/* ================== BOOKING PAGE LOADER (on business change) ================== */
// ===== Z-ORDER: keep all z >= 0 and sequential =====
function getMaxZMounted(refEl){
  return getMountedSiblings(refEl).reduce((m,e)=>Math.max(m, e.z||0), 0);
}


function normalizeZ() {
  const arr = window.Builder.elements || [];
  // If any z is missing/invalid, seed from array order
  let changed = false;
  arr.forEach((e, i) => {
    if (typeof e.z !== 'number' || e.z < 0 || !Number.isFinite(e.z)) {
      e.z = i; changed = true;
    }
  });
  // Compact to 0..N keeping relative order
  const sorted = [...arr].sort((a,b) => (a.z||0) - (b.z||0));
  sorted.forEach((e, i) => { if (e.z !== i) { e.z = i; changed = true; } });
  return changed;
}
function getMaxZ() {
  const arr = window.Builder.elements || [];
  return arr.reduce((m,e) => Math.max(m, (typeof e.z === 'number' ? e.z : 0)), 0);
}
function rerender() {
  if (normalizeZ()) { /* keep it tidy */ }
  if (typeof renderAllFromState === 'function') renderAllFromState();
  else if (typeof renderAll === 'function') renderAllFromState();
}

/* ================== BOOKING PAGE LOADER (robust + logs) ================== */
window.Builder = window.Builder || { elements: [], selectedId: null };

const PAGE_CANVAS = document.getElementById('page');

// Minimal renderers so you can see blocks
function attachSharedUI(node, el){
  node.dataset.eid = el.id;
  node.style.zIndex = String(el.z ?? 0); 
  if (window.Builder?.selectedId === el.id) node.classList.add('selected');

  
  attachSelectable(node, el);
  attachDragAnywhere(node, el);;
  attachResizeHandles(node, el);
  attachToolbar(node, el);
  updateToolbarPlacement(node, el);
}

function renderAllFromState(){
  const canvas = document.getElementById('page');
  if (!canvas) return;

  // keep the global undo/redo toolbar alive
  Array.from(canvas.querySelectorAll('.el')).forEach(n => n.remove());
  if (typeof ensureCanvasToolbar === 'function') ensureCanvasToolbar();

  const elems = window.Builder.elements || [];
  const byId = {};

  // 1) render top-level sections first
  elems
    .filter(e => !e.parentId && e.type === 'section')
    .sort((a,b) => (a.z||0) - (b.z||0))
    .forEach(e => {
      const n = Registry.section.render(e);
      byId[e.id] = n;
      canvas.appendChild(n);
    });

  // 2) render other top-level elements (not inside a section)
  elems
    .filter(e => !e.parentId && e.type !== 'section')
    .sort((a,b) => (a.z||0) - (b.z||0))
    .forEach(e => {
      const def = Registry[e.type] || Registry.__fallback;
      const n = def.render(e);
      byId[e.id] = n;
      canvas.appendChild(n);
    });

  // 3) render children into their parent section's content
  elems
    .filter(e => !!e.parentId)
    .sort((a,b) => (a.z||0) - (b.z||0))
    .forEach(e => {
      const parentNode = byId[e.parentId];
      if (!parentNode) return;
      const content = parentNode.querySelector('.section-content') || parentNode;
      const def = Registry[e.type] || Registry.__fallback;
      const n = def.render(e);
      byId[e.id] = n;
      content.appendChild(n);
    });

  if (typeof refreshHistoryUI === 'function') refreshHistoryUI();
}
function renderAll(){
  const page = document.getElementById('page');
  page.innerHTML = '';
  for (const el of (window.Builder.elements || [])) {
    const def = Registry[el.type];
    if (!def) continue;
    page.appendChild(def.render(el));
  }
  applyAllZ();  // 👈 after render, restack everything
}


document.addEventListener('click', (e) => {
  const tb = e.target.closest('.el-toolbar');
  if (tb) {
    const btn = e.target.closest('button');
    dbg('[delegate] toolbar click reached DOM', { text: btn?.textContent?.trim() });
  }
}, true);

// ===== Z-ORDER: push to DOM + reorder nodes =====
function getDomHostFor(el){
  // if this element is inside a section, its host is that section's content
  if (el.parentId){
    const host = document.querySelector(`.el[data-eid="${el.parentId}"] .section-content`);
    if (host) return host;
  }
  // top-level
  return document.getElementById('page');
}

function getMountedSiblings(el){
  const host = getDomHostFor(el);
  if (!host) return [];
  const ids = Array.from(host.querySelectorAll(':scope > .el')).map(n => n.dataset.eid);
  return (window.Builder.elements || []).filter(e => ids.includes(e.id));
}

function normalizeZFor(el){
  const sibs = getMountedSiblings(el).sort((a,b) => (a.z||0) - (b.z||0));
  sibs.forEach((e,i) => { e.z = i; });
}

// *** key function: set z-index styles AND reorder the DOM ***
function applyAllZ(){
  const hosts = [
    document.getElementById('page'),
    ...document.querySelectorAll('.section-content')
  ].filter(Boolean);

  hosts.forEach(host => {
    // map current child nodes to their data
    const pairs = Array.from(host.querySelectorAll(':scope > .el'))
      .map(node => {
        const id = node.dataset.eid;
        const data = (window.Builder.elements || []).find(e => e.id === id);
        return data ? { node, data } : null;
      })
      .filter(Boolean);

    // update CSS z-index
    pairs.forEach(({ node, data }) => {
      node.style.zIndex = String(data.z ?? 0);
    });

    // reorder DOM by z (lowest first)
    pairs.sort((a,b) => (a.data.z||0) - (b.data.z||0));
    pairs.forEach(({ node }) => host.appendChild(node));

    console.log('[z] applyAllZ host=', host.id || host.className,
      pairs.map(p => `${p.data.id}:${p.data.z}`).join(', '));
  });
}

// ---------- helpers to survive schema variations ----------
const toStr = v => (v == null ? '' : String(v));
function firstKeyLike(obj, regexArr){
  if (!obj) return null;
  const keys = Object.keys(obj);
  for (const rx of regexArr){
    const k = keys.find(k => rx.test(k));
    if (k) return k;
  }
  return null;
}
function matchBusiness(record, businessId){
  const v = record?.values || {};
  // find a "Business" field by name, case-insensitive
  const businessKey = firstKeyLike(v, [/^business$/i, /businessId/i, /owner/i]);
  const ref = businessKey ? v[businessKey] : undefined;

  const idStr = toStr(businessId);
  const candidates = [
    toStr(ref),
    toStr(ref?._id),
    toStr(ref?.id),
    toStr(ref?.recordId),
    toStr(ref?.value),   // ← added to support { value: "<id>" }
    toStr(v.businessId),
    toStr(v.ownerId)
  ].filter(Boolean);

  const ok = candidates.some(c => c === idStr);
  if (!ok) {
    console.log('[match] skip page', record?._id, 'candidates=', candidates, '!=', idStr);
  }
  return ok;
}


function pickPublishedFlag(values){
  const key = firstKeyLike(values, [/^is[\s_]*published$/i, /^published$/i]);
  return key ? !!values[key] : false;
}
function pickTime(values){
  // prefer Updated, else Published, else Created
  const k = firstKeyLike(values, [/^updated\s*at$/i, /^published\s*at$/i, /^created\s*at$/i, /^updated$/i]);
  return k ? Date.parse(values[k]) || 0 : 0;
}
function pickJson(values){
  // prefer Published JSON, else Draft JSON, case/space insensitive
  const pubK = firstKeyLike(values, [/^published\s*json$/i, /^publishedjson$/i]);
  const draK = firstKeyLike(values, [/^draft\s*json$/i, /^draftjson$/i]);
  return values[pubK] ?? values[draK] ?? '[]';
}

function choosePageForBusiness(list){
  if (!Array.isArray(list) || !list.length) return null;
  const published = list.filter(r => pickPublishedFlag(r.values || {}));
  if (published.length) return published[0];
  return [...list].sort((a,b) => pickTime(b.values||{}) - pickTime(a.values||{}))[0];
}

// ---------- main loader ----------
async function loadBookingPageForBusiness(businessId){
  console.log('[load] businessId=', businessId);
  if (!businessId) {
    window.Builder.elements = [];
    renderAllFromState();
    return;
  }

  try {
    const url = `/api/records/CustomBookingPage?ts=${Date.now()}`;
    console.log('[load] GET', url);
    const res = await fetch(url, {
      credentials: 'include',
      headers: { 'Accept': 'application/json' },
      cache: 'no-store'
    });
    console.log('[load] status', res.status);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const all = (await res.json()).filter(r => !r.deletedAt);
    console.log('[load] total pages:', all.length);

    const mine = all.filter(r => matchBusiness(r, businessId));
    console.log('[load] pages for business:', mine.length);

    const page = choosePageForBusiness(mine);
    if (!page) {
      console.log('[load] no page found for business');
      window.Builder.elements = [];
      renderAllFromState();
      return;
    }

    const jsonStr = pickJson(page.values || {});
    console.log('[load] using JSON length:', jsonStr?.length ?? 0);

    let arr = [];
    try { arr = JSON.parse(jsonStr) || []; }
    catch (e) {
      console.error('[load] invalid JSON in page', page._id, e);
      arr = [];
    }

    if (!Array.isArray(arr)) arr = [];
    window.Builder.elements = arr;
    window.Builder.selectedId = null;
    normalizeAllZ();   // ← ensure z is 0..N before painting
    renderAllFromState();
    if (typeof renderInspector === 'function') renderInspector();  
historyReset('load');     // <-- prime undo/redo baseline
refreshHistoryUI();



  } catch (err) {
    console.error('[load] failed:', err);
    window.Builder.elements = [];
    renderAllFromState();
  }
}

// ---------- wire to dropdown change + initial load ----------
document.addEventListener('business:change', (e) => {
  const businessId = e.detail?.id || '';
  console.log('[event] business:change', businessId);
  loadBookingPageForBusiness(businessId);
});

// initial try (in case a business is already selected)
document.addEventListener('DOMContentLoaded', () => {
  const BAD = new Set(['', 'Loading…', 'loading…', 'Loading...', 'loading...']);
  const dd = document.getElementById('business-dropdown');

  let pre = (dd && dd.value) || sessionStorage.getItem('selectedBusinessId') || '';
  if (BAD.has(pre)) {
    pre = sessionStorage.getItem('selectedBusinessId') || '';
  }
  if (BAD.has(pre)) pre = '';

  if (pre) {
    console.log('[init] preselected business', pre);
    loadBookingPageForBusiness(pre);
  } else {
    console.log('[init] no preselected business');
  }
});




///////////////////////////////
//make Page Droppable
// ====== Builder core (state + registry) ======
// ====== Builder core (state + registry) ======
const GRID = 6;
const snap = n => Math.round(n / GRID) * GRID;
const genId = () => 'e_' + Math.random().toString(36).slice(2,9);



// Use the SAME state everywhere (loader, publish, drag/drop)
window.Builder = window.Builder || { elements: [], selectedId: null };
const Builder = window.Builder;

// REPLACE your entire Registry with this
const Registry = {
  group: {
    defaults: () => ({
      frame: { x: 40, y: 40, w: 300, h: 180 },
      props: { background: '#fff', radius: 12, padding: 16 },
      style: {}
    }),
    render(el) {
      const node = document.createElement('div');
      node.className = 'el group';
      node.dataset.eid = el.id;

      node.style.left   = el.frame.x + 'px';
      node.style.top    = el.frame.y + 'px';
      node.style.width  = el.frame.w + 'px';
      node.style.height = el.frame.h + 'px';
      node.style.background   = el.props.background ?? '#fff';
      node.style.borderRadius = (el.props.radius ?? 12) + 'px';
      node.style.padding      = (el.props.padding ?? 16) + 'px';
      node.style.zIndex       = String(el.z ?? 0);

      if (window.Builder?.selectedId === el.id) node.classList.add('selected');

      attachSharedUI(node, el);
      return node;
    }
  },
//Registry.image.render
image: {
  defaults: () => ({
    frame: { x: 60, y: 60, w: 240, h: 160 },
    props: { src: '', fit: 'cover', radius: 12, alt: '', panX: 0, panY: 0 }, // ← add panX, panY
    style: {}
  }),
  render(el) {
  const node = document.createElement('div');
  node.className = 'el image';
  node.dataset.eid = el.id;

  node.style.left   = (el.frame.x ?? 60) + 'px';
  node.style.top    = (el.frame.y ?? 60) + 'px';
  node.style.width  = (el.frame.w ?? 240) + 'px';
  node.style.height = (el.frame.h ?? 160) + 'px';
  node.style.border = '1px solid #e5e7eb';
  node.style.borderRadius = (el.props?.radius ?? 12) + 'px';
  node.style.background = '#fff';
  node.style.zIndex = String(el.z ?? 0);
  node.style.overflow = 'visible';         // <<< allow toolbar to hang outside
  
  // inner wrapper does the clipping of the image
  const wrap = document.createElement('div');
  wrap.className = 'image-inner';
  wrap.style.position = 'absolute';
  wrap.style.inset = '0';
  wrap.style.overflow = 'hidden';
  wrap.style.borderRadius = 'inherit';

  const img = document.createElement('img');
  img.alt = el.props?.alt ?? '';
  img.style.width = '100%';
  img.style.height = '100%';
  img.style.objectFit = el.props?.fit ?? 'cover';
  img.style.pointerEvents = 'none';
  img.draggable = false;

    const px = Number(el.props?.panX) || 0;
  const py = Number(el.props?.panY) || 0;
  img.style.transform = `translate(${px}px, ${py}px)`;
  img.style.willChange = 'transform';

  wrap.appendChild(img);
  node.appendChild(wrap);

  if (el.props?.src) {
    img.src = el.props.src;
  } else {
    // placeholder overlay inside the clipped area
    const ph = document.createElement('div');
     ph.className = 'image-placeholder'; 
    ph.style.position = 'absolute';
    ph.style.inset = '0';
    ph.style.display = 'grid';
    ph.style.placeItems = 'center';
    ph.style.color = '#6b7280';
    ph.style.fontSize = '12px';
    ph.style.pointerEvents = 'none';
    ph.textContent = 'Click ＋ to add image';

    wrap.appendChild(ph);
  }



  attachSharedUI(node, el);
  return node;
}

  }
};

function applyImage(el, url){
  if (!el || !url) return;

  // update state
  el.props = el.props || {};
  el.props.src = url;

  // try to find the live node
  const sel = `.el[data-eid="${el.id}"]`;
  let live = document.querySelector(sel);
  if (!live && typeof rerender === 'function') {
    rerender();
    live = document.querySelector(sel);
  }

  // update DOM if present
  if (live) {
    const img = live.querySelector('img');
    if (img) img.src = url;
    const ph = live.querySelector('.image-placeholder');
    if (ph) ph.remove();
  } else {
    console.warn('[image] live node not found for', el.id);
  }

  historyPush('image:set-src');
}

const TEXT_PLACEHOLDER = 'Double-click to edit';

// --- TEXT ELEMENT ---
Registry.text = {
  defaults: () => ({
    frame: { x: 120, y: 160, w: 360, h: 48 },
    props: {
      content: '',                 // ← persisted text
      color: '#111827',
      fontSize: 20,
      weight: 400,
      align: 'left',
      lineHeight: 1.3,
      family: 'Inter, system-ui, sans-serif'
    },
    style: {}
  }),

  render(el){
    const node = document.createElement('div');
    node.className = 'el text';
    node.dataset.eid = el.id;

    // frame
    node.style.position = 'absolute';
    node.style.left   = (el.frame?.x ?? 120) + 'px';
    node.style.top    = (el.frame?.y ?? 160) + 'px';
    node.style.width  = (el.frame?.w ?? 360) + 'px';
    node.style.height = (el.frame?.h ?? 48) + 'px';
    node.style.zIndex = String(el.z ?? 0);
    node.style.boxSizing = 'border-box';

    // content node
    const c = document.createElement('div');
    c.className = 'text-content';

    const saved = (el.props?.content ?? '').trim();
    if (saved) {
      c.textContent = saved;
      c.classList.remove('placeholder');
    } else {
      c.textContent = 'Double-click to edit';
      c.classList.add('placeholder');   // grey/italic via CSS
    }

    // style from props (so it survives reload)
    c.style.color      = el.props?.color ?? '#111827';
    c.style.fontSize   = ((el.props?.fontSize ?? 20) + 'px');
    c.style.fontWeight = String(el.props?.weight ?? 400);
    c.style.textAlign  = el.props?.align ?? 'left';
    c.style.lineHeight = String(el.props?.lineHeight ?? 1.3);
    c.style.fontFamily = el.props?.family ?? 'system-ui, sans-serif';

    node.appendChild(c);

    // allow double-click to start editing (optional)
    node.addEventListener('dblclick', () => typeof beginTextEdit === 'function' && beginTextEdit(el));

    attachSharedUI(node, el);
    return node;
  }
};


async function openImagePicker(el){
  const inp = ensureImagePicker();

  const onChange = async () => {
    const file = inp.files?.[0];
    try {
      if (file) {
        const dataURL = await fileToDataURL(file);   // persistent in your JSON
        applyImage(el, dataURL);                      // ⟵ instant update
      }
    } finally {
      inp.value = '';
      inp.removeEventListener('change', onChange);
    }
  };

  // listen once so handlers don’t stack
  inp.addEventListener('change', onChange, { once: true });
  inp.click();
}



// ====== Render everything from state ======
const page = document.getElementById('page');

function renderAllFromState(){
  const page = document.getElementById('page');
  if (!page) return;

  page.innerHTML = '';

  // render parents (no parentId) before children
  const els = (window.Builder.elements || []).slice().sort((a,b) => {
    const A = a.parentId ? 1 : 0;
    const B = b.parentId ? 1 : 0;
    return A - B;  // parents first
  });

  for (const el of els){
    const def = Registry[el.type];
    if (!def) continue;
    const node = def.render(el);          // must set .el + data-eid
    const host = getDomHostFor(el);
    host.appendChild(node);
  }

  applyAllZ(); // paint z-index from state
}

function getMaxZForParent(pid){
  return (window.Builder.elements || [])
    .filter(e => (e.parentId || null) === (pid || null))
    .reduce((m, e) => Math.max(m, e.z || 0), 0);
}

function addElement(type, at, parentId = null) {
  const def = Registry[type];
  if (!def) return;
  const base = def.defaults();

  const start = clampToCanvas(
    at?.x ?? base.frame.x, at?.y ?? base.frame.y, base.frame.w, base.frame.h
  );

  const el = {
    id: genId(),
    type,
    parentId,
    props: base.props,
    style: base.style || {},
    frame: { x: start.x, y: start.y, w: base.frame.w, h: base.frame.h },
    z: getMaxZForParent(parentId) + 1,   // ← parent-aware
  };

  (window.Builder.elements || []).push(el);
  normalizeZ(parentId);
  selectElement(el.id);
  if (typeof renderAllFromState === 'function') renderAllFromState(); else renderAll?.();
  historyPush('add:' + type);
}

// ====== Add an element (used by drop) ======
// BEFORE
// function addElement(type, at) {

// AFTER
function addElement(type, at, parentId = null) {
  const def = Registry[type];
  if (!def) return;
  const base = def.defaults();

  const start = clampToCanvas(
    at?.x ?? base.frame.x, at?.y ?? base.frame.y, base.frame.w, base.frame.h
  );

  const el = {
    id: genId(),
    type,
    parentId,
    props: base.props,
    style: base.style || {},
    frame: { x: start.x, y: start.y, w: base.frame.w, h: base.frame.h },
    z: getMaxZForParent(parentId) + 1,   // ← parent-aware
  };

  (window.Builder.elements || []).push(el);
  normalizeZ(parentId);
  selectElement(el.id);
  if (typeof renderAllFromState === 'function') renderAllFromState(); else renderAll?.();
  historyPush('add:' + type);
}
function normalizeAllZ(){
  const parents = new Set((window.Builder.elements || []).map(e => e.parentId || null));
  parents.forEach(pid => normalizeZ(pid));
}

function restoreSnapshot(snap) {
  window.Builder.elements = JSON.parse(JSON.stringify(snap.elements || []));
  window.Builder.selectedId = snap.selectedId || null;
  normalizeAllZ();                  // ← instead of normalizeZ()
  rerender();
}


// ====== Make the canvas accept drops ======
page.addEventListener('dragover', (e) => {
  // only allow dragovers for our element payload
  if (e.dataTransfer.types.includes('application/x-ss-element')) {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'copy';
  }
});

page.addEventListener('drop', (e) => {
  if (!e.dataTransfer.types.includes('application/x-ss-element')) return;
  e.preventDefault();

  const type = e.dataTransfer.getData('application/x-ss-element');

  const rect = page.getBoundingClientRect();
  const pageX = snap(e.clientX - rect.left);
  const pageY = snap(e.clientY - rect.top);

  // if the pointer is over a Section, parent to it and convert to local coords
  const host = findTopSectionAt(pageX, pageY); // you added this helper earlier
  let target = { x: pageX, y: pageY };
  let pid = null;

  if (host) {
    target = pageToLocal(host, pageX, pageY);  // convert to section-local x/y
    pid = host.id;
  }

  addElement(type, target, pid);  // ← pass parent id
});

// initial paint (empty)
renderAllFromState();


/////////////////////////////

/////////////////////////////////////////
//Add Inspector

// ===== Inspector schema + renderer =====

// 1) Per-element props schema (start with "group")
const PropsSchemas = {
  group: [
    { key: 'background', label: 'Background', type: 'color',  path: 'props.background', default: '#ffffff' },
    { key: 'radius',     label: 'Corner radius', type: 'number', min: 0, max: 48, step: 1, path: 'props.radius', default: 12 },
    { key: 'padding',    label: 'Padding', type: 'number', min: 0, max: 64, step: 1, path: 'props.padding', default: 16 },
  ],
  section: [
    { key:'background', label:'Background',  type:'color',  path:'props.background', default:'#f9fafb' },
    { key:'padding',    label:'Padding',     type:'number', min:0, max:96, step:2, path:'props.padding',   default:24 },
    { key:'radius',     label:'Corner radius', type:'number', min:0, max:48, step:1, path:'props.radius',  default:0 },
  ],
  text: [
    { key: 'content',  label: 'Text', type: 'textarea', path: 'props.content',  default: 'Double-click to edit' },
    { key: 'color',    label: 'Color', type: 'color',    path: 'props.color',    default: '#111827' },
    { key: 'fontSize', label: 'Size',  type: 'number', min: 8, max: 96, step: 1, path: 'props.fontSize', default: 20 },
    { key: 'weight',   label: 'Weight', type: 'number', min: 100, max: 900, step: 100, path: 'props.weight', default: 400 },
    { key: 'align',    label: 'Align',  type: 'select', options: ['left','center','right'], path: 'props.align', default: 'left' },
  ],
  image: [
    { key: 'fit',     label: 'Object fit', type: 'select', options: ['cover','contain','fill','none','scale-down'], path: 'props.fit', default: 'cover' },
    { key: 'radius',  label: 'Corner radius', type: 'number', min: 0, max: 48, step: 1, path: 'props.radius', default: 12 },
  ],
};
// 2) tiny get/set by "a.b.c" path
function getByPath(obj, path, fallback){
  const parts = path.split('.');
  let cur = obj;
  for (const p of parts){ if (!cur || typeof cur !== 'object') return fallback; cur = cur[p]; }
  return cur === undefined ? fallback : cur;
}
function setByPath(obj, path, value){
  const parts = path.split('.');
  let cur = obj;
  for (let i=0;i<parts.length-1;i++){
    const p = parts[i];
    if (!cur[p] || typeof cur[p] !== 'object') cur[p] = {};
    cur = cur[p];
  }
  cur[parts[parts.length-1]] = value;
}

// live-apply without a full re-render
function applyLiveStyle(el){
  const node = document.querySelector(`.el[data-eid="${el.id}"]`);
  if (!node) return;

  if (el.type === 'group' || el.type === 'section'){
    node.style.background   = el.props?.background ?? (el.type === 'section' ? '#f9fafb' : '#fff');
    node.style.borderRadius = ((el.props?.radius ?? (el.type === 'section' ? 0 : 12)) + 'px');
    node.style.padding      = ((el.props?.padding ?? (el.type === 'section' ? 24 : 16)) + 'px');
  }

  // text
  if (el.type === 'text'){
    const content = node.querySelector('.text-content');
    if (!content) return;
    content.textContent   = el.props?.content ?? '';
    content.style.color   = el.props?.color ?? '#111827';
    content.style.fontSize   = (el.props?.fontSize ?? 20) + 'px';
    content.style.fontWeight = String(el.props?.weight ?? 400);
    content.style.textAlign  = el.props?.align ?? 'left';
    content.style.lineHeight = String(el.props?.lineHeight ?? 1.3);
    content.style.fontFamily = el.props?.family ?? 'system-ui, sans-serif';
  }
}

//Helper 
// top-level (page host) helpers
function getTopLevel() {
  return (window.Builder.elements || []).filter(e => !e.parentId);
}
function normalizeTopLevelZ() {
  const tops = getTopLevel().sort((a,b) => (a.z||0) - (b.z||0));
  tops.forEach((e,i) => { e.z = i; });
}

// Move the selected element's PARENT SECTION behind other sections
function sendParentSectionToBack(el = getSelectedElement()){
  if (!el || !el.parentId) { console.log('[sec-z] not in a section'); return; }
  const sec = (window.Builder.elements || []).find(e => e.id === el.parentId);
  if (!sec) return;

  console.log('[sec-z] sendParentSectionToBack', { section: sec.id, oldZ: sec.z });

  // push it under everyone then normalize 0..n
  sec.z = -1;
  normalizeTopLevelZ();

  applyAllZ();   // will reorder page-level DOM + paint zIndex
  rerender();    // keep inspector + chrome in sync
  historyPush('section:z-back');
}

// (optional) bring parent section to front
function bringParentSectionToFront(el = getSelectedElement()){
  if (!el || !el.parentId) { console.log('[sec-z] not in a section'); return; }
  const sec = (window.Builder.elements || []).find(e => e.id === el.parentId);
  if (!sec) return;

  const max = getTopLevel().reduce((m,e)=>Math.max(m, e.z||0), 0);
  sec.z = max + 1;
  normalizeTopLevelZ();
  applyAllZ();
  rerender();
  historyPush('section:z-front');
}

function mkInspectorBtn(label, title, onClick){
  const b = document.createElement('button');
  b.type = 'button';
  b.className = 'inspector-btn';
  b.textContent = label;
  if (title) b.title = title;
  b.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    onClick?.();
  });
  return b;
}

function buildInspectorControl(field, el) {
  // Custom renderer wins (for special widgets)
  if (typeof field.render === 'function') {
    const node = field.render(el);
    return node || null;
  }

  let input = null;

  switch (field.type) {
    case 'color': {
      const i = document.createElement('input');
      i.type = 'color';
      i.value = getByPath(el, field.path, field.default ?? '#ffffff');
      i.addEventListener('input', () => {
        setByPath(el, field.path, i.value);
        applyLiveStyle(el);
        historyPush('prop:' + field.key);
      });
      input = i;
      break;
    }
    case 'number': {
      const i = document.createElement('input');
      i.type = 'number';
      if (field.min != null)  i.min  = field.min;
      if (field.max != null)  i.max  = field.max;
      if (field.step != null) i.step = field.step;
      i.value = getByPath(el, field.path, field.default ?? 0);
      i.addEventListener('input', () => {
        const v = Number(i.value);
        setByPath(el, field.path, Number.isFinite(v) ? v : (field.default ?? 0));
        applyLiveStyle(el);
        historyPush('prop:' + field.key);
      });
      input = i;
      break;
    }
    case 'text': {
      const i = document.createElement('input');
      i.type = 'text';
      i.value = getByPath(el, field.path, field.default ?? '');
      i.addEventListener('input', () => {
        setByPath(el, field.path, i.value);
        applyLiveStyle(el);
        historyPush('prop:' + field.key);
      });
      input = i;
      break;
    }
    case 'textarea': {
      const ta = document.createElement('textarea');
      ta.rows = field.rows ?? 3;
      ta.value = getByPath(el, field.path, field.default ?? '');
      ta.addEventListener('input', () => {
        setByPath(el, field.path, ta.value);
        applyLiveStyle(el);
        historyPush('prop:' + field.key);
      });
      input = ta;
      break;
    }
    case 'select': {
      const sel = document.createElement('select');
      const opts = field.options || [];
      opts.forEach(opt => {
        const [val, label] = Array.isArray(opt) ? opt : [opt, String(opt)];
        const o = document.createElement('option');
        o.value = val; o.textContent = label;
        sel.appendChild(o);
      });
      sel.value = getByPath(el, field.path, field.default ?? (opts[0]?.[0] ?? ''));
      sel.addEventListener('change', () => {
        setByPath(el, field.path, sel.value);
        applyLiveStyle(el);
        historyPush('prop:' + field.key);
      });
      input = sel;
      break;
    }
    case 'checkbox': {
      const i = document.createElement('input');
      i.type = 'checkbox';
      i.checked = !!getByPath(el, field.path, field.default ?? false);
      i.addEventListener('change', () => {
        setByPath(el, field.path, !!i.checked);
        applyLiveStyle(el);
        historyPush('prop:' + field.key);
      });
      input = i;
      break;
    }
    default:
      return null; // unknown type → don’t append anything
  }

  return input;
}


// 4) Build the inspector UI for the selected element
function renderInspector(){
  const box = document.getElementById('inspector');
  if (!box) return;

  const el = (typeof getSelectedElement === 'function') ? getSelectedElement() : null;

  box.innerHTML = '';
  const h = document.createElement('h3');
  h.textContent = 'Inspector';
  box.appendChild(h);

  if (!el){
    box.insertAdjacentHTML('beforeend','<div class="empty">Select an element to edit its properties.</div>');
    return;
  }

  const schema = PropsSchemas[el.type] || [];
  if (!schema.length){
    box.insertAdjacentHTML('beforeend', `<div class="empty">No editable props for "<b>${el.type}</b>".</div>`);
    return;
  }

schema.forEach(field => {
  const wrap  = document.createElement('div');
  wrap.className = 'field';

  if (field.label) {
    const label = document.createElement('label');
    label.textContent = field.label;
    wrap.appendChild(label);
  }

  const control = buildInspectorControl(field, el);
  if (control) wrap.appendChild(control);   // only append if it’s a real Node

  box.appendChild(wrap);
});

// Optional: extra controls for specific types
if (el.type === 'image' && typeof buildImagePanInspector === 'function') {
  box.appendChild(buildImagePanInspector(el));
}


 // --- Actions (same as toolbar) ---
// ---------- Inspector Actions (VERTICAL) ----------
// ----- Inspector Actions: vertical stack -----
// --- Inspector Actions (REPLACE your add()/calls block with this) ---
const actions = document.createElement('div');
actions.className = 'inspector-actions';

const title = document.createElement('div');
title.className = 'inspector-actions-title';
title.textContent = 'Actions';
actions.appendChild(title);

const stack = document.createElement('div');
stack.className = 'inspector-bottomrow';

// helper that logs before/after + runs the fn
function addIns(label, tip, fn, name){
  stack.appendChild(
    mkInspectorBtn(label, tip, () => {
      selectElement(el.id);
      const cur = getSelectedElement();
      console.log(`[inspector] "${tip}" clicked`, { name, target: el.id, selected: cur?.id });
      logZ(`before ${name}`, cur || el);          // ← requires logZ from the debug helpers I gave you
      try { fn(); } catch (e) { console.error(`[inspector] ${name} error`, e); }
      logZ(`after ${name}`, getSelectedElement() || el);
    })
  );
}

// z-order
addIns('⤊','Bring to front', bringToFront, 'bringToFront');
addIns('▲','Bring forward',  bringForward,  'bringForward');
addIns('▼','Send backward',  sendBackward,  'sendBackward');
addIns('⤋','Send to back',   sendToBack,    'sendToBack');

// type-specific
if (el.type === 'image') addIns('＋','Upload image', () => openImagePicker(el), 'openImagePicker');
if (el.type === 'text')  addIns('✎','Edit text',    () => beginTextEdit(el),   'beginTextEdit');

// common
addIns('⧉','Duplicate', () => duplicateSelected({ x:20, y:20 }), 'duplicateSelected');
addIns('✕','Delete',    () => deleteElementById(el.id, { cascade:true }), 'deleteElement');

// show only if the element is inside a section
if (el.parentId) {
  stack.appendChild(
    mkInspectorBtn('⤶ Sec back', 'Send parent section to back', () => {
      sendParentSectionToBack(el);
    })
  );
  stack.appendChild(
    mkInspectorBtn('⤒ Sec front', 'Bring parent section to front', () => {
      bringParentSectionToFront(el);
    })
  );
}

actions.appendChild(stack);
box.appendChild(actions);



  // ---------------------------------------------------------------


}

////Temp
// === DEBUG UTILITIES ===
window.SS_DEBUG = true;

function dbg(...args){ if (window.SS_DEBUG) console.log(...args); }
function warn(...args){ if (window.SS_DEBUG) console.warn(...args); }
function group(label){ if (window.SS_DEBUG) console.groupCollapsed(label); }
function groupEnd(){ if (window.SS_DEBUG) console.groupEnd(); }

// snapshot z-state of mounted siblings around an element
function snapshotZ(el){
  const sibs = getMountedSiblings(el);
  return sibs.map(s => ({ id: s.id, z: s.z || 0 }));
}

function logZ(where, el){
  if (!el){ warn(`[${where}] no selected element`); return; }
  const host = getDomHostFor(el);
  const sibs = getMountedSiblings(el);
  group(`[z] ${where} el=${el.id} parent=${el.parentId || '∅'} z=${el.z || 0} (sibs=${sibs.length})`);
  console.table(sibs.map(s => ({ id: s.id, z: s.z || 0 })));
  console.log('DOM host:', host);
  groupEnd();
}

//end temp


///////////////////////////////////////////////////Add Elements 
///Change Background Color 
// --- page-level settings (color or image) ---


// Attach shared chrome (selection, move, resize, toolbar) to ANY element node
function attachSharedUI(node, el) {
  node.dataset.eid = el.id;
  node.style.zIndex = String(el.z ?? 0);

  if (window.Builder?.selectedId === el.id) node.classList.add('selected');

 
  attachSelectable(node, el);
  attachDragAnywhere(node, el);;
  attachResizeHandles(node, el);
  attachToolbar(node, el);
  updateToolbarPlacement(node, el);
}

//Make sure elements dont go outside of page 
// ===== Bounds helpers =====
function getCanvasBounds(elW, elH){
  const pageEl = document.getElementById('page');
  const maxX = Math.max(0, pageEl.clientWidth  - elW);
  const maxY = Math.max(0, pageEl.clientHeight - elH);
  return { minX: 0, minY: 0, maxX, maxY };
}
const pageEl = document.getElementById('page');
if (pageEl) {
  pageEl.addEventListener('pointerdown', (e) => {
    if (!e.target.closest('.el')) selectElement(null);
  });
}

function clampToCanvas(x, y, elW, elH){
  const b = getCanvasBounds(elW, elH);
  return {
    x: Math.min(Math.max(b.minX, x), b.maxX),
    y: Math.min(Math.max(b.minY, y), b.maxY)
  };
}
////////////////////////////////////Elements/////////////////////////
// ====== Make the "Group" tab draggable ======
const groupTab = document.querySelector('.tab[data-tab="group"]');
// don’t edit your HTML; set it via JS:
groupTab?.setAttribute('draggable', 'true');

groupTab?.addEventListener('dragstart', (e) => {
  // custom MIME so we only accept our elements
  e.dataTransfer.setData('application/x-ss-element', 'group');
  e.dataTransfer.effectAllowed = 'copy';
});

// ====== Make the "Image" tab draggable ======
const imageTab = document.querySelector('.tab[data-tab="image"]');
imageTab?.setAttribute('draggable', 'true');
imageTab?.addEventListener('dragstart', (e) => {
  e.dataTransfer.setData('application/x-ss-element', 'image');
  e.dataTransfer.effectAllowed = 'copy';
});


//Image Element
 function ensureAddImageFab(){
  if (document.getElementById('add-image-fab')) return;

  const btn = document.createElement('button');
  btn.id = 'add-image-fab';
  btn.type = 'button';
  btn.title = 'Add image';
  btn.textContent = '+';

  btn.addEventListener('click', () => {
    // default size from the image defaults
    const def = (Registry.image && Registry.image.defaults())
      || { frame: { x:60, y:60, w:240, h:160 } };

    // center-ish placement inside the page
    const pageEl = document.getElementById('page');
    const rect = pageEl.getBoundingClientRect();
    const cx = rect.width  / 2 - def.frame.w / 2;
    const cy = rect.height / 3 - def.frame.h / 2;

    const start = clampToCanvas(cx, cy, def.frame.w, def.frame.h);
    addElement('image', { x: start.x, y: start.y });

    // prompt for URL right away
    const created = getSelectedElement && getSelectedElement();
    if (created && created.type === 'image') {
      const url = prompt('Image URL (you can change later by double-clicking):', created.props?.src || '');
      if (url) {
        created.props = created.props || {};
        created.props.src = url;

        // live update the DOM img
        const img = document.querySelector(`.el.image[data-eid="${created.id}"] img`);
        if (img) img.src = url;

        historyPush('image:set-src');
      }
    }
  });

  document.body.appendChild(btn); // outside #page so it’s always visible
}

function applyImagePan(el){
  const node = document.querySelector(`.el.image[data-eid="${el.id}"]`);
  if (!node) return;
  const img = node.querySelector('img');
  if (!img) return;
  const px = Number(el.props?.panX) || 0;
  const py = Number(el.props?.panY) || 0;
  img.style.transform = `translate(${px}px, ${py}px)`;
}

function setImagePan(el, x, y){
  el.props = el.props || {};
  el.props.panX = x;
  el.props.panY = y;
  applyImagePan(el);
  historyPush('image:pan-set');
}

function nudgeImage(el, dx, dy){
  el.props = el.props || {};
  el.props.panX = (Number(el.props.panX) || 0) + dx;
  el.props.panY = (Number(el.props.panY) || 0) + dy;
  applyImagePan(el);
  historyPush('image:pan-nudge');
}

function buildImagePanInspector(el){
  const wrap = document.createElement('div');
  wrap.className = 'inspector-section';

  // Step field
  const stepField = document.createElement('div');
  stepField.className = 'field';
  const stepLabel = document.createElement('label');
  stepLabel.textContent = 'Nudge step (px)';
  const stepInput = document.createElement('input');
  stepInput.type = 'number';
  stepInput.min = '1';
  stepInput.value = '5';
  stepInput.style.width = '80px';
  stepField.append(stepLabel, stepInput);

  // Arrow grid
  const grid = document.createElement('div');
  grid.style.display = 'grid';
  grid.style.gridTemplateColumns = 'repeat(3, 40px)';
  grid.style.gap = '6px';
  grid.style.marginTop = '8px';

  const makeBtn = (txt, dx, dy, title='') => {
    const b = document.createElement('button');
    b.type = 'button';
    b.textContent = txt;
    if (title) b.title = title;
    b.addEventListener('click', () => {
      const step = Math.max(1, parseInt(stepInput.value || '5', 10));
      if (dx === 0 && dy === 0 && txt === '•') {
        setImagePan(el, 0, 0); // center
      } else {
        nudgeImage(el, dx*step, dy*step);
      }
      updateReadout();
    });
    return b;
  };

  // layout:
  //   [ ]  [↑]  [ ]
  //   [←]  [•]  [→]
  //   [ ]  [↓]  [ ]
  grid.append(
    document.createElement('div'),  makeBtn('↑', 0, -1, 'Up'), document.createElement('div'),
    makeBtn('←', -1, 0, 'Left'),    makeBtn('•', 0, 0, 'Center'), makeBtn('→', 1, 0, 'Right'),
    document.createElement('div'),  makeBtn('↓', 0, 1, 'Down'), document.createElement('div')
  );

  // Current offsets (optional display)
  const cur = document.createElement('div');
  cur.style.marginTop = '6px';
  const updateReadout = () => {
    const x = Number(el.props?.panX) || 0;
    const y = Number(el.props?.panY) || 0;
    cur.textContent = `Offset: x=${x}px, y=${y}px`;
  };
  updateReadout();


  wrap.append(stepField, grid, cur);
  return wrap;
}


///////////////////////////////////////
//Text Elements
// after your existing group/image tab wiring
const textTab = document.querySelector('.tab[data-tab="text"]');
textTab?.setAttribute('draggable', 'true');
textTab?.addEventListener('dragstart', (e) => {
  e.dataTransfer.setData('application/x-ss-element', 'text');
  e.dataTransfer.effectAllowed = 'copy';
});




PropsSchemas.text = [
  { key: 'content',  label: 'Text',       type: 'textarea', path: 'props.content',  default: 'Edit me' },
  { key: 'color',    label: 'Color',      type: 'color',    path: 'props.color',    default: '#111827' },
  { key: 'fontSize', label: 'Font size',  type: 'number',   path: 'props.fontSize', default: 20, min: 10, max: 96, step: 1 },
  { key: 'weight',   label: 'Weight',     type: 'number',   path: 'props.weight',   default: 400, min:100, max:900, step:100 },
  { key: 'align',    label: 'Align',      type: 'select',   path: 'props.align',    default: 'left', options: ['left','center','right'] },
  { key: 'lineHeight', label:'Line height', type:'number',  path:'props.lineHeight', default: 1.3, step: 0.1, min:1, max:2 },
  { key: 'family',   label: 'Font',       type: 'text',     path: 'props.family',   default: 'Inter, system-ui, sans-serif' },
];

function applyLiveTextStyle(el){
  const node = document.querySelector(`.el[data-eid="${el.id}"]`);
  if (!node) return;
  const c = node.querySelector('.text-content');
  if (!c) return;
  const st = el.style || {};
  if (st.fontSize)   c.style.fontSize = st.fontSize + 'px';
  if (st.color)      c.style.color    = st.color;
}

function beginTextEdit(el){
  const node = document.querySelector(`.el[data-eid="${el.id}"]`);
  const c = node?.querySelector('.text-content');
  if (!c) return;

  c.classList.remove('placeholder');
  c.setAttribute('contenteditable', 'true');
  c.focus();

  const commit = () => {
    const next = (c.textContent || '').trim();
    el.props = el.props || {};
    el.props.content = next;

    if (!next) {
      c.textContent = 'Double-click to edit';
      c.classList.add('placeholder');
    }
    c.removeAttribute('contenteditable');
    c.removeEventListener('blur', commit);
    c.removeEventListener('keydown', onKey);
    historyPush('text:edit');
  };

  const onKey = (e) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); c.blur(); }
  };

  c.addEventListener('blur', commit);
  c.addEventListener('keydown', onKey);
}


/////////////////////////////
//Section Element
function attachSectionTag(node, el){
  const tag = document.createElement('div');
  tag.className = 'section-tag';

  const inp = document.createElement('input');
  inp.type = 'text';
  inp.placeholder = 'Section label';
  inp.value = el.props?.tag || '';
  inp.addEventListener('input', () => {
    el.props = el.props || {};
    el.props.tag = inp.value;
  });
  inp.addEventListener('change', () => historyPush('section:tag'));

  // don’t start drag when clicking the input
  inp.addEventListener('pointerdown', e => e.stopPropagation());

  // keep tag visible + on top while interacting
  const raise = () => node.classList.add('hover-raise');
  const lower = () => {
    if (document.activeElement === inp) return; // still typing → keep raised
    node.classList.remove('hover-raise');
  };
  node.addEventListener('mouseenter', raise);
  node.addEventListener('mouseleave', lower);

  inp.addEventListener('focus', () => {
    node.classList.add('tag-editing', 'hover-raise');
  });
  inp.addEventListener('blur', () => {
    node.classList.remove('tag-editing');
    // if not hovered and not selected, drop the raise
    if (!node.matches(':hover') && !node.classList.contains('selected')) {
      node.classList.remove('hover-raise');
    }
  });

  tag.appendChild(inp);
  node.appendChild(tag);
}


Registry.section = {

  defaults: () => ({
    frame: { x: 0, y: 120, w: 0, h: 240 },   // w will be forced to page width
    props: { background: '#f9fafb', radius: 0, padding: 24 },
    style: {}
  }),

  render(el){
    const node = document.createElement('div');
  node.className = 'el section-el'; 
    node.dataset.eid = el.id;

    const page = document.getElementById('page');
    const pageW = page?.clientWidth ?? 800;

    // enforce full-width + x=0
    el.frame.x = 0;
    el.frame.w = pageW;

    // frame
    node.style.left   = '0px';
    node.style.top    = (el.frame.y ?? 120) + 'px';
    node.style.width  = pageW + 'px';
    node.style.height = (el.frame.h ?? 240) + 'px';
    node.style.zIndex = String(el.z ?? 0);

    node.style.boxSizing  = 'border-box';  
    // look
    node.style.background   = el.props?.background ?? '#f9fafb';
    node.style.border       = '1px dashed #d1d5db';
    node.style.borderRadius = (el.props?.radius ?? 0) + 'px';
    node.style.padding      = (el.props?.padding ?? 24) + 'px';
  node.style.zIndex       = String(el.z ?? 0);
  node.style.overflow     = 'visible';

    // Host for children (absolute so left/top of children are local)
  const content = document.createElement('div');
  content.className = 'section-content';
  content.style.position = 'absolute';
  content.style.left = '0'; content.style.top = '0';
  content.style.right = '0'; content.style.bottom = '0';
  content.style.padding = (el.props?.padding ?? 16) + 'px';
  content.style.boxSizing = 'border-box';
  node.appendChild(content);


   // 👇 add the hover label
  attachSectionTag(node, el);
    // shared UI (drag/resize/toolbar)
    attachSharedUI(node, el);

    return node;
  }
};

//make section draggable
const sectionTab = document.querySelector('.tab[data-tab="section"]');
sectionTab?.setAttribute('draggable', 'true');
sectionTab?.addEventListener('dragstart', (e) => {
  e.dataTransfer.setData('application/x-ss-element', 'section');
  e.dataTransfer.effectAllowed = 'copy';
});

//make elements in section  stick
// Is point (px,py) inside element's frame (page coords)?
function pointIn(el, px, py){
  const x = el.frame?.x ?? 0, y = el.frame?.y ?? 0;
  const w = el.frame?.w ?? 0, h = el.frame?.h ?? 0;
  return (px >= x && px <= x + w && py >= y && py <= y + h);
}

// Top-most section under a page coordinate
function findTopSectionAt(px, py){
  const arr = (window.Builder.elements || [])
    .filter(e => e.type === 'section' && !e.parentId && pointIn(e, px, py))
    .sort((a,b) => (a.z||0) - (b.z||0));
  return arr[arr.length - 1] || null;
}

// Children of a parent id, sorted by z
function childrenOf(pid){
  return (window.Builder.elements || [])
    .filter(e => e.parentId === pid)
    .sort((a,b) => (a.z||0) - (b.z||0));
}

// Convert a PAGE point to LOCAL coords inside a section (account for padding)
function pageToLocal(section, px, py){
  const pad = Number(section.props?.padding ?? 16);
  return { x: snap(px - section.frame.x - pad), y: snap(py - section.frame.y - pad) };
}

function getHostFor(el){
  const page = document.getElementById('page');
  if (!el?.parentId) return page;

  // parent section’s content area
  const parent = page.querySelector(`.el[data-eid="${el.parentId}"]`);
  const content = parent?.querySelector('.section-content');
  return content || page; // fallback
}


/////////////////////////////////////////////////////////////////////
//Make elements movable
// Drag anywhere on the element (not the toolbar/handles/inputs)
function attachDragAnywhere(node, el){
  // nicer UX
  node.style.cursor = 'move';

  node.addEventListener('pointerdown', (e) => {
    if (e.button !== 0) return; // left click only

    // don't start a drag from chrome or editable controls
    if (e.target.closest('.resize-handle, .el-toolbar, .delete-btn, .inspector-btn')) return;
    const t = e.target;
    if (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable) return;

    e.preventDefault();
    e.stopPropagation();

    // select the element you grabbed
    selectElement(el.id);

    const start = { x: e.clientX, y: e.clientY, ex: el.frame.x, ey: el.frame.y };
    node.setPointerCapture(e.pointerId);

    const onMove = (ev) => {
      const dx = ev.clientX - start.x;
      const dy = ev.clientY - start.y;

      let nx = snap(start.ex + dx);
      let ny = snap(start.ey + dy);

      // sections stay full-width at x=0
      if (el.type === 'section') nx = 0;

      const clamped = clampToCanvas(nx, ny, el.frame.w, el.frame.h);
      el.frame.x = clamped.x;
      el.frame.y = clamped.y;

      // live paint
      node.style.left = el.frame.x + 'px';
      node.style.top  = el.frame.y + 'px';
      updateToolbarPlacement(node, el);
    };

    const onUp = () => {
      node.releasePointerCapture(e.pointerId);
      node.removeEventListener('pointermove', onMove);
      node.removeEventListener('pointerup', onUp);
      historyPush('move');
    };

    node.addEventListener('pointermove', onMove);
    node.addEventListener('pointerup', onUp);
  });
}

//Resize Elements
// ===== Corner resizing for any element =====
function attachResizeHandles(node, el){
  const corners = ['nw','ne','sw','se'];

  corners.forEach(pos => {
    const h = document.createElement('div');
    h.className = `resize-handle ${pos}`;
    h.dataset.pos = pos;
    node.appendChild(h);

    h.addEventListener('pointerdown', (e) => {
      e.preventDefault();
      e.stopPropagation();

      const pageEl = document.getElementById('page');
      const start = {
        cx: e.clientX, cy: e.clientY,
        ex: el.frame.x, ey: el.frame.y,
        ew: el.frame.w, eh: el.frame.h
      };
const ratio = (start.ew || 1) / Math.max(1, start.eh || 1);
// opposite (fixed) corner while dragging this handle
 const anchor = {
 x: start.ex + (pos.includes('w') ? start.ew : 0),
y: start.ey + (pos.includes('n') ? start.eh : 0)
};

 const minW = 0, minH = 0;   // no minimum size


      h.setPointerCapture(e.pointerId);

      const onMove = (ev) => {
        const dx = ev.clientX - start.cx;
        const dy = ev.clientY - start.cy;

        // propose new box based on corner
        let x = start.ex, y = start.ey, w = start.ew, h2 = start.eh;

        if (pos.includes('e')) w = Math.max(minW, snap(start.ew + dx));
        if (pos.includes('s')) h2 = Math.max(minH, snap(start.eh + dy));

        if (pos.includes('w')) {
          const newW = Math.max(minW, snap(start.ew - dx));
          x = snap(start.ex + (start.ew - newW));
          w = newW;
        }
        if (pos.includes('n')) {
          const newH = Math.max(minH, snap(start.eh - dy));
          y = snap(start.ey + (start.eh - newH));
          h2 = newH;
        }
 // ---- Aspect ratio lock (hold Shift) ----
 if (ev.shiftKey) {
   // choose the dominant delta to drive the other dimension
   const widthLed = Math.abs(w - start.ew) >= Math.abs(h2 - start.eh);
   if (widthLed) {
     h2 = Math.max(minH, Math.round(w / ratio));
   } else {
     w  = Math.max(minW, Math.round(h2 * ratio));
   }
   // keep the opposite corner (anchor) fixed
  x = pos.includes('w') ? (anchor.x - w) : anchor.x;
   y = pos.includes('n') ? (anchor.y - h2) : anchor.y;
 }



        // clamp box to canvas
        const pageW = pageEl.clientWidth;
        const pageH = pageEl.clientHeight;

        // keep left/top >= 0
        if (x < 0) { w += x; x = 0; }
        if (y < 0) { h2 += y; y = 0; }

        // keep right/bottom <= page size
        if (x + w > pageW) w = pageW - x;
        if (y + h2 > pageH) h2 = pageH - y;

   // keep right/bottom <= page size
w  = Math.max(minW, Math.min(w,  pageW - x));
h2 = Math.max(minH, Math.min(h2, pageH - y));

        // update state + live paint
        el.frame = { x, y, w, h: h2 };
        node.style.left   = x + 'px';
        node.style.top    = y + 'px';
        node.style.width  = w + 'px';
        node.style.height = h2 + 'px';
        updateToolbarPlacement(node, el);

    if (el.type === 'section') {
  node.style.left  = '0px';
  node.style.width = document.getElementById('page').clientWidth + 'px';
}
    
      };

      const onUp = () => {
        h.releasePointerCapture(e.pointerId);
        h.removeEventListener('pointermove', onMove);
        h.removeEventListener('pointerup', onUp);
           historyPush('resize');   
        // (optional) mark dirty for autosave later
      };

      h.addEventListener('pointermove', onMove);
      h.addEventListener('pointerup', onUp);
    });
  });
}


// Delete elements 
// ===== Selection + Delete (shared) =====
function selectElement(id){
  const prev = window.Builder.selectedId;
  window.Builder.selectedId = id || null;

  // toggle highlight without repainting the whole canvas
  const prevNode = prev ? document.querySelector(`.el[data-eid="${prev}"]`) : null;
  const curNode  = id ? document.querySelector(`.el[data-eid="${id}"]`) : null;
  if (prevNode) prevNode.classList.remove('selected');
  if (curNode)  curNode.classList.add('selected');

  // just refresh the inspector UI
  if (typeof renderInspector === 'function') renderInspector();
}

// Attach a small “X” button that deletes this element
// Replace your current deleteElementById with this:
function deleteElementById(id, { cascade = true } = {}) {
  const list = window.Builder.elements || [];
  if (!id) return;

  // collect ids to remove: el + (optionally) its descendants
  const toDelete = new Set([id]);
  if (cascade) {
    let grew = true;
    while (grew) {
      grew = false;
      for (const el of list) {
        if (el.parentId && toDelete.has(el.parentId) && !toDelete.has(el.id)) {
          toDelete.add(el.id);
          grew = true;
        }
      }
    }
  }

  // filter and keep everything else
  window.Builder.elements = list.filter(e => !toDelete.has(e.id));

  if (toDelete.has(window.Builder.selectedId)) window.Builder.selectedId = null;

  // re-render + history
  if (typeof renderAllFromState === 'function') renderAllFromState();
  else if (typeof renderAll === 'function') renderAllFromState();
  historyPush('delete');
}

//Send to back 
// Put this near your other z-order helpers
function sendToBackImmediate(targetId){
  const el = targetId
    ? (window.Builder.elements || []).find(e => e.id === targetId)
    : getSelectedElement();
  if (!el) return;

  dbg('[z] sendToBackImmediate start', { id: el.id, parent: el.parentId, z: el.z });

  const host = getDomHostFor(el);
  const sibs = getMountedSiblings(el);
  if (!host || sibs.length < 2) { dbg('[z] nothing to do'); return; }

  // --- State: push under everyone, then renumber 0..n
  let minZ = Infinity;
  sibs.forEach(s => { minZ = Math.min(minZ, s.z || 0); });
  el.z = minZ - 1;
  normalizeZFor(el);      // now el should become z=0 among its mounted siblings

  // --- DOM fallback: force the node to the bottom in this host
  const node = host.querySelector(`:scope > .el[data-eid="${el.id}"]`);
  if (node) host.insertBefore(node, host.firstElementChild);

  applyAllZ();            // paint z-index + final DOM order
  rerender();             // (your renderer is safe; keeps state + inspector in sync)
  historyPush('z-back');
  logZ('after sendToBackImmediate', el);
}

// Make clicking the element select it (ignore clicks on handles/buttons)
function attachSelectable(node, el){
  node.addEventListener('pointerdown', (e) => {
    if (e.target.closest('.delete-btn, .drag-handle, .resize-handle, .el-tool-btn, .el-toolbar')) return;
    selectElement(el.id); // <- triggers renderInspector()
  }, { capture: true });
}



//Element Selector and move and delete using keyboard instead of arrows 


function moveSelectedBy(dx, dy){
  const el = getSelectedElement();
  if (!el) return;
  const pageEl = document.getElementById('page');

  let nx = (el.frame.x || 0) + dx;
  let ny = (el.frame.y || 0) + dy;

  // keep fully inside canvas
  const clamped = clampToCanvas(nx, ny, el.frame.w, el.frame.h);
  el.frame.x = clamped.x;
  el.frame.y = clamped.y;

  // re-render (works with either renderer function name)
  if (typeof renderAllFromState === 'function') renderAllFromState();
  else if (typeof renderAll === 'function') renderAllFromState();
}

function isTypingTarget(t){
  if (!t) return false;
  const tag = (t.tagName || '').toLowerCase();
  if (tag === 'input' || tag === 'textarea' || tag === 'select') return true;
  if (t.isContentEditable) return true;
  return false;
}
//delete,nudge and duplicate elements with control d or command d
// ===== Keyboard: delete + arrow-key nudges + duplicate =====
// ===== Keyboard: delete, arrows, duplicate, z-order =====
document.addEventListener('keydown', (e) => {
  if (isTypingTarget && isTypingTarget(e.target)) return;

    // --- Undo / Redo ---
  if ((e.ctrlKey || e.metaKey) && !e.shiftKey && (e.key === 'z' || e.key === 'Z')) {
    e.preventDefault(); historyUndo(); return;
  }
  if ((e.ctrlKey || e.metaKey) && ((e.shiftKey && (e.key === 'z' || e.key === 'Z')) || e.key === 'y' || e.key === 'Y')) {
    e.preventDefault(); historyRedo(); return;
  }
  const selected = getSelectedElement && getSelectedElement();

  // Duplicate: Ctrl/Cmd + D
  if ((e.ctrlKey || e.metaKey) && (e.key === 'd' || e.key === 'D')) {
    e.preventDefault();
    duplicateSelected({ x: 20, y: 20 });
    return;
  }

  // Z-order:
  // Ctrl/Cmd + ]  => bring forward
  if ((e.ctrlKey || e.metaKey) && e.key === ']') {
    e.preventDefault(); bringForward(); return;
  }
  // Ctrl/Cmd + [  => send backward
  if ((e.ctrlKey || e.metaKey) && e.key === '[') {
    e.preventDefault(); sendBackward(); return;
  }
  // Ctrl/Cmd + Shift + ]  => bring to front
  if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === ']') {
    e.preventDefault(); bringToFront(); return;
  }
// Ctrl/Cmd + Shift + [  => send to back
if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === '[') {
  e.preventDefault(); sendToBackImmediate(); return;
}


  // Delete / Backspace
  if ((e.key === 'Delete' || e.key === 'Backspace') && selected) {
    e.preventDefault();
    deleteElementById(selected.id);
    return;
  }

  // Arrow-key nudges (1px; Shift = 10px)
  if (!selected) return;
  const step = e.shiftKey ? 10 : 1;

  if (e.key === 'ArrowLeft')  { e.preventDefault(); moveSelectedBy(-step, 0); historyPush('nudge');}
  if (e.key === 'ArrowRight') { e.preventDefault(); moveSelectedBy( step, 0); historyPush('nudge');}
  if (e.key === 'ArrowUp')    { e.preventDefault(); moveSelectedBy(0, -step); historyPush('nudge');}
  if (e.key === 'ArrowDown')  { e.preventDefault(); moveSelectedBy(0,  step); historyPush('nudge');}
});

/////
// /Duplicate Images 
// ===== Duplicate selected element =====
function duplicateSelected(offset = { x: 20, y: 20 }) {
  const src = getSelectedElement(); if (!src) return;

  const copy = JSON.parse(JSON.stringify(src));
  copy.id = genId();
  copy.parentId = src.parentId || null;

  // top of the mounted stack for that host
  copy.z = getMaxZMounted(src) + 1;

  copy.frame.x = (src.frame.x || 0) + (offset.x || 0);
  copy.frame.y = (src.frame.y || 0) + (offset.y || 0);

  const clamped = clampToCanvas(copy.frame.x, copy.frame.y, copy.frame.w, copy.frame.h);
  copy.frame.x = clamped.x;
  copy.frame.y = clamped.y;

  (window.Builder.elements || []).push(copy);

  // mount the new node once, then restack
  rerender();
  normalizeZFor(copy);
  applyAllZ();

  selectElement(copy.id);
  historyPush('duplicate');
}



//Allow images to be uploaded when the plus button is pressed 
// Reusable hidden <input type="file"> for image uploads
let _imagePicker;
function ensureImagePicker(){
  if (_imagePicker) return _imagePicker;
  const inp = document.createElement('input');
  inp.type = 'file';
  inp.accept = 'image/*';
  inp.style.display = 'none';
  document.body.appendChild(inp);
  _imagePicker = inp;
  return _imagePicker;
}

// Read a File as a Data URL (persists in your JSON)
function fileToDataURL(file){
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(r.result);
    r.onerror = reject;
    r.readAsDataURL(file);
  });
}



//Make Elements move foward or back with toolbar
// ===== Element toolbar (z-order, duplicate, delete) =====
function attachToolbar(node, el){
  const bar = document.createElement('div');
  bar.className = 'el-toolbar';

  const mk = (label, title, handlerName, handlerFn) => {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'el-tool-btn';
    b.textContent = label;
    b.title = title;
    b.addEventListener('click', (ev) => {
      ev.preventDefault();
      ev.stopPropagation();

      // ensure the click really hits this element
      selectElement(el.id);
      const cur = getSelectedElement();

      dbg(`[toolbar] "${title}" clicked`, { label, handlerName, targetId: el.id, selectedId: cur?.id });
      logZ(`before ${handlerName}`, cur || el);

      try { handlerFn(); }
      catch (err) { console.error(`[toolbar] ${handlerName} error`, err); }

      const after = getSelectedElement() || el;
      logZ(`after ${handlerName}`, after);
    });
    return b;
  };

  const buttons = [
    mk('⤊','Bring to front', 'bringToFront', bringToFront),
    mk('▲','Bring forward',  'bringForward', bringForward),
    mk('▼','Send backward',  'sendBackward', sendBackward),
    mk('⤋','Send to back', 'sendToBackImmediate', () => sendToBackImmediate()),
    ...(el.type === 'image' ? [ mk('＋','Upload image','openImagePicker', () => openImagePicker(el)) ] : []),
    ...(el.type === 'text'  ? [ mk('✎','Edit text',   'beginTextEdit',   () => beginTextEdit(el)) ]  : []),
    mk('⧉','Duplicate', 'duplicateSelected', () => duplicateSelected({ x:20, y:20 })),
    mk('✕','Delete',    'deleteElement',     () => deleteElementById(el.id, { cascade:true })),
  ];

  buttons.forEach(btn => bar.appendChild(btn));
  node.appendChild(bar);
}



// ===== Z-order controls ===== using keyboard 
function getSelectedElement(){
  const id = window.Builder?.selectedId;
  return (window.Builder?.elements || []).find(e => e.id === id) || null;
}
// Find the DOM container that actually hosts the element right now
// host where an element is mounted
function getDomHostFor(el){
  if (el.parentId){
    const host = document.querySelector(`.el[data-eid="${el.parentId}"] .section-content`);
    if (host) return host;
  }
  return document.getElementById('page');
}

function getMountedSiblings(el){
  const host = getDomHostFor(el);
  if (!host) return [];
  const ids = Array.from(host.querySelectorAll(':scope > .el')).map(n => n.dataset.eid);
  return (window.Builder.elements || []).filter(e => ids.includes(e.id));
}

function normalizeZFor(el){
  const sibs = getMountedSiblings(el).sort((a,b) => (a.z||0) - (b.z||0));
  sibs.forEach((e,i) => { e.z = i; });
}

// Reorder DOM to match z (lowest first)
function applyAllZ(){
  const hosts = [
    document.getElementById('page'),
    ...document.querySelectorAll('.section-content')
  ].filter(Boolean);

  hosts.forEach(host => {
    const pairs = Array.from(host.querySelectorAll(':scope > .el'))
      .map(node => {
        const id = node.dataset.eid;
        const data = (window.Builder.elements || []).find(e => e.id === id);
        return data ? { node, data } : null;
      })
      .filter(Boolean);

    pairs.forEach(({ node, data }) => { node.style.zIndex = String(data.z ?? 0); });
    pairs.sort((a,b) => (a.data.z||0) - (b.data.z||0));
    pairs.forEach(({ node }) => host.appendChild(node));

    dbg('[z] applyAllZ host=', host.id || host.className,
        pairs.map(p => `${p.data.id}:${p.data.z}`).join(', '));
  });
}

function rerender(){
  if (typeof renderAllFromState === 'function') renderAllFromState();
  else if (typeof renderAll === 'function') renderAll();
}


function bringToFront(){
  const el = getSelectedElement(); if (!el) return;
  const sibs = getMountedSiblings(el);
  if (sibs.length < 2) return;
  el.z = Math.max(...sibs.map(s => s.z || 0)) + 1;
  normalizeZFor(el);
  applyAllZ();
  historyPush('z-front');
}

function sendToBack(){
  const el = getSelectedElement(); if (!el) return;
  const sibs = getMountedSiblings(el);
  if (sibs.length < 2) return;
  // force below everyone, then compact to 0..n
  el.z = Math.min(...sibs.map(s => s.z || 0)) - 1;
  normalizeZFor(el);
  applyAllZ();
  historyPush('z-back');
}

function bringForward(){
  const el = getSelectedElement(); if (!el) return;
  const sibs = getMountedSiblings(el).sort((a,b)=> (a.z||0)-(b.z||0));
  const i = sibs.findIndex(s => s.id === el.id);
  if (i === -1 || i === sibs.length - 1) { bringToFront(); return; }
  const next = sibs[i+1];
  [el.z, next.z] = [next.z||0, el.z||0];
  normalizeZFor(el);
  applyAllZ();
  historyPush('z-forward');
}

function sendBackward(){
  const el = getSelectedElement(); if (!el) return;
  const sibs = getMountedSiblings(el).sort((a,b)=> (a.z||0)-(b.z||0));
  const i = sibs.findIndex(s => s.id === el.id);
  if (i <= 0) { sendToBack(); return; }
  const prev = sibs[i-1];
  [el.z, prev.z] = [prev.z||0, el.z||0];
  normalizeZFor(el);
  applyAllZ();
  historyPush('z-backward');
}



//Tool Bar
// Place toolbar outside unless near the canvas top
function updateToolbarPlacement(node, el){
  const TOOLBAR_H = 32;   // approx toolbar height (px)
  const MARGIN    = 6;
  const tooHigh = (el.frame?.y ?? 0) <= (TOOLBAR_H + MARGIN);
  if (tooHigh) node.classList.add('toolbar-inside');
  else node.classList.remove('toolbar-inside');
}

//Undo and Redo function 
// ================== HISTORY (Undo / Redo) ==================
const HISTORY_LIMIT = 100;
const History = { stack: [], index: -1 };

function snapshotState() {
  return {
    elements: JSON.parse(JSON.stringify(window.Builder.elements || [])),
    selectedId: window.Builder.selectedId || null
  };
}
function restoreSnapshot(snap) {
  window.Builder.elements = JSON.parse(JSON.stringify(snap.elements || []));
  window.Builder.selectedId = snap.selectedId || null;
  normalizeAllZ();// keep z tidy (helper you’ll add below if not present yet)
  rerender();
}
function historyReset(label = 'reset') {
  History.stack = [snapshotState()];
  History.index = 0;
  if (typeof refreshHistoryUI === 'function') refreshHistoryUI();
}
function historyPush(label = '') {
  const snap = snapshotState();
  if (History.index < History.stack.length - 1) {
    History.stack = History.stack.slice(0, History.index + 1);
  }
  History.stack.push(snap);
  if (History.stack.length > HISTORY_LIMIT) {
    History.stack.shift();
  } else {
    History.index++;
  }
  if (typeof refreshHistoryUI === 'function') refreshHistoryUI();
}
function historyUndo() {
  if (History.index <= 0) return;
  History.index--;
  restoreSnapshot(History.stack[History.index]);
  if (typeof refreshHistoryUI === 'function') refreshHistoryUI();
}
function historyRedo() {
  if (History.index >= History.stack.length - 1) return;
  History.index++;
  restoreSnapshot(History.stack[History.index]);
  if (typeof refreshHistoryUI === 'function') refreshHistoryUI();
}


//Make Undo and redo buttons work and appear 
// ===== Canvas toolbar (Undo / Redo) =====
function ensureCanvasToolbar(){
  const page = document.getElementById('page');
  if (!page || document.getElementById('canvas-toolbar')) return;

  const bar = document.createElement('div');
  bar.id = 'canvas-toolbar';

  const undoBtn = document.createElement('button');
  undoBtn.id = 'canvas-undo';
  undoBtn.className = 'canvas-btn';
  undoBtn.textContent = 'Undo';
  undoBtn.title = 'Undo (Ctrl/Cmd + Z)';
  undoBtn.addEventListener('click', () => historyUndo());

  const redoBtn = document.createElement('button');
  redoBtn.id = 'canvas-redo';
  redoBtn.className = 'canvas-btn';
  redoBtn.textContent = 'Redo';
  redoBtn.title = 'Redo (Ctrl/Cmd + Shift + Z or Ctrl/Cmd + Y)';
  redoBtn.addEventListener('click', () => historyRedo());

  bar.append(undoBtn, redoBtn);
document.body.appendChild(bar);

}

function refreshHistoryUI(){
  const undoBtn = document.getElementById('canvas-undo');
  const redoBtn = document.getElementById('canvas-redo');
  if (!undoBtn || !redoBtn) return;
  const canUndo = History.index > 0;
  const canRedo = History.index < (History.stack.length - 1);
  undoBtn.disabled = !canUndo;
  redoBtn.disabled = !canRedo;
}

// create toolbar once DOM is ready
document.addEventListener('DOMContentLoaded', ensureCanvasToolbar);


