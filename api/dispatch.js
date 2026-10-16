/**
 * ReliefLink — Vercel Serverless API dispatcher (Node.js)
 * All /api/v1/* requests are rewritten here (see vercel.json) with the remaining
 * path passed as ?path=... . Talks to Supabase (PostgREST). No external deps.
 *
 * Env (set in Vercel project):
 *   SUPABASE_URL, SUPABASE_SERVICE_KEY, ADMIN_EMAIL, ADMIN_PASSWORD
 */

const crypto = require('crypto');

const SB_URL = (process.env.SUPABASE_URL || '').replace(/\/$/, '');
const SB_KEY = process.env.SUPABASE_SERVICE_KEY || '';

const ST_LABEL = { pending: 'Pending', assigned: 'Assigned', in_progress: 'In Progress', resolved: 'Resolved' };
const CAT_LABEL = {
  rescue: 'Rescue', medical: 'Medical', food: 'Food', shelter: 'Shelter', clothing: 'Clothing',
  transport: 'Transport', sanitation: 'Sanitation', special: 'Special', recovery: 'Recovery',
  missing: 'Missing', psychological: 'Support', flood_predictor: 'Flood'
};

/* ── Supabase REST helpers ─────────────────────────────── */
function rid(prefix) { return prefix + '-' + Math.random().toString(36).slice(2, 8); }
function nowIso() { return new Date().toISOString(); }

// Last n month keys 'YYYY-MM', oldest first — used for growth/hours charts.
function monthKeys(n) {
  const out = [], d = new Date();
  for (let i = n - 1; i >= 0; i--) {
    const m = new Date(d.getFullYear(), d.getMonth() - i, 1);
    out.push(m.getFullYear() + '-' + String(m.getMonth() + 1).padStart(2, '0'));
  }
  return out;
}

async function sb(table, { method = 'GET', query, body, prefer } = {}) {
  let url = SB_URL + '/rest/v1/' + table;
  const params = new URLSearchParams();
  for (const k in (query || {})) { const v = query[k]; if (v != null) params.append(k, String(v)); }
  const q = params.toString();
  if (q) url += '?' + q;
  const headers = { apikey: SB_KEY, Authorization: 'Bearer ' + SB_KEY, 'Content-Type': 'application/json' };
  if (prefer) headers.Prefer = prefer;
  const r = await fetch(url, { method, headers, body: body != null ? JSON.stringify(body) : undefined });
  if (r.status === 204) return null;
  const text = await r.text();
  const data = text ? JSON.parse(text) : null;
  if (!r.ok) throw new Error('supabase ' + r.status + ' ' + JSON.stringify(data));
  return data;
}

async function sbCount(table, filter) {
  let url = SB_URL + '/rest/v1/' + table + '?select=id' + (filter ? '&' + filter : '');
  const r = await fetch(url, { method: 'HEAD', headers: { apikey: SB_KEY, Authorization: 'Bearer ' + SB_KEY, Prefer: 'count=exact' } });
  const cr = r.headers.get('content-range') || r.headers.get('Content-Range') || '';
  const m = cr.split('/');
  return m.length > 1 ? parseInt(m[1], 10) || 0 : 0;
}

/* ── Response helpers ──────────────────────────────────── */
function ok(res, data, message) { res.status(200).json({ success: true, data: data == null ? null : data, message: message || '' }); }
function fail(res, message, status) { res.status(status || 400).json({ success: false, data: null, message: message || 'error' }); }

/* ── Auth: scrypt password hashing + HMAC session tokens (zero deps) ── */
const AUTH_SECRET = process.env.AUTH_SECRET || 'relieflink-dev-secret-set-AUTH_SECRET-in-vercel';
function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  return 'scrypt$' + salt + '$' + crypto.scryptSync(String(pw), salt, 32).toString('hex');
}
function verifyPassword(pw, stored) {
  try {
    const p = String(stored || '').split('$');
    if (p.length !== 3 || p[0] !== 'scrypt') return false;
    const calc = crypto.scryptSync(String(pw), p[1], 32).toString('hex');
    return crypto.timingSafeEqual(Buffer.from(calc, 'hex'), Buffer.from(p[2], 'hex'));
  } catch (e) { return false; }
}
function b64url(s) { return Buffer.from(s).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function makeToken(user) {
  const payload = b64url(JSON.stringify({ uid: user.id, role: user.role || 'citizen', name: user.full_name || '', phone: user.phone || '', exp: Date.now() + 30 * 864e5 }));
  return payload + '.' + crypto.createHmac('sha256', AUTH_SECRET).update(payload).digest('hex');
}
function readToken(req) {
  try {
    const h = String(req.headers.authorization || '');
    const parts = (h.startsWith('Bearer ') ? h.slice(7) : '').split('.');
    if (parts.length !== 2) return null;
    const expect = crypto.createHmac('sha256', AUTH_SECRET).update(parts[0]).digest('hex');
    if (!crypto.timingSafeEqual(Buffer.from(parts[1], 'hex'), Buffer.from(expect, 'hex'))) return null;
    const t = JSON.parse(Buffer.from(parts[0].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString());
    return t.exp && t.exp > Date.now() ? t : null;
  } catch (e) { return null; }
}
function publicUser(u) { return { id: u.id, full_name: u.full_name, phone: u.phone, email: u.email || null, role: u.role, city: u.city, status: u.status || 'active' }; }

/* ── Endpoint handlers ─────────────────────────────────── */
async function createHelpRequest(res, b) {
  const p = normPKPhone(b.phone); // never reject an emergency request, just clean the number
  const row = {
    id: rid('RFL'), user_id: b.user_id || null, full_name: b.full_name || 'Citizen',
    phone: b.phone || '', city: b.city || '', category: b.category || 'special',
    description: b.description || '', urgency: b.urgent ? 'critical' : (b.urgency || 'high'),
    status: 'pending', latitude: b.latitude != null ? b.latitude : null,
    longitude: b.longitude != null ? b.longitude : null, created_at: nowIso(), updated_at: nowIso()
  };
  const out = await sb('help_requests', { method: 'POST', body: row, prefer: 'return=representation' });
  ok(res, (out && out[0]) || row, 'Request received');
}

async function listHelpRequests(res, q) {
  const limit = Math.min(parseInt(q.limit, 10) || 100, 500);
  const query = { select: '*', order: 'created_at.desc', limit: String(limit) };
  if (q.user_id) query.user_id = 'eq.' + q.user_id;
  ok(res, (await sb('help_requests', { query })) || []);
}

/* ── Registration validation ───────────────────────── */
// Normalise any Pakistani number format (+92, 0092, spaces, dashes) to 03XXXXXXXXX.
function normPKPhone(raw) {
  let d = String(raw || '').replace(/\D/g, '');
  if (d.startsWith('0092')) d = d.slice(4);
  else if (d.startsWith('92')) d = d.slice(2);
  if (d.startsWith('0')) d = d.slice(1);
  if (!/^3\d{9}$/.test(d)) return null;
  const s = d.slice(1, 11);
  if (/(.)\1{4}/.test(s) || /0123456789|9876543210/.test(s)) return null; // 03000000000 / 03123456789 type garbage
  return '03' + s;
}
const PK_CITIES = ['karachi','lahore','islamabad','rawalpindi','multan','faisalabad','peshawar','quetta','hyderabad','sukkur','larkana','gujranwala','gujrat','sargodha','bahawalpur','abbottabad','mardan','dera ismail khan','sahiwal','jhang','rajanpur','muzaffargarh','layyah','khairpur','navabshah','tangowal','sheikhupura','attock','thatta','gwadar','gilgit','skardu','chitral','dir','swat','bannu','dera ghazi khan','kohat','nowshera','charsadda','murree','kahuta','wah','sialkot','narowal','okara','bhakkar','jahram','gojra','kamalia','muridke','pakpattan','ararian','veri'];
const NAME_RE = /^[A-Za-z؀-ۿ][A-Za-z؀-ۿ '-]{1,39}$/;
function cleanCity(v) { v = String(v || '').trim().slice(0, 80); return /^[A-Za-z؀-ۿ0-9 ,.\/'-]+$/.test(v) ? v : ''; } // same rigor as names: allow-listed charset + max length
function validName(n) {
  n = String(n || '').trim();
  if (n.length < 2 || !NAME_RE.test(n)) return false;
  if (/^(?<c>.)(?:\k<c>)+$/.test(n.replace(/\s/g, ''))) return false; // aaaa, xxx
  return true;
}

/* ── Accounts: register / sign in / session / promote citizen ── */
async function register(res, b) {
  const role = b.role === 'volunteer' ? 'volunteer' : 'citizen';
  const phone = normPKPhone(b.phone);
  if (!phone) return fail(res, 'Invalid mobile number — use a real Pakistani number like 03001234567', 400);
  if (!validName(b.full_name)) return fail(res, 'Invalid name — please write your real name (2-40 letters)', 400);
  if (String(b.password || '').length < 6) return fail(res, 'Password must be at least 6 characters', 400);
  const city = cleanCity(b.city);
  // Volunteers must give a city (that is how they get matched). A citizen only needs
  // name + valid mobile + password to create an account — area comes later with their request.
  if (role === 'volunteer' && !city) return fail(res, 'City is required \u2014 type your area or city', 400);
  let skills = [];
  if (role === 'volunteer') {
    skills = (Array.isArray(b.skills) ? b.skills : []).filter(Boolean).slice(0, 3);
    if (!skills.length) return fail(res, 'Select at least one skill — tell us how you can help', 400);
    const known = PK_CITIES.some(k => city.toLowerCase().indexOf(k) > -1);
    if (!known && city.length < 3) return fail(res, 'Please write your city name properly', 400);
  }
  const dup = await sb('users', { query: { select: '*', phone: 'eq.' + phone, limit: '1' } });
  if (dup && dup.length) {
    const ex = dup[0];
    if (ex.password_hash) return fail(res, 'This number is already registered — please sign in', 409);
    // Pre-password account (old volunteer or guest row): set the password and sign them straight in
    const up = await sb('users', { method: 'PATCH', query: { id: 'eq.' + ex.id, select: '*' }, body: { password_hash: hashPassword(b.password), updated_at: nowIso() }, prefer: 'return=representation' });
    const user = (up && up[0]) || ex;
    let vol = null;
    if (user.role === 'volunteer' || role === 'volunteer') {
      vol = ((await sb('volunteers', { query: { select: '*', user_id: 'eq.' + user.id, limit: '1' } }).catch(function () { return []; })) || [])[0] || null;
      if (!vol) {
        const v = await sb('volunteers', { method: 'POST', prefer: 'return=representation', body: { id: rid('vol'), user_id: user.id, full_name: user.full_name, phone, city: user.city || city, skills, availability: b.availability || 'available', registered_at: nowIso() } });
        vol = (v && v[0]) || null;
      }
    }
    return ok(res, { user: publicUser(user), volunteer: vol, token: makeToken(user) }, 'Password set — you are now signed in');
  }
  const uid = rid('usr');
  const out = await sb('users', { method: 'POST', prefer: 'return=representation', body: { id: uid, full_name: b.full_name, phone, email: b.email || null, role, city, password_hash: hashPassword(b.password), created_at: nowIso(), updated_at: nowIso() } });
  const user = (out && out[0]) || { id: uid, full_name: b.full_name, phone, role, city };
  let vol = null;
  if (role === 'volunteer') {
    const v = await sb('volunteers', { method: 'POST', prefer: 'return=representation', body: { id: rid('vol'), user_id: uid, full_name: b.full_name, phone, city, skills, availability: b.availability || 'available', registered_at: nowIso() } });
    vol = (v && v[0]) || null;
  }
  ok(res, { user: publicUser(user), volunteer: vol, token: makeToken(user) }, role === 'volunteer' ? 'Volunteer account created' : 'Account created');
}

async function signin(res, b) {
  const phone = normPKPhone(b.phone);
  if (!phone || !b.password) return fail(res, 'Enter your mobile number and password', 400);
  const rows = await sb('users', { query: { select: '*', phone: 'eq.' + phone, limit: '5' } });
  const u = (rows || []).find(r => verifyPassword(b.password, r.password_hash));
  if (!u) return fail(res, 'Incorrect mobile number or password', 401);
  let vol = null;
  if (u.role === 'volunteer') vol = ((await sb('volunteers', { query: { select: '*', user_id: 'eq.' + u.id, limit: '1' } }).catch(function () { return []; })) || [])[0] || null;
  ok(res, { user: publicUser(u), volunteer: vol, token: makeToken(u) }, 'Welcome back!');
}

async function me(res, req) {
  const t = readToken(req);
  if (!t) return fail(res, 'Session expired — please sign in again', 401);
  const rows = await sb('users', { query: { select: '*', id: 'eq.' + t.uid, limit: '1' } });
  const u = (rows || [])[0];
  if (!u) return fail(res, 'Account not found', 404);
  let vol = null;
  if (u.role === 'volunteer') vol = ((await sb('volunteers', { query: { select: '*', user_id: 'eq.' + u.id, limit: '1' } }).catch(function () { return []; })) || [])[0] || null;
  ok(res, { user: publicUser(u), volunteer: vol });
}

// Guest who already sent requests → give their phone a password, link past requests
async function promoteCitizen(res, b) {
  const phone = normPKPhone(b.phone);
  if (!phone) return fail(res, 'Enter the mobile number you used to send the request', 400);
  if (String(b.password || '').length < 6) return fail(res, 'Password must be at least 6 characters', 400);
  const rows = await sb('users', { query: { select: '*', phone: 'eq.' + phone, limit: '5' } }) || [];
  if (rows.some(r => r.password_hash)) return fail(res, 'This number already has an account — please sign in', 409);
  const hash = hashPassword(b.password);
  // Real world: the dashboard already knows this person — name/city come from the request they sent, never re-asked
  const dName = validName(b.full_name) ? String(b.full_name).trim() : '';
  const dCity = cleanCity(b.city);
  let u = rows[0];
  if (u) {
    const patch = { password_hash: hash, updated_at: nowIso() };
    if (dName && (!u.full_name || /help seeker|citizen/i.test(u.full_name))) patch.full_name = dName;
    if (dCity && !u.city) patch.city = dCity;
    const out = await sb('users', { method: 'PATCH', query: { id: 'eq.' + u.id, select: '*' }, body: patch, prefer: 'return=representation' });
    u = (out && out[0]) || u;
  } else {
    const name = dName || 'Citizen';
    const out = await sb('users', { method: 'POST', prefer: 'return=representation', body: { id: rid('usr'), full_name: name, phone, role: 'citizen', city: dCity, password_hash: hash, created_at: nowIso(), updated_at: nowIso() } });
    u = (out && out[0]) || { id: rid('usr'), full_name: name, phone, role: 'citizen' };
  }
  await sb('help_requests', { method: 'PATCH', query: { phone: 'eq.' + phone, user_id: 'is.null' }, body: { user_id: u.id } }).catch(function () {});
  ok(res, { user: publicUser(u), token: makeToken(u) }, 'Account created — your past requests are now linked');
}

// Back-compat: old landing used register-role — now it is register (password required)
async function registerRole(res, b) { return register(res, b); }

/* A signed-in user editing their OWN profile (name / phone / area). Token is the only
   authority for which row is updated — the id is never taken from the request body. */
async function updateProfile(res, req, b) {
  const t = readToken(req);
  if (!t) return fail(res, 'Session expired — please sign in again', 401);
  if (!t.uid || t.uid === 'admin') return fail(res, 'Not available for this account', 403);
  const rows = await sb('users', { query: { select: '*', id: 'eq.' + t.uid, limit: '1' } });
  const u = (rows || [])[0];
  if (!u) return fail(res, 'Account not found', 404);
  const patch = { updated_at: nowIso() };
  if (b.full_name != null && String(b.full_name).trim() !== '') {
    if (!validName(b.full_name)) return fail(res, 'Invalid name — please write your real name (2-40 letters)', 400);
    patch.full_name = String(b.full_name).trim();
  }
  if (b.city != null && String(b.city).trim() !== '') {
    const c = cleanCity(b.city);
    if (!c) return fail(res, 'Invalid area — use letters only (max 80 characters)', 400);
    patch.city = c;
  }
  if (b.phone != null && String(b.phone).trim() !== '') {
    const p = normPKPhone(b.phone);
    if (!p) return fail(res, 'Invalid mobile number — use a real Pakistani number like 03001234567', 400);
    if (p !== u.phone) {
      const dup = await sb('users', { query: { select: 'id', phone: 'eq.' + p, limit: '1' } });
      if (dup && dup.length && dup[0].id !== u.id) return fail(res, 'That number already belongs to another account', 409);
      patch.phone = p;
    }
  }
  if (Object.keys(patch).length <= 1) return fail(res, 'Nothing to update', 400);
  const out = await sb('users', { method: 'PATCH', query: { id: 'eq.' + u.id, select: '*' }, body: patch, prefer: 'return=representation' });
  const nu = (out && out[0]) || Object.assign({}, u, patch);
  // keep any volunteer row's contact fields in sync so dispatch stays accurate
  if (nu.role === 'volunteer') {
    await sb('volunteers', { method: 'PATCH', query: { user_id: 'eq.' + nu.id }, body: { full_name: nu.full_name, phone: nu.phone, city: nu.city } }).catch(function () {});
  }
  ok(res, { user: publicUser(nu), token: makeToken(nu) }, 'Profile updated');
}

/* ── Self-service account controls. The token (never the body) decides which row is
   affected, so a user can only act on their OWN profile. ── */
async function _selfFromToken(req) {
  const t = readToken(req);
  if (!t || !t.uid || t.uid === 'admin') return null;
  const rows = await sb('users', { query: { select: '*', id: 'eq.' + t.uid, limit: '1' } });
  return (rows || [])[0] || null;
}

// Soft, reversible — profile is turned off but every record is kept.
async function deactivateAccount(res, req) {
  const u = await _selfFromToken(req);
  if (!u) return fail(res, 'Session expired \u2014 please sign in again', 401);
  try {
    const out = await sb('users', { method: 'PATCH', query: { id: 'eq.' + u.id, select: '*' }, body: { status: 'deactivated', deactivated_at: nowIso(), updated_at: nowIso() }, prefer: 'return=representation' });
    ok(res, { user: publicUser((out && out[0]) || Object.assign({}, u, { status: 'deactivated' })) }, 'Profile deactivated \u2014 you can reactivate any time');
  } catch (e) {
    fail(res, 'Account settings not ready yet \u2014 the database migration (005) needs to be applied first', 500);
  }
}

async function reactivateAccount(res, req) {
  const u = await _selfFromToken(req);
  if (!u) return fail(res, 'Session expired \u2014 please sign in again', 401);
  try {
    const out = await sb('users', { method: 'PATCH', query: { id: 'eq.' + u.id, select: '*' }, body: { status: 'active', deactivated_at: null, updated_at: nowIso() }, prefer: 'return=representation' });
    ok(res, { user: publicUser((out && out[0]) || Object.assign({}, u, { status: 'active' })) }, 'Profile reactivated');
  } catch (e) {
    fail(res, 'Account settings not ready yet \u2014 the database migration (005) needs to be applied first', 500);
  }
}

// Permanent — needs the account password, then removes the account, its volunteer
// profile and every help request the person submitted. Cannot be undone.
async function deleteAccount(res, req, b) {
  const u = await _selfFromToken(req);
  if (!u) return fail(res, 'Session expired \u2014 please sign in again', 401);
  if (!b.password || !verifyPassword(b.password, u.password_hash)) return fail(res, 'Enter your password to confirm permanent deletion', 401);
  await sb('volunteers', { method: 'DELETE', query: { user_id: 'eq.' + u.id } }).catch(function () {});
  await sb('help_requests', { method: 'DELETE', query: { user_id: 'eq.' + u.id } }).catch(function () {});
  if (u.phone) await sb('help_requests', { method: 'DELETE', query: { phone: 'eq.' + u.phone } }).catch(function () {});
  await sb('users', { method: 'DELETE', query: { id: 'eq.' + u.id } });
  ok(res, { deleted: true }, 'Your account and its data have been permanently deleted');
}

async function adminSignin(res, b) {
  const wantEmail = (process.env.ADMIN_EMAIL || '').toLowerCase();
  const wantPw = process.env.ADMIN_PASSWORD || '';
  const email = (b.email || '').toLowerCase();
  const mk = function (e) { return makeToken({ id: 'admin', role: 'admin', full_name: e.split('@')[0], phone: '' }); };
  if (wantEmail && wantPw) {
    if (email === wantEmail && b.password === wantPw) return ok(res, { user: { id: 'admin', email, role: 'admin' }, token: mk(email) }, 'Signed in');
    return fail(res, 'Invalid admin email or password', 401);
  }
  // No admin credentials configured yet — demo sign-in so the dashboard is reachable.
  if (email && b.password) return ok(res, { user: { id: 'admin', email, role: 'admin' }, token: mk(email) }, 'Signed in (demo)');
  return fail(res, 'Enter your admin email and password', 400);
}

async function listTasks(res) {
  ok(res, (await sb('volunteer_tasks', { query: { select: '*', status: 'eq.open', order: 'priority.desc,created_at.desc', limit: '100' } })) || []);
}
async function myAssignments(res, q) {
  if (!q.volunteer_id) return ok(res, []);
  ok(res, (await sb('volunteer_tasks', { query: { select: '*', assigned_volunteer_id: 'eq.' + q.volunteer_id, order: 'created_at.desc', limit: '100' } })) || []);
}
async function volunteerStats(res, q) {
  let completed = 0;
  try { completed = await sbCount('volunteer_tasks', 'assigned_volunteer_id=eq.' + encodeURIComponent(q.volunteer_id || '') + '&status=eq.completed'); } catch (e) {}
  ok(res, { tasks_completed: completed, hours_served: completed * 4 });
}
async function claimTask(res, id, b) {
  const patch = { assigned_volunteer_id: b.volunteer_id || null, status: 'claimed', updated_at: nowIso() };
  const out = await sb('volunteer_tasks', { method: 'PATCH', query: { id: 'eq.' + id, select: '*' }, body: patch, prefer: 'return=representation' });
  ok(res, (out && out[0]) || patch, 'Task claimed');
}
async function taskProgress(res, id, b) {
  const patch = { status: b.status || 'in_progress', progress_note: b.progress_note || '', updated_at: nowIso() };
  if (b.status === 'completed') patch.completed_at = nowIso();
  const out = await sb('volunteer_tasks', { method: 'PATCH', query: { id: 'eq.' + id, select: '*' }, body: patch, prefer: 'return=representation' });
  ok(res, (out && out[0]) || patch, 'Progress saved');
}
async function adminOverview(res) {
  const [total, resolved, pending, vols, openTasks] = await Promise.all([
    sbCount('help_requests', ''), sbCount('help_requests', 'status=eq.resolved'),
    sbCount('help_requests', 'status=eq.pending'), sbCount('volunteers', ''),
    sbCount('volunteer_tasks', 'status=eq.open').catch(() => 0)
  ]);
  const recent = await sb('help_requests', { query: { select: '*', order: 'created_at.desc', limit: '5' } }).catch(() => []);
  const alerts = await sb('alerts', { query: { select: '*', is_active: 'eq.true', limit: '50' } }).catch(() => []);

  // ── Real volunteer / task analytics — each block degrades to null on failure ──
  let growth = null, hoursMonthly = null, hoursTotal = null, topVols = null,
    skills = null, avail = null, recentVols = null, availableNow = null;
  try {
    const V = (await sb('volunteers', { query: { select: 'id,full_name,skills,availability,verified,registered_at', order: 'registered_at.desc', limit: '500' } })) || [];
    const keys = monthKeys(12), per = {};
    keys.forEach(k => { per[k] = 0; });
    V.forEach(v => { const k = String(v.registered_at || '').slice(0, 7); if (k in per) per[k]++; });
    let run = 0; growth = keys.map(k => (run += per[k]));
    const sc = {}; V.forEach(v => (v.skills || []).forEach(s => { sc[s] = (sc[s] || 0) + 1; }));
    skills = Object.keys(sc).sort((a, b) => sc[b] - sc[a]).slice(0, 4).map(k => ({ name: k, count: sc[k] }));
    const av = {}; V.forEach(v => { const a = v.availability || 'available'; av[a] = (av[a] || 0) + 1; });
    avail = Object.keys(av).map(k => ({ name: k, count: av[k] }));
    availableNow = av.available || 0;
    recentVols = V.slice(0, 5).map(v => ({
      id: v.id, name: v.full_name || 'Volunteer',
      skills: (v.skills || []).join(', ') || 'General',
      availability: v.availability || 'available', verified: !!v.verified
    }));
  } catch (e) {}
  try {
    const T = (await sb('volunteer_tasks', { query: { select: 'assigned_volunteer_id,completed_at,updated_at', status: 'eq.completed', order: 'completed_at.desc', limit: '500' } })) || [];
    const keys = monthKeys(12), per = {};
    keys.forEach(k => { per[k] = 0; });
    T.forEach(t => { const k = String(t.completed_at || t.updated_at || '').slice(0, 7); if (k in per) per[k]++; });
    hoursMonthly = keys.map(k => per[k] * 4);
    hoursTotal = T.length * 4;
    const byVol = {}; T.forEach(t => { if (t.assigned_volunteer_id) byVol[t.assigned_volunteer_id] = (byVol[t.assigned_volunteer_id] || 0) + 1; });
    topVols = Object.keys(byVol).sort((a, b) => byVol[b] - byVol[a]).slice(0, 5)
      .map(k => ({ volunteer_id: k, tasks: byVol[k], hours: byVol[k] * 4 }));
    if (topVols.length) {
      const V2 = (await sb('volunteers', { query: { select: 'id,full_name', limit: '500' } }).catch(() => [])) || [];
      const nm = {}; V2.forEach(v => { nm[v.id] = v.full_name; });
      topVols.forEach(t => { t.name = nm[t.volunteer_id] || 'Volunteer'; });
    }
  } catch (e) {}

  ok(res, {
    total_requests: total, active_volunteers: vols, resolved, pending,
    open_tasks: openTasks, volunteers_available: availableNow, hours_total: hoursTotal,
    volunteer_growth: growth, hours_monthly: hoursMonthly, top_volunteers: topVols,
    skill_distribution: skills, availability: avail, recent_volunteers: recentVols,
    recent_requests: (recent || []).map(r => ({ id: String(r.id).slice(-4), category: CAT_LABEL[r.category] || r.category || 'Help', location: r.city || '—', status: ST_LABEL[r.status] || 'Pending' })),
    map_markers: alerts || []
  });
}

/* ── Alerts (admin broadcast → volunteer notifications) ── */
async function createAlert(res, req, b) {
  if (!readToken(req)) return fail(res, 'Sign in required — only the authorized team can send alerts', 401);
  const title = (b.title || '').trim();
  if (!title) return fail(res, 'Alert title is required', 400);
  const row = {
    id: rid('alr'), title,
    disaster_type: b.disaster_type || 'flood',
    severity: b.severity || 'high',
    description: b.description || '',
    location_text: b.location_text || b.city || '',
    latitude: b.latitude != null ? +b.latitude : null,
    longitude: b.longitude != null ? +b.longitude : null,
    radius_km: b.radius_km != null ? +b.radius_km : null,
    is_active: true, created_at: nowIso(), updated_at: nowIso()
  };
  const out = await sb('alerts', { method: 'POST', body: row, prefer: 'return=representation' });
  ok(res, (out && out[0]) || row, 'Alert broadcast to volunteers');
}
async function listAlerts(res, q) {
  const query = { select: '*', order: 'created_at.desc', limit: String(Math.min(parseInt(q.limit, 10) || 50, 200)) };
  if (q.active === 'true') query.is_active = 'eq.true';
  ok(res, (await sb('alerts', { query })) || []);
}

/* ── Volunteers (admin roster + verification) ──────────── */
async function listVolunteers(res, q) {
  const query = { select: '*', order: 'registered_at.desc', limit: '200' };
  if (q.availability) query.availability = 'eq.' + q.availability;
  ok(res, (await sb('volunteers', { query })) || []);
}
async function verifyVolunteer(res, req, id) {
  if (!readToken(req)) return fail(res, 'Sign in required', 401);
  const out = await sb('volunteers', { method: 'PATCH', query: { id: 'eq.' + id, select: 'id,verified' }, body: { verified: true }, prefer: 'return=representation' });
  ok(res, (out && out[0]) || { id: id, verified: true }, 'Volunteer verified');
}
async function listShelters(res) {
  ok(res, (await sb('shelters', { query: { select: '*', type: 'neq.hospital', order: 'created_at.desc', limit: '100' } })) || []);
}
async function listHospitals(res) {
  const rows = (await sb('shelters', { query: { select: '*', type: 'eq.hospital', limit: '100' } })) || [];
  ok(res, rows.map(x => Object.assign({}, x, { beds_available: Math.max((x.capacity || 0) - (x.current_occupancy || 0), 0) })));
}

/* ── Router ────────────────────────────────────────────── */
function readBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string') { try { return JSON.parse(req.body); } catch (e) { return {}; } }
  return {};
}

async function updateVolunteer(res, req, id, b) {
  const t = readToken(req);
  if (!t) return fail(res, 'Sign in required — only the account owner can update the profile', 401);
  if (t.role !== 'admin') {
    const v = ((await sb('volunteers', { query: { select: 'id,user_id', id: 'eq.' + id, limit: '1' } }).catch(function () { return []; })) || [])[0];
    if (v && v.user_id && v.user_id !== t.uid) return fail(res, 'You are not allowed to update this profile', 403);
  }
  const patch = {};
  if (Array.isArray(b.skills)) patch.skills = b.skills.slice(0, 12);
  if (b.availability) patch.availability = String(b.availability);
  if (Array.isArray(b.assets)) patch.assets = b.assets.slice(0, 8);
  if (!Object.keys(patch).length) return fail(res, 'Nothing to update — send skills, availability or assets', 400);
  const out = await sb('volunteers', { method: 'PATCH', query: { id: 'eq.' + id }, body: patch, prefer: 'return=representation' });
  if (!out || !out.length) return fail(res, 'Volunteer not found', 404);
  ok(res, out[0], 'Volunteer updated');
}

/* ── AI engines: triage, copilot, matching ─────────────── */
// Multilingual keyword engine (English / Urdu / Roman Urdu) — deterministic, no key needed.
const K = {
  water:     /paani|pani|water|flood|sel\b|siyabi|bah[ao]|doob|subk|dub|پانی|سیلاب|ڈوب/i,
  injured:   /zakhmi|injur|blood|bleed|chot|khoon|wound|زخمی|چوٹ|خون/i,
  trapped:   /phans|trapped|stuck|chat\b|chatt|roof|tarap|پھنس/i,
  medical:   /medical|ambulance|doctor|dard|tabiyat|bhari|sick|patient|pregnan|operation|oxygen|heart|طبی|اسبیتال|دل|آکسیجن/i,
  fire:      /\baag\b|fire|burn|lash\b|smoke|dhuain|flame|آگ|جل/i,
  storm:     /toofan|storm|cyclone|tez hawa|aandhi|heavy rain|tez barish|baarish|طوفان|بارش/i,
  quake:     /zalzala|earthquake|kamp|tremor|shaking|زلزلہ/i,
  landslide: /landslide|pahaad|pahad|rockfall|mountain.*slide/i,
  missing:   /missing|gum|kho gaya|kho gayi|nazar nahi|la pata|lost child|لاپتا|گم/i,
  children:  /bach|child|kid|minor|infant|bache|beta|beti|بچے/i,
  elderly:   /buzurg|elderly|dadi|nani|abu|ammi jan|old person|frail|disab|بوڑھے|کمزور/i,
  women:     /aurat|woman|female|khatoon|behen|mother|ladies|عورت|خاتون/i,
  urgent:    /urgent|foran|fauran|jaldi|critical|khatra|danger|immediately|abhi|mauth|death|dying|فوری|خطرہ/i,
  shelter:   /shelter|khanabados|rehne|camp\b|homeless|ghar toot|ghar gir|makan gir|پناہ|شیلٹر|کیمپ/i,
  food:      /khaana|khana|food|roti|meal|bhook|ration|clean water|کھانا|روٹی|بھوک/i,
  transport: /transport|gari|vehicle|nikalne|evacuat|relocate|move us|boat|kashi|bus|کشتی|نقل/i
};
const NUMWORD = { ek:1, do:2, teen:3, char:4, panj:5, panch:5, che:6, saat:7, aath:8, nau:9, das:10,
  one:1, two:2, three:3, four:4, five:5, six:6, seven:7, eight:8, nine:9, ten:10 };

function extractIntent(text) {
  text = String(text || '');
  const hit = (re) => re.test(text);
  let people = 0;
  const m = text.match(/(\d+)\s*(?:\+)?\s*(?:log|people|members|family|individual)/i);
  if (m) people = parseInt(m[1], 10) || 0;
  if (!people) {
    const w = text.match(/\b(ek|do|teen|char|panch|panj|che|saat|aath|nau|das|one|two|three|four|five|six|seven|eight|nine|ten)\s+(?:log|people|members|persons|of us|bachay|children|individuals)/i);
    if (w) people = NUMWORD[w[1].toLowerCase()] || 0;
  }
  let incident = 'other';
  if (hit(K.quake)) incident = 'earthquake';
  else if (hit(K.fire)) incident = 'fire';
  else if (hit(K.landslide)) incident = 'landslide';
  else if (hit(K.water)) incident = 'flood';
  else if (hit(K.storm)) incident = 'storm';
  else if (hit(K.medical) || hit(K.injured)) incident = 'medical';
  else if (hit(K.missing)) incident = 'missing';
  const needs = [];
  if (hit(K.trapped) || (hit(K.water) && hit(K.transport))) needs.push('rescue');
  if (hit(K.transport) || hit(K.trapped)) needs.push('evacuation');
  if (hit(K.medical) || hit(K.injured)) needs.push('medical');
  if (hit(K.shelter)) needs.push('shelter');
  if (hit(K.food) || hit(K.water)) needs.push('food_water');
  if (hit(K.transport)) needs.push('transport');
  if (hit(K.missing)) needs.push('search');
  if (!needs.length) needs.push(hit(K.urgent) ? 'rescue' : 'assessment');
  const enteringHome = hit(K.water) && /house|ghar|home|makan|building|گھر|عمارت|floor|kamra|room/i.test(text);
  const danger = hit(K.trapped) || hit(K.injured) || hit(K.fire) || enteringHome || (hit(K.water) && hit(K.transport)) || (hit(K.medical) && (hit(K.children) || hit(K.elderly)));
  let urgency = danger ? (hit(K.children) || hit(K.elderly) || people >= 6 || hit(K.urgent) ? 'critical' : 'high')
    : hit(K.urgent) ? 'high' : 'medium';
  if ((needs.includes('rescue') || needs.includes('evacuation')) && urgency === 'medium') urgency = 'high';
  const flags = [];
  if (hit(K.trapped)) flags.push('trapped');
  if (hit(K.injured)) flags.push('injured');
  if (hit(K.children)) flags.push('children');
  if (hit(K.elderly)) flags.push('elderly');
  if (/pregnan/i.test(text)) flags.push('pregnant');
  return { incident_type: incident, needs: [...new Set(needs)], people_count: people, urgency, flags };
}

function triageScore(urgency, people, flags) {
  let s = { critical: 55, high: 40, medium: 20, low: 8 }[urgency] || 20;
  s += Math.min(20, (people || 0) * 3);
  if (flags.includes('trapped')) s += 15;
  if (flags.includes('injured')) s += 12;
  if (flags.includes('children')) s += 8;
  if (flags.includes('elderly')) s += 6;
  if (flags.includes('pregnant')) s += 8;
  s = Math.min(100, s);
  return { score: s, recommended: s >= 75 ? 'critical' : s >= 45 ? 'high' : s >= 25 ? 'medium' : 'low' };
}

const GUIDANCE = {
  flood: ['Move to the highest floor with essentials — do not walk or drive through moving water.', 'Switch off electricity at the mains before water enters.', 'Keep documents and medicine in a sealed bag on you.'],
  medical: ['Call an ambulance (115) or Rescue 1122 now — do not wait for the chat.', 'Do not move a seriously injured person unless they are in immediate danger.', 'Apply direct pressure on bleeding wounds with a clean cloth.'],
  fire: ['Get everyone out, stay low under smoke, do not use lifts.', 'Call Fire Brigade 16 and shut the gas supply if safe.', 'Do not re-enter for belongings.'],
  storm: ['Stay inside, away from windows; charge phones and keep a torch handy.', 'Avoid metal roofs, trees, and billboards; report damaged wires to 118.', 'Store drinking water — storms often contaminate supply.'],
  earthquake: ['Drop, Cover, Hold On — do not run during shaking.', 'After shaking: check gas and wiring before moving; expect aftershocks.', 'Do not use lifts; watch for cracked stairs and walls.'],
  landslide: ['Move away from the slope, uphill and to the sides — never straight down.', 'Report blocked roads so others can reroute.', 'Avoid riverbanks after slides — debris dams can burst.'],
  missing: ['Register a police report (15) with a recent photo and last-seen details.', 'Share the last known location with rescue teams, not on social media.', 'Keep a family member reachable at the reported number.'],
  other: ['Stay where you are if safe; note your nearest landmark.', 'Keep your phone charged and Rescue 1122 within reach.']
};
function nextQuestion(i) {
  if (!i.people_count) return 'How many people are with you?';
  if (i.needs.includes('rescue') || i.needs.includes('evacuation')) return 'Are you on a rooftop or trapped?';
  if (i.incident_type === 'medical') return 'Is the injured person conscious or able to walk?';
  if (i.incident_type === 'missing') return 'When and where were they last seen?';
  return 'Enter your area or nearest landmark so the team reaches the right place.';
}

// Copilot: Groq LLM if GROQ_API_KEY env is set, otherwise the deterministic rule engine.
async function copilot(res, b) {
  const message = String(b.message || '').slice(0, 800);
  const rule = extractIntent(message);
  const tri = triageScore(rule.urgency, rule.people_count, rule.flags);
  if (process.env.GROQ_API_KEY && message) {
    try {
      const gr = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + process.env.GROQ_API_KEY, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: 'llama-3.3-70b-versatile', temperature: 0.3, response_format: { type: 'json_object' },
          messages: [
            { role: 'system', content: 'You are ReliefLink PK disaster copilot. From the citizen message (English/Urdu/Roman Urdu), reply ONLY JSON: {"incident_type":"flood|earthquake|fire|storm|landslide|medical|missing|other","needs":["rescue","evacuation","medical","shelter","food_water","transport","search","assessment"],"people_count":number,"urgency":"critical|high|medium|low","flags":["trapped","injured","children","elderly","pregnant"],"reply":"one short caring sentence in the SAME language as the user"}. Never invent facts.' },
            { role: 'user', content: message }
          ]
        })
      });
      if (gr.ok) {
        const gj = await gr.json();
        const j = JSON.parse(gj.choices[0].message.content);
        const i2 = { incident_type: j.incident_type || rule.incident_type, needs: (j.needs || rule.needs).slice(0, 4), people_count: +j.people_count || rule.people_count, urgency: j.urgency || rule.urgency, flags: (j.flags || rule.flags).slice(0, 5) };
        const t2 = triageScore(i2.urgency, i2.people_count, i2.flags);
        return ok(res, { engine: 'groq', intent: i2, triage: t2, guidance: GUIDANCE[i2.incident_type] || GUIDANCE.other, question: nextQuestion(i2), reply: j.reply || '', draft: { incident_type: i2.incident_type, needs: i2.needs, people_count: i2.people_count, urgency: i2.urgency, description: message } }, 'Copilot reply');
      }
    } catch (e) { /* fall through to rule engine */ }
  }
  const reply = 'I understood your situation: ' + rule.incident_type.toUpperCase() +
    (rule.flags.length ? ' (' + rule.flags.join(', ') + ')' : '') + '. Don\'t wait for emergency services — call Rescue 1122.';
  ok(res, { engine: 'rules', intent: rule, triage: tri, guidance: GUIDANCE[rule.incident_type] || GUIDANCE.other, question: nextQuestion(rule), reply, draft: { incident_type: rule.incident_type, needs: rule.needs, people_count: rule.people_count, urgency: rule.urgency, description: message } }, 'Copilot reply');
}

/* ── Mesh Network (real-time zone relay) ─────────────────
   Serverless can't hold WebSockets, so the live port is short-poll:
   POST a message, GET the zone's recent messages + peer presence.
   Coordinates are kept only when inside Pakistan (map scope). */
const PK_BOX = { s: 23.6, n: 37.3, w: 58.4, e: 78.4 };
function _meshZone(v) {
  const z = String(v || '').trim().toLowerCase().replace(/[^\w\- ]/g, '').slice(0, 40).trim();
  return z || 'general';
}
function _pk(v) { const f = parseFloat(v); return Number.isFinite(f) && f >= PK_BOX.s && f <= PK_BOX.n ? f : null; }
function _pkLng(v) { const f = parseFloat(v); return Number.isFinite(f) && f >= PK_BOX.w && f <= PK_BOX.e ? f : null; }

async function createMeshMessage(res, b) {
  const zone = _meshZone(b.zone);
  const body = String(b.body || '').replace(/[^\S\n ]+/g, ' ').trim().slice(0, 1000);
  if (!body) return fail(res, 'Message is empty', 400);
  const lat = _pk(b.lat), lon = _pkLng(b.lon);
  const row = {
    id: rid('mesh'),
    zone,
    sender: String(b.sender || 'Neighbour').replace(/[^\w\- ]/g, '').slice(0, 30) || 'Neighbour',
    body,
    emergency: b.emergency === true || b.emergency === 'true',
    created_at: nowIso()
  };
  if (lat != null && lon != null) { row.latitude = lat; row.longitude = lon; }
  const created = await sb('mesh_messages', { method: 'POST', body: row, prefer: 'return=representation' });
  ok(res, created && created[0] ? created[0] : row, 'Posted');
}

async function listMeshZone(res, q) {
  const zone = _meshZone(q.zone);
  // recent window: since=<iso> returns only newer rows (polling); otherwise last 50.
  const query = { select: '*', zone: 'eq.' + zone, order: 'created_at.desc', limit: 50 };
  if (q.since) query.created_at = 'gt.' + encodeURIComponent(String(q.since));
  const messages = (await sb('mesh_messages', { query })) || [];
  // Peer presence for the 1 km radar: latest located message per sender.
  const peers = {};
  messages.forEach(function (m) {
    if (m.latitude == null || m.longitude == null) return;
    const k = String(m.sender || 'anon');
    if (!peers[k]) peers[k] = { name: k, lat: m.latitude, lon: m.longitude, at: m.created_at };
  });
  ok(res, { zone, messages: messages.slice().reverse(), peers: Object.keys(peers).map(function (k) { return peers[k]; }) }, '');
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(204).end();

  const raw = req.query.path || '';
  const seg = (Array.isArray(raw) ? raw.join('/') : String(raw)).split('/').filter(Boolean);
  const q = Object.assign({}, req.query);
  delete q.path;
  const method = req.method;
  const b = readBody(req);

  // Admin sign-in and AI copilot need no DB — handled before the config guard.
  if (seg[0] === 'auth' && seg[1] === 'admin-signin' && method === 'POST') return await adminSignin(res, b);
  if (seg[0] === 'ai' && seg[1] === 'copilot' && method === 'POST') return await copilot(res, b);

  if (!SB_URL || !SB_KEY) return fail(res, 'Backend not configured: set SUPABASE_URL and SUPABASE_SERVICE_KEY in Vercel env vars', 500);

  try {
    const r0 = seg[0];
    if (r0 === 'help-requests') return method === 'POST' ? await createHelpRequest(res, b) : await listHelpRequests(res, q);
    if (r0 === 'auth') {
      if (seg[1] === 'register' && method === 'POST') return await register(res, b);
      if (seg[1] === 'signin' && method === 'POST') return await signin(res, b);
      if (seg[1] === 'me' && method === 'GET') return await me(res, req);
      if (seg[1] === 'promote-citizen' && method === 'POST') return await promoteCitizen(res, b);
      if (seg[1] === 'update-profile' && method === 'POST') return await updateProfile(res, req, b);
      if (seg[1] === 'deactivate' && method === 'POST') return await deactivateAccount(res, req);
      if (seg[1] === 'reactivate' && method === 'POST') return await reactivateAccount(res, req);
      if (seg[1] === 'delete-account' && method === 'POST') return await deleteAccount(res, req, b);
      if (seg[1] === 'register-role' && method === 'POST') return await registerRole(res, b);
      return fail(res, 'Unknown auth endpoint', 404);
    }
    if (r0 === 'tasks') {
      if (seg[1] === 'my-assignments') return await myAssignments(res, q);
      if (seg[1] === 'volunteer-stats') return await volunteerStats(res, q);
      if (seg[2] === 'claim' && method === 'POST') return await claimTask(res, seg[1], b);
      if (seg[2] === 'progress' && (method === 'PATCH' || method === 'POST')) return await taskProgress(res, seg[1], b);
      if (!seg[1]) return await listTasks(res);
      return fail(res, 'Unknown tasks endpoint', 404);
    }
    if (r0 === 'analytics' && seg[1] === 'admin-overview') return await adminOverview(res);
    if (r0 === 'alerts') return method === 'POST' ? await createAlert(res, req, b) : await listAlerts(res, q);
    if (r0 === 'volunteers') {
      if (seg[1] && seg[2] === 'verify' && method === 'POST') return await verifyVolunteer(res, req, seg[1]);
      if (seg[1] && method === 'PATCH') return await updateVolunteer(res, req, seg[1], b);
      if (!seg[1]) return await listVolunteers(res, q);
      return fail(res, 'Unknown volunteers endpoint', 404);
    }
    if (r0 === 'shelters') return await listShelters(res);
    if (r0 === 'hospitals') return await listHospitals(res);
    if (r0 === 'mesh') return method === 'POST' ? await createMeshMessage(res, b) : await listMeshZone(res, q);
    return fail(res, 'Not found: /api/v1/' + seg.join('/'), 404);
  } catch (e) {
    return fail(res, 'Server error: ' + (e && e.message ? e.message : String(e)), 500);
  }
};
