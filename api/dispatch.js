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
const HR_STATUS = ['pending', 'assigned', 'in_progress', 'resolved'];
const HR_PRIORITY = ['low', 'medium', 'high', 'critical'];
const TASK_STATUS = ['open', 'claimed', 'in_progress', 'completed'];
async function createHelpRequest(res, b) {
  const p = normPKPhone(b.phone); // never reject an emergency request, just clean the number
  const row = {
    id: rid('RFL'), user_id: b.user_id || null, full_name: b.full_name || 'Citizen',
    phone: p || String(b.phone || '').slice(0, 20), city: b.city || '', category: b.category || 'special',
    description: String(b.description || '').slice(0, 2000), urgency: b.urgent ? 'critical' : (b.urgency || 'high'),
    status: 'pending', latitude: b.latitude != null ? b.latitude : null,
    longitude: b.longitude != null ? b.longitude : null, created_at: nowIso(), updated_at: nowIso()
  };
  const out = await sb('help_requests', { method: 'POST', body: row, prefer: 'return=representation' });
  ok(res, (out && out[0]) || row, 'Request received');
}

async function listHelpRequests(res, q) {
  const limit = Math.min(parseInt(q.limit, 10) || 100, 500);
  const query = { select: '*', order: 'created_at.desc', limit: String(limit) };
  if (q.user_id) query.user_id = 'eq.' + String(q.user_id).slice(0, 60);
  if (q.phone) query.phone = 'eq.' + (normPKPhone(q.phone) || String(q.phone).slice(0, 20));
  if (q.status) query.status = 'in.(' + String(q.status).split(',').filter(s => HR_STATUS.indexOf(s.trim()) >= 0).map(s => s.trim()).join(',') + ')';
  if (q.category) {
    const cats = String(q.category).split(',').map(c => c.trim()).filter(c => CAT_LABEL[c] !== undefined);
    if (cats.length) query.category = 'in.(' + cats.join(',') + ')';
  }
  if (q.id) query.id = 'eq.' + String(q.id).slice(0, 40);
  ok(res, (await sb('help_requests', { query })) || []);
}

// Workflow transitions the admin queue can write, in order.
async function updateHelpRequest(res, req, id, b) {
  const t = readToken(req);
  const status = String(b.status || '').toLowerCase();
  if (status && HR_STATUS.indexOf(status) < 0) return fail(res, 'Status must be pending, assigned, in_progress or resolved', 400);
  const sid = encodeURIComponent(String(id).slice(0, 40));
  const found = await sb('help_requests', { query: { select: 'id,user_id,status,phone', id: 'eq.' + sid, limit: '1' } }).catch(function () { return []; });
  const cur = (found || [])[0];
  if (!cur) return fail(res, 'Request not found', 404);
  const admin = !!(t && t.role === 'admin');
  // A citizen may only close their own request ("I am safe / no longer need help").
  // Ownership is the account id, the phone number they were given, or the device id
  // the standalone service pages file their requests under (help_requests.user_id).
  const owns = !!t && String(cur.user_id) === String(t.uid);
  const dev = String(b.device || '').slice(0, 60);
  const ownsDevice = !!dev && !!cur.user_id && String(cur.user_id) === dev;
  const samePhone = !!(b.phone && cur.phone) && normPKPhone(b.phone) != null && normPKPhone(b.phone) === normPKPhone(cur.phone);
  if (!admin) {
    if (!owns && !ownsDevice && !samePhone) return fail(res, 'You can only update your own request', 403);
    if (status !== 'resolved') return fail(res, 'Only the response team can move this request forward', 403);
  }
  const patch = { updated_at: nowIso() };
  if (status) patch.status = status;
  // The service dashboards keep their rider/host/team details inside the description,
  // so the response team can also rewrite it — admins only, always length-capped.
  if (b.description != null && admin) {
    patch.description = String(b.description).slice(0, 2000);
    if (!status) patch.status = cur.status;   // keep the row unchanged when only notes moved
  }
  const out = await sb('help_requests', { method: 'PATCH', query: { id: 'eq.' + sid, select: '*' }, body: patch, prefer: 'return=representation' });
  if (!out || !out.length) return fail(res, 'Request not found', 404);
  ok(res, out[0], status ? 'Request marked ' + (ST_LABEL[status] || status) : 'Request updated');
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

async function listTasks(res, q) {
  const query = { select: '*', order: 'priority.desc,created_at.desc', limit: '200' };
  if (q.status) query.status = 'eq.' + String(q.status).slice(0, 20);
  if (q.request_id) query.request_id = 'eq.' + String(q.request_id).slice(0, 40);
  ok(res, (await sb('volunteer_tasks', { query })) || []);
}

// Admin dispatch: turn a help request (or any job) into a volunteer task, optionally
// handed straight to a matched volunteer — then the request moves to "assigned".
async function createTask(res, req, b) {
  const t = readToken(req);
  if (!t) return fail(res, 'Sign in required — only the response team can create tasks', 401);
  const title = String(b.title || '').trim().slice(0, 160);
  if (!title) return fail(res, 'Task title is required', 400);
  const vol = String(b.assigned_volunteer_id || '').slice(0, 40);
  const row = {
    id: rid('task'),
    request_id: b.request_id ? String(b.request_id).slice(0, 40) : null,
    title: title,
    category: String(b.category || 'special').slice(0, 30),
    city: String(b.city || '').slice(0, 80),
    distance_km: Math.min(2000, +b.distance_km || 0),
    skills_needed: (Array.isArray(b.skills_needed) ? b.skills_needed : []).slice(0, 10).map(String),
    priority: HR_PRIORITY.indexOf(String(b.priority || '').toLowerCase()) >= 0 ? String(b.priority).toLowerCase() : 'medium',
    status: vol ? 'claimed' : 'open',
    assigned_volunteer_id: vol || null,
    progress_note: String(b.progress_note || '').slice(0, 500),
    created_at: nowIso(), updated_at: nowIso()
  };
  if (vol) row.completed_at = null;
  let out = null;
  try {
    out = await sb('volunteer_tasks', { method: 'POST', body: row, prefer: 'return=representation' });
  } catch (e) {
    // Older task tables may not carry every optional column — retry with the core fields.
    const min = { id: row.id, title: row.title, category: row.category, city: row.city, priority: row.priority,
      status: row.status, assigned_volunteer_id: row.assigned_volunteer_id, created_at: row.created_at, updated_at: row.updated_at };
    if (row.request_id) min.request_id = row.request_id;
    try { out = await sb('volunteer_tasks', { method: 'POST', body: min, prefer: 'return=representation' }); }
    catch (e2) { return fail(res, 'Could not save the task — volunteer_tasks table needs to be created (db/migrations/002)', 500); }
  }
  // Keep the citizen's tracker honest: a dispatched request is no longer just "pending".
  if (row.request_id) {
    await sb('help_requests', { method: 'PATCH', query: { id: 'eq.' + encodeURIComponent(row.request_id) },
      body: { status: 'assigned', updated_at: nowIso() }, prefer: 'return=representation' }).catch(function () {});
  }
  ok(res, (out && out[0]) || row, vol ? 'Task dispatched to volunteer' : 'Task opened for volunteers');
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
  const task = (out && out[0]) || patch;
  if (task.request_id) {
    await sb('help_requests', { method: 'PATCH', query: { id: 'eq.' + encodeURIComponent(String(task.request_id)) }, body: { status: 'assigned', updated_at: nowIso() } }).catch(function () {});
  }
  ok(res, task, 'Task claimed');
}
async function taskProgress(res, id, b) {
  const status = String(b.status || 'in_progress').toLowerCase();
  if (TASK_STATUS.indexOf(status) < 0) return fail(res, 'Status must be open, claimed, in_progress or completed', 400);
  const patch = { status: status, progress_note: b.progress_note || '', updated_at: nowIso() };
  if (status === 'completed') patch.completed_at = nowIso();
  const out = await sb('volunteer_tasks', { method: 'PATCH', query: { id: 'eq.' + id, select: '*' }, body: patch, prefer: 'return=representation' });
  const task = (out && out[0]) || patch;
  // A finished job closes the citizen's request; work started shows as in progress.
  if (task.request_id) {
    const linked = status === 'completed' ? 'resolved' : (status === 'in_progress' || status === 'claimed') ? 'in_progress' : null;
    if (linked) await sb('help_requests', { method: 'PATCH', query: { id: 'eq.' + encodeURIComponent(String(task.request_id)) }, body: { status: linked, updated_at: nowIso() } }).catch(function () {});
  }
  ok(res, task, 'Progress saved');
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
  medical:   /medical|ambulance|doctor|dard|tabiyat|bhari|sick|patient|pregnan|operation|oxygen|heart|fever|bukhaar|bukhar|behoosh|طبی|اسبیتال|دل|آکسیجن/i,
  fire:      /\baag\b|fire|burn|lash\b|smoke|dhuain|flame|آگ|جل/i,
  storm:     /toofan|storm|cyclone|tez hawa|aandhi|heavy rain|barish|baarish|barsaat|\brain\b|طوفان|بارش/i,
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

/* Copilot LLM chain: Gemini if GEMINI_API_KEY is set, then Groq if GROQ_API_KEY is
   set, then Pollinations (free, no key) so the chat always answers with a real model.
   Keys belong in Vercel env vars — never commit them, this repository is public.
   gemini-2.0-flash / gemini-2.5-flash are retired for newer keys and the live aliases
   answer 503 when Google is busy, so each provider falls through to the next. */
const GEMINI_MODELS = ['gemini-flash-latest', 'gemini-3.5-flash', 'gemini-flash-lite-latest'];
const LLM_MODELS = ['openai-fast', 'openai'];   // free tier = 1 reply / 30 s per IP, so keep the list short and quick
const CP_SYSTEM = 'You are ReliefLink PK disaster copilot. The citizen is writing from a disaster zone in Pakistan, in English, Urdu or Roman Urdu. Reply ONLY JSON, no prose around it: {"incident_type":"flood|earthquake|fire|storm|landslide|medical|missing|other","needs":["rescue","evacuation","medical","shelter","food_water","transport","search","assessment"],"people_count":number,"urgency":"critical|high|medium|low","flags":["trapped","injured","children","elderly","pregnant"],"reply":"one short caring sentence"}. Write reply in the SAME script the user used: Roman Urdu in Latin letters for Roman Urdu (e.g. "Allah aap ko hifazat mein rakhe"), Urdu script for Urdu, English for English — never Devanagari. Vary the wording each time, answer what they just said, never repeat yourself, never invent facts, never claim help has been dispatched.';
const CP_NEEDS = ['rescue', 'evacuation', 'medical', 'shelter', 'food_water', 'transport', 'search', 'assessment'];
const CP_TYPES = ['flood', 'earthquake', 'fire', 'storm', 'landslide', 'medical', 'missing', 'other'];
const CP_URGENCY = ['critical', 'high', 'medium', 'low'];
const CP_FLAGS = ['trapped', 'injured', 'children', 'elderly', 'pregnant'];

function parseJsonLoose(text) {
  const s = String(text || '').replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/, '').trim();
  if (!s) return null;
  try { return JSON.parse(s); } catch (e) { /* fall through */ }
  const a = s.indexOf('{'), b = s.lastIndexOf('}');
  if (a >= 0 && b > a) { try { return JSON.parse(s.slice(a, b + 1)); } catch (e) { return null; } }
  return null;
}

function toOpenAiMessages(message, history) {
  const msgs = [{ role: 'system', content: CP_SYSTEM }];
  (Array.isArray(history) ? history : []).slice(-6).forEach(function (h) {
    const text = String((h && h.text) || '').slice(0, 800);
    if (text) msgs.push({ role: h.role === 'model' ? 'assistant' : 'user', content: text });
  });
  msgs.push({ role: 'user', content: message });
  return msgs;
}

function timeoutSignal(ms) {
  return typeof AbortSignal !== 'undefined' && AbortSignal.timeout ? AbortSignal.timeout(ms) : undefined;
}

// Returns the parsed model answer (with _model), or null so the caller can try the next provider.
async function geminiReply(message, history) {
  const key = process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY;
  if (!key || !message) return null;
  const contents = [];
  (Array.isArray(history) ? history : []).slice(-6).forEach(function (h) {
    const text = String((h && h.text) || '').slice(0, 800);
    if (text) contents.push({ role: h.role === 'model' ? 'model' : 'user', parts: [{ text: text }] });
  });
  contents.push({ role: 'user', parts: [{ text: message }] });
  const models = (process.env.GEMINI_MODEL ? [String(process.env.GEMINI_MODEL)] : []).concat(GEMINI_MODELS);
  for (const model of models) {
    try {
      const r = await fetch('https://generativelanguage.googleapis.com/v1beta/models/' + model + ':generateContent?key=' + encodeURIComponent(key), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          system_instruction: { parts: [{ text: CP_SYSTEM }] },
          contents: contents,
          // thinking models spend this budget on hidden tokens too — 400 truncated the JSON
          generationConfig: { temperature: 0.9, topP: 0.95, maxOutputTokens: 2048, responseMimeType: 'application/json' }
        }),
        signal: timeoutSignal(14000)
      });
      if (!r.ok) continue;
      const j = await r.json();
      const parts = (((j.candidates || [])[0] || {}).content || {}).parts || [];
      const parsed = parseJsonLoose(parts.map(function (p) { return p.text || ''; }).join(''));
      if (parsed && parsed.reply) { parsed._model = model; return parsed; }
    } catch (e) { /* busy, retired or timed out — try the next alias */ }
  }
  return null;
}

// Any OpenAI-compatible chat endpoint: Groq, or free Pollinations (no key).
const CP_CACHE = new Map();   // same question twice inside 5 min must not burn the free quota
function cacheKey(message) { return String(message).toLowerCase().replace(/[^a-z0-9\u0600-\u06ff ]/g, '').trim().slice(0, 160); }

async function openAiReply(url, headers, models, message, history, tag, errs) {
  if (!message) return null;
  const ck = tag + ':' + cacheKey(message);
  const hit = CP_CACHE.get(ck);
  if (hit && Date.now() - hit.at < 300000) { const c = Object.assign({}, hit.g); c._cached = true; return c; }
  const msgs = toOpenAiMessages(message, history);
  for (const model of models) {
    try {
      const r = await fetch(url, {
        method: 'POST',
        headers: Object.assign({ 'Content-Type': 'application/json' }, headers || {}),
        body: JSON.stringify({ model: model, messages: msgs, temperature: 0.9, seed: Math.floor(Math.random() * 1e9) }),
        signal: timeoutSignal(13000)
      });
      if (!r.ok) { if (errs) errs.push(tag + ':' + model + ' HTTP ' + r.status + ' ' + String(await r.text()).slice(0, 120)); continue; }
      const j = await r.json();
      const choice = (j.choices || [])[0];
      const text = choice && choice.message ? choice.message.content : '';
      const parsed = parseJsonLoose(text);
      if (parsed && parsed.reply) {
        parsed._model = model; parsed._engine = tag;
        if (CP_CACHE.size > 60) CP_CACHE.clear();
        CP_CACHE.set(ck, { at: Date.now(), g: parsed });
        return parsed;
      }
      if (errs) errs.push(tag + ':' + model + ' unparseable ' + String(text).slice(0, 120));
    } catch (e) { /* rate limited or down — try the next model */
      if (errs) errs.push(tag + ':' + model + ' ' + (e && e.name ? e.name : 'error') + ' ' + String(e && e.message || '').slice(0, 90));
    }
  }
  return null;
}

// Copilot: first live LLM that answers wins, otherwise the deterministic rule engine.
async function copilot(res, b) {
  const message = String(b.message || '').slice(0, 800);
  const rule = extractIntent(message);
  const tri = triageScore(rule.urgency, rule.people_count, rule.flags);
  const errs = [];
  const g = (await geminiReply(message, b.history)) ||
    (process.env.GROQ_API_KEY ? await openAiReply('https://api.groq.com/openai/v1/chat/completions', { Authorization: 'Bearer ' + process.env.GROQ_API_KEY }, ['llama-3.3-70b-versatile'], message, b.history, 'groq', errs) : null) ||
    (process.env.LLM_OFFLINE === '1' ? null : await openAiReply('https://text.pollinations.ai/openai?referrer=relieflink', {}, (process.env.LLM_MODELS || LLM_MODELS.join(',')).split(','), message, b.history, 'live', errs));
  if (g) {
    const label = g._engine === 'groq' ? 'Groq AI' : g._engine === 'live' ? 'Live AI' : 'Gemini AI';
    const i2 = {
      incident_type: CP_TYPES.indexOf(g.incident_type) >= 0 ? g.incident_type : rule.incident_type,
      needs: (Array.isArray(g.needs) ? g.needs : rule.needs).filter(function (n) { return CP_NEEDS.indexOf(n) >= 0; }).slice(0, 4),
      people_count: Math.min(99, +g.people_count || rule.people_count),
      urgency: CP_URGENCY.indexOf(g.urgency) >= 0 ? g.urgency : rule.urgency,
      flags: (Array.isArray(g.flags) ? g.flags : rule.flags).filter(function (f) { return CP_FLAGS.indexOf(f) >= 0; }).slice(0, 5)
    };
    if (!i2.needs.length) i2.needs = rule.needs;
    const t2 = triageScore(i2.urgency, i2.people_count, i2.flags);
    return ok(res, { engine: g._engine || 'gemini', engineLabel: label, model: g._model, intent: i2, triage: t2, guidance: GUIDANCE[i2.incident_type] || GUIDANCE.other, question: nextQuestion(i2), reply: String(g.reply).slice(0, 300), draft: { incident_type: i2.incident_type, needs: i2.needs, people_count: i2.people_count, urgency: i2.urgency, description: message } }, 'Copilot reply');
  }
  const LABEL = { flood: 'flooding', earthquake: 'an earthquake', fire: 'a fire', storm: 'a storm or heavy rain', landslide: 'a landslide', medical: 'a medical emergency', missing: 'a missing person', other: 'an emergency' };
  const reply = 'This sounds like ' + (LABEL[rule.incident_type] || 'an emergency') +
    (rule.flags.length ? ' with ' + rule.flags.join(', ') : '') + '. Call Rescue 1122 now and stay on this channel — the AI helper is offline right now, so these are keyword-based answers.';
  ok(res, { engine: 'rules', engineLabel: 'Offline helper', aiDebug: errs, intent: rule, triage: tri, guidance: GUIDANCE[rule.incident_type] || GUIDANCE.other, question: nextQuestion(rule), reply, draft: { incident_type: rule.incident_type, needs: rule.needs, people_count: rule.people_count, urgency: rule.urgency, description: message } }, 'Copilot reply');
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
  // The relay table is optional (db/migrations/004_mesh.sql) — never 500 a citizen's message over it.
  try {
    const created = await sb('mesh_messages', { method: 'POST', body: row, prefer: 'return=representation' });
    return ok(res, created && created[0] ? created[0] : row, 'Posted');
  } catch (e) {
    ok(res, Object.assign({ queued: true }, row), 'Mesh relay storage is not configured — message kept on this device');
  }
}

async function listMeshZone(res, q) {
  const zone = _meshZone(q.zone);
  // recent window: since=<iso> returns only newer rows (polling); otherwise last 50.
  const query = { select: '*', zone: 'eq.' + zone, order: 'created_at.desc', limit: 50 };
  if (q.since) query.created_at = 'gt.' + encodeURIComponent(String(q.since));
  let messages = [];
  try {
    messages = (await sb('mesh_messages', { query })) || [];
  } catch (e) {
    // 004_mesh.sql not applied yet — an empty zone is a working answer, not a server error.
    return ok(res, { zone, messages: [], peers: [], relay: 'unavailable' }, 'Mesh relay not configured');
  }
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
    if (r0 === 'help-requests') {
      if (seg[1] && method === 'PATCH') return await updateHelpRequest(res, req, seg[1], b);
      if (seg[1] && method === 'GET') { q.id = seg[1]; return await listHelpRequests(res, q); }
      return method === 'POST' ? await createHelpRequest(res, b) : await listHelpRequests(res, q);
    }
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
      if (!seg[1] && method === 'POST') return await createTask(res, req, b);
      if (!seg[1]) return await listTasks(res, q);
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
