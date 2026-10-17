/* ReliefLink — live sync for the service dashboards
   (food, clothes, home, recovery, missing, tracking + their admin consoles)

   These pages used to keep their requests in localStorage only, which meant a
   citizen's request never left their own phone: an admin on another device saw
   nothing. This layer mirrors every record into the same help_requests table the
   command centre already reads, and pulls the team's status/agent changes back.

   localStorage stays the instant cache (the UI never waits on the network); the
   server is the source of truth. Fields that have no column (quantity, people,
   note, rider/host/team, mode…) ride along as one encoded token at the end of
   `description`, which is expanded again on every device.
*/
(function (w) {
  'use strict';

  var API = (w.RELIEF_API || ((w.location.hostname === 'localhost' || w.location.hostname === '127.0.0.1')
    ? 'https://relieflink-neon.vercel.app/api/v1' : '/api/v1')).replace(/\/$/, '');

  /* page step  <->  server status (same 4 stages, different names) */
  var TO_SERVER = { sent: 'pending', approved: 'assigned', on_the_way: 'in_progress', delivered: 'resolved' };
  var TO_STEP = { pending: 'sent', assigned: 'approved', in_progress: 'on_the_way', resolved: 'delivered' };
  var OPEN = '\u27e6rl:', CLOSE = '\u27e7';

  var CFG = null, SNAP = {}, CREATING = {}, TIMER = null;

  /* ── session (shared with the rest of the site through localStorage) ── */
  function sess() { try { return JSON.parse(localStorage.getItem('rl_session') || 'null'); } catch (e) { return null; } }
  function token() { var s = sess(); return (s && s.token) || ''; }
  function isAdmin() { var s = sess(); return !!(s && s.user && s.user.role === 'admin'); }
  function hdr(extra) {
    var h = { 'Content-Type': 'application/json' }, t = token();
    if (t) h.Authorization = 'Bearer ' + t;
    for (var k in (extra || {})) h[k] = extra[k];
    return h;
  }

  function read(key) { try { return JSON.parse(localStorage.getItem(key || CFG.listKey)) || []; } catch (e) { return []; } }
  function write(list, key) { try { localStorage.setItem(key || CFG.listKey, JSON.stringify(list)); } catch (e) {} }
  function stamp(id, srvId, key) {
    var list = read(key), hit = false;
    list.forEach(function (r) { if (r.id === id) { r.srvId = srvId; hit = true; } });
    if (hit) write(list, key);
  }

  /* ── record <-> description token ── */
  function pack(rec, cfg) {
    var p = {}, k;
    for (k in rec) if (k !== 'srvId') p[k] = rec[k];
    // keep free-text fields short so the encoded token always fits in `description`
    for (k in p) { if (typeof p[k] === 'string' && p[k].length > 140) p[k] = p[k].slice(0, 140); }
    var sum = '';
    try { sum = String((cfg.summary ? cfg.summary(rec) : (rec.sum || '')) || '').replace(OPEN, '').slice(0, 200); } catch (e) { sum = ''; }
    var body = '';
    try { body = encodeURIComponent(JSON.stringify(p)); } catch (e) { body = ''; }
    if (body.length > 1500) sum = '';                       // the token matters more than the readable summary
    if (body.length > 1700) body = body.slice(0, 1700);     // absurd case: the row is still stored, just not replayable
    return (sum ? sum + ' ' : '') + OPEN + body + CLOSE;
  }
  function unpack(desc) {
    var s = String(desc || ''), i = s.indexOf(OPEN);
    if (i < 0) return null;
    var end = s.indexOf(CLOSE, i);
    try { return JSON.parse(decodeURIComponent(end > i ? s.slice(i + OPEN.length, end) : s.slice(i + OPEN.length))); } catch (e) { return null; }
  }
  function human(desc) {
    var s = String(desc || ''), i = s.indexOf(OPEN);
    return (i < 0 ? s : s.slice(0, i)).trim();
  }

  /* ── transport ── */
  function call(method, url, body) {
    return fetch(url, { method: method, headers: hdr(), body: body ? JSON.stringify(body) : undefined })
      .then(function (r) {
        return r.json().catch(function () { return {}; }).then(function (j) {
          return { ok: r.ok, status: r.status, data: j && j.success ? j.data : null, message: j && j.message };
        });
      })
      .catch(function () { return { ok: false, status: 0, data: null }; });
  }
  function getJSON(url) {
    return fetch(url, { headers: hdr() })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (j) { return j && j.success ? j.data : null; })
      .catch(function () { return null; });
  }

  function create(rec, cfg) {
    if (CREATING[rec.id]) return Promise.resolve(null);
    CREATING[rec.id] = true;
    var phone = rec.phone || rec.rphone || '';
    var body = {
      category: cfg.category, user_id: rec.userId || null,
      full_name: rec.name || rec.rname || rec.pname || 'Citizen',
      phone: phone,
      city: rec.address || rec.seenPlace || rec.currentArea || rec.city || '',
      description: pack(rec, cfg), urgency: rec.urgent || rec.urgency === 'urgent' || rec.priority === 'high' ? 'critical' : 'high'
    };
    return call('POST', API + '/help-requests', body).then(function (r) {
      delete CREATING[rec.id];
      if (r && r.ok && r.data && r.data.id) {
        rec.srvId = r.data.id;
        SNAP[rec.id] = rec.updatedAt || rec.createdAt;
        stamp(rec.id, r.data.id, cfg.listKey);
        return r.data.id;
      }
      return null;
    });
  }
  function push(rec, cfg) {
    if (!rec.srvId) return create(rec, cfg);
    var body = {
      status: TO_SERVER[rec.status] || 'pending',
      description: pack(rec, cfg),
      phone: rec.phone || rec.rphone || '',
      device: rec.userId || ''            // proves ownership for the standalone pages (no login needed)
    };
    return call('PATCH', API + '/help-requests/' + encodeURIComponent(rec.srvId), body).then(function (r) {
      if (r && r.ok) SNAP[rec.id] = rec.updatedAt || rec.createdAt;   // local record already holds exactly what we sent
      return !!(r && r.ok);
    });
  }

  /* ── two-way merge: newer side wins, unsent local writes are flushed ── */
  function syncInto(cfg) {
    if (!API || !navigator.onLine) return Promise.resolve(read(cfg.listKey));
    var key = cfg.listKey;
    var url = API + '/help-requests?category=' + encodeURIComponent(cfg.category) + '&limit=300';
    if (cfg.mine) {
      var uid = typeof cfg.uid === 'function' ? cfg.uid() : (cfg.uid || '');
      if (uid) url += '&user_id=' + encodeURIComponent(uid);
    }
    return getJSON(url).then(function (rows) {
      if (!Array.isArray(rows)) return read(key);      // server unreachable — leave the device cache alone
      var local = read(key), server = {}, res = [], i;
      for (i = 0; i < rows.length; i++) {
        var p = unpack(rows[i].description);
        if (!p || !p.id) continue;                      // request raised in the main citizen app — not this page's shape
        server[p.id] = { p: p, row: rows[i], at: rows[i].updated_at || rows[i].created_at, step: TO_STEP[rows[i].status] };
      }
      for (i = 0; i < local.length; i++) {
        var L = local[i], S = server[L.id];
        if (!S) {
          if (!L.srvId || CREATING[L.id]) res.push(L);  // not on the server yet -> will be created below
          continue;
        }
        delete server[L.id];
        var localAt = Date.parse(L.updatedAt || L.createdAt || '') || 0;
        var serverAt = Date.parse(S.at || '') || 0;
        if (localAt > serverAt) { res.push(L); if (!CREATING[L.id]) (L.srvId ? push : create)(L, cfg); }
        else res.push(Object.assign({}, S.p, { status: S.step || S.p.status, updatedAt: S.at, srvId: S.row.id }));
      }
      for (i in server) res.push(Object.assign({}, server[i].p, { status: server[i].step || server[i].p.status, updatedAt: server[i].at, srvId: server[i].row.id }));
      res.sort(function (a, b) { return (Date.parse(b.createdAt || 0) || 0) - (Date.parse(a.createdAt || 0) || 0); });
      write(res, key);
      res.forEach(function (r) { if (r.srvId) SNAP[r.id] = r.updatedAt || r.createdAt; });
      // a citizen's own device is authoritative for its unsent requests — flush anything
      // that was filed while offline (admin consoles keep their local notes private)
      if (cfg.mine) res.forEach(function (r) { if (!r.srvId && !CREATING[r.id]) create(r, cfg); });
      return res;
    });
  }

  /* flush anything the page just changed (called right after the page saves its list) */
  function after(list, cfg) {
    if (!API) return;
    (list || read(cfg.listKey)).forEach(function (rec) {
      var at = rec.updatedAt || rec.createdAt || '';
      if (!at || SNAP[rec.id] === at) return;
      SNAP[rec.id] = at;
      if (rec.srvId) push(rec, cfg); else create(rec, cfg);
    });
  }

  /* ── admin session bar (the standalone consoles have no login of their own) ── */
  function loginBar(cfg) {
    if (!cfg.admin || isAdmin() || !API) return;
    var bar = document.createElement('div');
    bar.style.cssText = 'position:fixed;left:0;right:0;bottom:0;z-index:99;display:flex;gap:8px;flex-wrap:wrap;'
      + 'align-items:center;justify-content:center;padding:10px 12px;background:#12251C;color:#F5EEDB;'
      + 'font:600 13px/1.4 "Plus Jakarta Sans",system-ui,sans-serif;box-shadow:0 -6px 20px rgba(0,0,0,.25)';
    bar.innerHTML = '<span>Sign in as the response team to update these requests</span>'
      + '<input id="rlLiveEmail" type="email" placeholder="admin email" style="padding:8px;border-radius:8px;border:0;font:inherit">'
      + '<input id="rlLivePw" type="password" placeholder="password" style="padding:8px;border-radius:8px;border:0;font:inherit">'
      + '<button id="rlLiveGo" style="padding:8px 14px;border:0;border-radius:8px;background:#C9A227;color:#12251C;font:inherit;cursor:pointer">Sign in</button>'
      + '<span id="rlLiveMsg" role="alert" style="color:#FFB4B4;font-weight:700;max-width:46%"></span>';
    bar.appendChild(document.createTextNode(''));
    document.body.appendChild(bar);
    document.getElementById('rlLiveGo').onclick = function () {
      var email = document.getElementById('rlLiveEmail').value.trim();
      var password = document.getElementById('rlLivePw').value;
      var msg = document.getElementById('rlLiveMsg');
      var btn = this;
      if (!email || !password) { msg.textContent = 'Enter the admin email and password.'; return; }
      msg.textContent = '';
      btn.textContent = 'Signing in…';
      call('POST', API + '/auth/admin-signin', { email: email, password: password }).then(function (r) {
        if (r && r.ok && r.data && r.data.token) {
          try { localStorage.setItem('rl_session', JSON.stringify(r.data)); } catch (e) {}
          bar.remove();
          syncInto(cfg).then(function () { if (cfg.onChanged) cfg.onChanged(); });
          return;
        }
        btn.textContent = 'Sign in';
        btn.style.background = '#EF5B5B';
        msg.textContent = (r && r.status === 0)
          ? 'No connection — sign in again when you are back online.'
          : (r && r.message) || 'Sign in failed (' + (r && r.status) + ')';
        setTimeout(function () { btn.style.background = '#C9A227'; }, 2600);
      }.bind(this));
    };
  }

  /* ── public API ── */
  w.RLive = {
    TO_SERVER: TO_SERVER, TO_STEP: TO_STEP, human: human,

    /* bind({category, listKey, uid, summary, onChanged, mine, admin}) */
    bind: function (cfg) {
      CFG = Object.assign({ mine: false, admin: false, listKey: 'relieflink_requests' }, cfg || {});
      if (!CFG.uid) CFG.uid = function () { try { return localStorage.getItem('relieflink_user_id') || ''; } catch (e) { return ''; } };
      loginBar(CFG);
      return w.RLive;
    },
    sync: function (cfg) { return syncInto(cfg || CFG); },
    after: function (list) { after(list, CFG); },
    /* re-pull while the page is open so the citizen sees the team's updates */
    watch: function (ms) {
      if (TIMER) return;
      var tick = function () { if (!document.hidden) syncInto(CFG).then(function () { if (CFG.onChanged) CFG.onChanged(); }); };
      TIMER = setInterval(tick, ms || 25000);
      document.addEventListener('visibilitychange', function () { if (!document.hidden) tick(); });
    },
    /* tracking page: several services on one screen */
    pullInto: function (cfg) { return syncInto(Object.assign({ mine: true, listKey: 'relieflink_requests' }, cfg || {})); },
    multi: function (list) { return Promise.all((list || []).map(function (c) { return syncInto(c); })); },
    send: function (rec, cfg) { return (rec && rec.srvId ? push : create)(rec, cfg); },
    isAdmin: isAdmin, token: token
  };
})(window);
