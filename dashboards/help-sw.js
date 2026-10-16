/* ReliefLink Help — Service Worker
   Purpose: back the URGENT alert Notifications. When a request escalates (status changes
   or admin marks it urgent), the page calls registration.showNotification(...). This SW
   handles the click and focuses / opens the app on that specific request.
*/
var CACHE = 'rl-help-v1';

self.addEventListener('install', function(){ self.skipWaiting(); });
self.addEventListener('activate', function(e){ e.waitUntil(self.clients.claim()); });

/* Tapping the notification → open (or focus) the citizen app on that request */
self.addEventListener('notificationclick', function(e){
  e.notification.close();
  var d = e.notification.data || {};
  var url = 'help.html' + (d.id ? '#urgent=' + encodeURIComponent(d.id) : '#myrequests');
  e.waitUntil(
    self.clients.matchAll({ type:'window', includeUncontrolled:true }).then(function(list){
      for (var i=0;i<list.length;i++){
        var c = list[i];
        try{
          if ('url' in c && /\/dashboards\/help\.html/.test(c.url)){
            /* tell the running app to jump to that request */
            c.postMessage({ type:'rl:open-urgent', id: d.id || null });
            return c.focus();
          }
        }catch(_){}
      }
      return self.clients.openWindow(url);
    })
  );
});

/* Optional: allow page to ask SW to show a notification (survives some tab-hidden cases) */
self.addEventListener('message', function(e){
  var m = e.data || {};
  if (m.type === 'rl:notify'){
    e.waitUntil(self.registration.showNotification(m.title || 'ReliefLink', {
      body: m.body || '', tag: m.tag || ('rl-'+Date.now()),
      icon: m.icon || undefined, badge: m.badge || undefined,
      data: m.data || {}, requireInteraction: !!m.sticky, renotify: true
    }));
  }
});

/* Network-first for html/css/js (dev stays fresh); fall back to cache when offline */
self.addEventListener('fetch', function(e){
  var req = e.request;
  if (req.method !== 'GET') return;
  var u;
  try { u = new URL(req.url); } catch(_){ return; }
  if (u.origin !== location.origin) return;
  if (/\.(html|css|js)$/.test(u.pathname)){
    e.respondWith(
      fetch(req).then(function(res){
        try{ caches.open(CACHE).then(function(c){ c.put(req, res.clone()); }); }catch(_){ }
        return res;
      }).catch(function(){ return caches.match(req); })
    );
  }
});
