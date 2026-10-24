// Keeps the page and the last device list it loaded, so the installed app opens without a connection.
// Network first: online it's always the live Pi; the saved copy is only used when the Pi can't be
// reached. Saved copies carry X-NetWatch-Saved (when they were fetched) so the page can say so.
const CACHE = "netwatch-1";
const SAVED = ["/", "/api/devices", "/api/events?limit=200", "/api/settings"];
const WAIT_MS = 6000;  // weak signal: give up on the Pi after this and show the saved copy

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(["/manifest.webmanifest", "/icon-192.png", "/icon-512.png", "/favicon.svg"])));
  self.skipWaiting();
});

self.addEventListener("activate", (e) => {
  e.waitUntil(caches.keys()
    .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
    .then(() => self.clients.claim()));
});

async function save(cache, key, r) {
  const headers = new Headers(r.headers);
  headers.set("X-NetWatch-Saved", new Date().toISOString());
  await cache.put(key, new Response(await r.blob(), { status: r.status, headers }));
}

async function networkFirst(req, key) {
  const cache = await caches.open(CACHE);
  try {
    const r = await Promise.race([fetch(req),
      new Promise((_, no) => setTimeout(() => no(new Error("timed out")), WAIT_MS))]);
    if (r.ok) await save(cache, key, r.clone());
    return r;
  } catch (err) {
    const saved = await cache.match(key);
    if (saved) return saved;
    throw err;
  }
}

self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== "GET" || url.origin !== location.origin) return;
  // Device details and DNS lookups aren't kept: they're only worth it live.
  if (SAVED.includes(url.pathname + url.search)) return e.respondWith(networkFirst(e.request, url.pathname + url.search));
  if (e.request.mode === "navigate") return e.respondWith(networkFirst(e.request, "/"));
  e.respondWith(caches.match(e.request).then((hit) => hit || fetch(e.request)));
});
