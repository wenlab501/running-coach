/* Running Coach service worker.
 * Static shell: cache-first (asset URLs carry ?v= so new releases are new URLs).
 * Page navigation: network-first, cached shell when offline.
 * Encrypted data (dashboard*.enc.json) and the public summary: network-first, last good copy when offline
 * (marked with X-RC-Offline). Decrypted data never reaches this worker or any cache. */
const VERSION = "rc-2026-10-07";
const STATIC = `rc-static-${VERSION}`;
const DATA = "rc-data";
const SHELL = ["./", "index.html", "manifest.webmanifest", "icon.svg", "icon-192.png", "icon-512.png", "apple-touch-icon.png"];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(STATIC).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (e) => {
  e.waitUntil(caches.keys()
    .then((ks) => Promise.all(ks.filter((k) => k.startsWith("rc-static-") && k !== STATIC).map((k) => caches.delete(k))))
    .then(() => self.clients.claim()));
});

const isData = (url) => url.origin === self.location.origin &&
  /\/data\/(dashboard(\.viewer)?\.enc\.json|public_summary\.json)$/.test(url.pathname);

async function networkFirstData(req, url) {
  const key = url.origin + url.pathname;             // ignore query strings
  try {
    const r = await fetch(req, { cache: "no-store" });
    if (r.ok) await (await caches.open(DATA)).put(key, r.clone());
    return r;
  } catch {
    const hit = await caches.match(key);
    if (!hit) return new Response("", { status: 503, statusText: "offline" });
    const h = new Headers(hit.headers);
    h.set("X-RC-Offline", "1");
    return new Response(await hit.blob(), { status: 200, headers: h });
  }
}

self.addEventListener("fetch", (e) => {
  const req = e.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  if (isData(url)) { e.respondWith(networkFirstData(req, url)); return; }
  if (req.mode === "navigate") {
    e.respondWith(fetch(req)
      .then((r) => { const c = r.clone(); caches.open(STATIC).then((s) => s.put("./", c)); return r; })
      .catch(() => caches.match("./")));
    return;
  }
  if (url.origin === self.location.origin || url.hostname === "cdnjs.cloudflare.com") {
    e.respondWith(caches.match(req).then((hit) => hit || fetch(req).then((r) => {
      if (r.ok || r.type === "opaque") { const c = r.clone(); caches.open(STATIC).then((s) => s.put(req, c)); }
      return r;
    })));
  }
});
