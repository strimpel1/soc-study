// Streams the encrypted videos: answers the player's byte-range requests by fetching only the
// encrypted 1 MiB chunks that cover the range and decrypting them here. The key lives in memory only;
// if this worker was restarted, it asks the open page for the key again.
let KEY = null, CHUNK = 1 << 20, waiters = [];
const GROUP = 4; // chunks fetched per network request

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));
self.addEventListener("message", (e) => {
  const d = e.data || {};
  if (d.type === "key") { KEY = d.key; CHUNK = d.chunk || CHUNK; waiters.splice(0).forEach((w) => w()); }
  if (d.type === "lock") KEY = null;
});

async function needKey() {
  if (KEY) return true;
  const pages = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
  pages.forEach((p) => p.postMessage({ type: "needkey" }));
  await new Promise((res) => { waiters.push(res); setTimeout(res, 4000); });
  return !!KEY;
}

async function openChunk(nonce, i, last, data) {
  const iv = new Uint8Array(12); iv.set(nonce, 0); new DataView(iv.buffer).setUint32(8, i);
  const aad = new Uint8Array(5); new DataView(aad.buffer).setUint32(0, i); aad[4] = last ? 1 : 0;
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: aad }, KEY, data));
}

const nonces = new Map();
async function nonceOf(url) {
  if (!nonces.has(url)) {
    const r = await fetch(url, { headers: { Range: "bytes=0-7" } });
    const b = new Uint8Array(await r.arrayBuffer());
    nonces.set(url, b.slice(0, 8));
  }
  return nonces.get(url);
}

async function stream(req, url) {
  if (!(await needKey())) return new Response("locked", { status: 403 });
  const size = Number(url.searchParams.get("size"));
  const src = url.pathname.replace(/\/stream\/([^/]+)\.mp4$/, "/data/$1");
  const m = /bytes=(\d+)-(\d*)/.exec(req.headers.get("Range") || "");
  const start = m ? Number(m[1]) : 0;
  const end = Math.min(m && m[2] ? Number(m[2]) : size - 1, size - 1);
  if (!size || start > end) return new Response(null, { status: 416, headers: { "Content-Range": `bytes */${size}` } });
  const SEALED = CHUNK + 16, total = Math.ceil(size / CHUNK), fileLen = 8 + size + total * 16;
  const nonce = await nonceOf(src);
  let i = Math.floor(start / CHUNK);
  const lastIdx = Math.floor(end / CHUNK);
  const body = new ReadableStream({
    async pull(ctrl) {
      if (i > lastIdx) return ctrl.close();
      const to = Math.min(i + GROUP - 1, lastIdx);
      const a = 8 + i * SEALED, b = Math.min(8 + (to + 1) * SEALED, fileLen) - 1;
      const r = await fetch(src, { headers: { Range: `bytes=${a}-${b}` } });
      if (r.status !== 206 && r.status !== 200) throw new Error("fetch " + r.status);
      let buf = new Uint8Array(await r.arrayBuffer());
      if (r.status === 200) buf = buf.subarray(a, b + 1); // host ignored the range
      for (let k = i; k <= to; k++) {
        const sealed = buf.subarray((k - i) * SEALED, Math.min((k - i + 1) * SEALED, buf.length));
        const plain = await openChunk(nonce, k, k === total - 1, sealed);
        const from = k === Math.floor(start / CHUNK) ? start - k * CHUNK : 0;
        const upto = k === lastIdx ? end - k * CHUNK + 1 : plain.length;
        ctrl.enqueue(plain.subarray(from, upto));
      }
      i = to + 1;
    },
  });
  return new Response(body, {
    status: 206,
    headers: { "Content-Type": "video/mp4", "Accept-Ranges": "bytes", "Content-Length": String(end - start + 1),
               "Content-Range": `bytes ${start}-${end}/${size}`, "Cache-Control": "no-store" },
  });
}

self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (/\/stream\/[^/]+\.mp4$/.test(url.pathname)) e.respondWith(stream(e.request, url).catch((err) => new Response(String(err), { status: 500 })));
});
