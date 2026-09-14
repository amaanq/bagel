const MODULE = "/__bagel/static/solver.wasm";
const BATCH = 1 << 16;

const decode = (text) =>
  Uint8Array.from(atob(text.replace(/-/g, "+").replace(/_/g, "/")), (ch) =>
    ch.charCodeAt(0),
  );
const encode = (bytes) =>
  btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

function shadowRootFor(host) {
  if (host.shadowRoot) return host.shadowRoot;
  const template = host.querySelector(":scope > template");
  if (!template) return null;
  const root = host.attachShadow({ mode: "open" });
  root.appendChild(template.content.cloneNode(true));
  template.remove();
  return root;
}

async function run(host) {
  const root = shadowRootFor(host) || host;
  const status = root.querySelector?.(".bagel-status");
  const handoff = decode(host.dataset.p);
  const { instance } = await WebAssembly.instantiateStreaming(fetch(MODULE));
  const { memory, buf, unpack, solve, seal } = instance.exports;
  const base = buf();
  const view = () => new Uint8Array(memory.buffer);
  view().set(handoff, base);
  const difficulty = unpack(handoff.length);
  if (difficulty < 0) return;

  const started = performance.now();
  let nonce = 0n;
  let found = -1n;
  while (found < 0n) {
    found = solve(nonce, BATCH, difficulty);
    nonce += BigInt(BATCH);
    if (status) {
      const elapsed = ((performance.now() - started) / 1000).toFixed(1);
      status.textContent = `Checking... (${elapsed}s)`;
    }
    await new Promise((resolve) => setTimeout(resolve, 0));
  }

  const iv = crypto.getRandomValues(new Uint32Array(1))[0];
  const length = seal(found, iv);
  const resp = await fetch(host.dataset.v, {
    method: "POST",
    headers: { "content-type": "text/plain" },
    body: encode(view().subarray(base, base + length)),
  });
  if (resp.ok && host.dataset.mode !== "background") window.location.reload();
}

document.addEventListener("DOMContentLoaded", () => {
  const mount = document.getElementById("bagel-challenge");
  for (const host of document.querySelectorAll("bagel-challenge")) {
    if (mount && mount !== host && !mount.contains(host)) mount.appendChild(host);
    if (host.dataset.p && host.dataset.v) run(host).catch(() => { });
  }
});
