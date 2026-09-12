// Bagel SHA-256 Proof-of-Work solver.
//
// Runs on the client's JS engine so proving costs us nothing. Throughput
// comes from a small bounded pool of SubtleCrypto digests: enough to keep
// the pipeline full, few enough to avoid the memory churn of thousands of
// in-flight promises. The main thread yields between batches so the page
// stays responsive while solving.

/**
 * Solve a SHA-256 proof-of-work challenge.
 * @param {string} challenge - The challenge key (hex string)
 * @param {number} difficulty - Number of leading zero hex nibbles required
 * @param {string} verifyUrl - URL to POST the solution to
 * @returns {Promise<boolean>} Whether verification succeeded
 */
export async function solve(
  challenge,
  difficulty,
  verifyUrl,
  background = false,
  root = document,
) {
  if (typeof challenge !== "string" || !/^[0-9a-fA-F]{64}$/.test(challenge)) {
    console.error("[bagel] PoW: invalid challenge key");
    return false;
  }
  if (!Number.isInteger(difficulty) || difficulty < 1 || difficulty > 64) {
    console.error("[bagel] PoW: invalid difficulty");
    return false;
  }
  if (!root || typeof crypto?.subtle?.digest !== "function") {
    console.error("[bagel] PoW: SubtleCrypto unavailable");
    return false;
  }

  const startTime = performance.now();
  const challengeBytes = hexToBytes(challenge);
  // Reused across nonces: challenge || 8-byte big-endian nonce.
  const input = new Uint8Array(challengeBytes.length + 8);
  input.set(challengeBytes, 0);
  const nonceView = new DataView(
    input.buffer,
    input.byteOffset + challengeBytes.length,
    8,
  );

  const poolSize = concurrencyFor();
  const statusEl = root.querySelector?.(".bagel-status") ?? null;
  const reportProgress = throttleProgress(statusEl, startTime);

  let nonce = 0;
  let found = -1;

  // Bounded pool: `poolSize` digests in flight, then yield so input stays
  // responsive. Each batch allocates `poolSize` promises, not thousands.
  while (found < 0) {
    const batch = new Array(poolSize);
    for (let i = 0; i < poolSize; i++) {
      batch[i] = tryNonce(input, nonceView, nonce + i, difficulty);
    }
    const results = await Promise.all(batch);
    for (let i = 0; i < results.length; i++) {
      if (results[i]) {
        found = nonce + i;
        break;
      }
    }
    nonce += poolSize;
    reportProgress(nonce);
    await yieldToUI();
  }

  const elapsed = ((performance.now() - startTime) / 1000).toFixed(2);
  console.log(
    `[bagel] PoW solved: nonce=${found}, ${nonce} attempts in ${elapsed}s`,
  );

  try {
    const resp = await fetch(verifyUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ nonce: found, challenge }),
    });
    if (resp.ok) {
      // Background delivery solved on the live page; only interstitials reload.
      if (!background) {
        window.location.reload();
      }
      return true;
    }
  } catch (e) {
    console.error("[bagel] PoW verification failed:", e);
  }
  return false;
}

/// Digests per batch: enough parallelism for SubtleCrypto, bounded for memory.
function concurrencyFor() {
  const cores = Number(globalThis.navigator?.hardwareConcurrency) || 4;
  return Math.min(256, Math.max(32, cores * 16));
}

/// Yield control so hover, scroll and the progress label stay alive.
function yieldToUI() {
  if (typeof globalThis.scheduler?.yield === "function") {
    return globalThis.scheduler.yield();
  }
  return new Promise((resolve) => setTimeout(resolve, 0));
}

/// Cache the status node and throttle text writes to ~4Hz; formatting
/// (`toLocaleString`) only runs when a write actually happens.
function throttleProgress(el, startTime) {
  if (!el) return () => {};
  let last = 0;
  return (nonce) => {
    const now = performance.now();
    if (now - last < 250) return;
    last = now;
    const elapsed = ((now - startTime) / 1000).toFixed(1);
    el.textContent = `Checking... (${elapsed}s, ${nonce.toLocaleString()} attempts)`;
  };
}

/**
 * Try a single nonce against the challenge.
 * SHA-256(challenge || nonce_bytes) must have `difficulty` leading zero nibbles.
 */
async function tryNonce(input, nonceView, nonce, difficulty) {
  nonceView.setBigUint64(0, BigInt(nonce));
  const hash = await crypto.subtle.digest("SHA-256", input);
  return checkLeadingZeros(new Uint8Array(hash), difficulty);
}

function checkLeadingZeros(hash, nibbles) {
  const fullBytes = Math.floor(nibbles / 2);
  for (let i = 0; i < fullBytes; i++) {
    if (hash[i] !== 0) return false;
  }
  if (nibbles % 2 === 1) {
    if (hash[fullBytes] >> 4 !== 0) return false;
  }
  return true;
}

const HEX_TABLE = (() => {
  const table = new Uint8Array(256);
  for (let i = 0; i < 10; i++) table[48 + i] = i;
  for (let i = 0; i < 6; i++) {
    table[65 + i] = 10 + i;
    table[97 + i] = 10 + i;
  }
  return table;
})();

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length >> 1);
  for (let i = 0; i < bytes.length; i++) {
    const hi = HEX_TABLE[hex.charCodeAt(i * 2)] ?? 0;
    const lo = HEX_TABLE[hex.charCodeAt(i * 2 + 1)] ?? 0;
    bytes[i] = (hi << 4) | lo;
  }
  return bytes;
}

/**
 * Give the host a shadow root when the HTML parser did not. Declarative shadow
 * DOM is only applied during parsing, so a widget spliced in after `</html>`
 * or by a browser that ignores `shadowrootmode` arrives as an inert template.
 */
function shadowRootFor(host) {
  if (host.shadowRoot) return host.shadowRoot;

  const template = host.querySelector(":scope > template");
  if (!template) return null;

  const root = host.attachShadow({ mode: "open" });
  root.appendChild(template.content.cloneNode(true));
  template.remove();
  return root;
}

// Auto-start if data attributes are present
document.addEventListener("DOMContentLoaded", () => {
  const mount = document.getElementById("bagel-challenge");
  for (const host of document.querySelectorAll("bagel-challenge")) {
    if (mount && mount !== host && !mount.contains(host)) {
      mount.appendChild(host);
    }

    const root = shadowRootFor(host) || host;
    const challenge = host.dataset.challenge;
    const difficulty = Number.parseInt(host.dataset.difficulty, 10);
    const verifyUrl = host.dataset.verifyUrl || "/__bagel/pow/verify";
    if (typeof challenge !== "string" || !Number.isInteger(difficulty))
      continue;
    solve(
      challenge,
      difficulty,
      verifyUrl,
      host.dataset.mode === "background",
      root,
    ).catch((err) => {
      console.error("[bagel] PoW solver failed:", err);
    });
  }
});
