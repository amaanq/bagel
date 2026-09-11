// Bagel SHA-256 Proof-of-Work solver
// Uses SubtleCrypto for SHA-256 and Web Workers for parallelism.

const WORKER_COUNT = navigator.hardwareConcurrency || 4;

/**
 * Solve a SHA-256 proof-of-work challenge.
 * @param {string} challenge - The challenge key (hex string)
 * @param {number} difficulty - Number of leading zero hex nibbles required
 * @param {string} verifyUrl - URL to POST the solution to
 * @returns {Promise<boolean>} Whether verification succeeded
 */
export async function solve(challenge, difficulty, verifyUrl, background = false, root = document) {
  const startTime = performance.now();

  // Split work across workers
  const chunkSize = 1_000_000;
  let nonce = 0;
  let found = null;

  // Try to solve using SubtleCrypto in the main thread (workers are optional)
  const challengeBytes = hexToBytes(challenge);

  while (!found) {
    const batch = [];
    for (let i = 0; i < 10000 && !found; i++) {
      const candidate = nonce + i;
      batch.push(tryNonce(challengeBytes, candidate, difficulty));
    }

    const results = await Promise.all(batch);
    for (let i = 0; i < results.length; i++) {
      if (results[i]) {
        found = nonce + i;
        break;
      }
    }
    nonce += batch.length;

    // Update progress indicator if available
    const elapsed = ((performance.now() - startTime) / 1000).toFixed(1);
    const el = root.querySelector(".bagel-status");
    if (el) {
      el.textContent = `Checking... (${elapsed}s, ${nonce.toLocaleString()} attempts)`;
    }
  }

  const elapsed = ((performance.now() - startTime) / 1000).toFixed(2);
  console.log(`[bagel] PoW solved: nonce=${found}, ${nonce} attempts in ${elapsed}s`);

  // Submit the solution
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

/**
 * Try a single nonce against the challenge.
 * SHA-256(challenge || nonce_bytes) must have `difficulty` leading zero nibbles.
 */
async function tryNonce(challengeBytes, nonce, difficulty) {
  const nonceBytes = numberToBytes(nonce);
  const input = new Uint8Array(challengeBytes.length + nonceBytes.length);
  input.set(challengeBytes, 0);
  input.set(nonceBytes, challengeBytes.length);

  const hash = await crypto.subtle.digest("SHA-256", input);
  return checkLeadingZeros(new Uint8Array(hash), difficulty);
}

function checkLeadingZeros(hash, nibbles) {
  const fullBytes = Math.floor(nibbles / 2);
  for (let i = 0; i < fullBytes; i++) {
    if (hash[i] !== 0) return false;
  }
  if (nibbles % 2 === 1) {
    if ((hash[fullBytes] >> 4) !== 0) return false;
  }
  return true;
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function numberToBytes(n) {
  // Encode as 8-byte big-endian
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  view.setBigUint64(0, BigInt(n));
  return new Uint8Array(buf);
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
    const difficulty = parseInt(host.dataset.difficulty, 10);
    const verifyUrl = host.dataset.verifyUrl || "/__bagel/pow/verify";
    solve(challenge, difficulty, verifyUrl, host.dataset.mode === "background", root);
  }
});
