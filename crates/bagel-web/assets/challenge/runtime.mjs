const WORKER = "/__bagel/static/worker.mjs";
const completed = new WeakSet();

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
  const controller = new AbortController();
  let worker;
  const cancel = () => {
    worker?.terminate();
    controller.abort();
  };
  window.addEventListener("pagehide", cancel, { once: true });

  try {
    worker = new Worker(WORKER, { type: "module" });
    const proof = await new Promise((resolve, reject) => {
      controller.signal.addEventListener("abort", () => reject(controller.signal.reason), {
        once: true,
      });
      worker.onmessage = ({ data }) => {
        switch (data.type) {
          case "progress":
            if (status) status.textContent = `Checking... (${(data.elapsed / 1000).toFixed(1)}s)`;
            break;
          case "proof":
            resolve(data.proof);
            break;
          default:
            reject(new Error("Challenge worker failed"));
        }
      };
      worker.onerror = (event) => {
        event.preventDefault();
        reject(new Error("Challenge worker failed"));
      };
      worker.onmessageerror = () => reject(new Error("Invalid challenge worker message"));
      worker.postMessage(host.dataset.p);
    });

    const resp = await fetch(host.dataset.v, {
      method: "POST",
      headers: { "content-type": "text/plain" },
      body: proof,
      signal: controller.signal,
    });
    if (!resp.ok) throw new Error("Challenge verification failed");
    completed.add(host);
    if (status) status.textContent = "Check complete";
    if (host.dataset.mode !== "background") window.location.reload();
  } catch (error) {
    if (!controller.signal.aborted) {
      if (status) status.textContent = "Couldn't complete the check. Reload to try again.";
      console.error("Bagel challenge failed", error);
    }
  } finally {
    worker?.terminate();
    window.removeEventListener("pagehide", cancel);
  }
}

function mount() {
  const container = document.getElementById("bagel-challenge");
  for (const host of document.querySelectorAll("bagel-challenge")) {
    if (container && container !== host && !container.contains(host)) container.appendChild(host);
    if (host.dataset.p && host.dataset.v && !completed.has(host)) run(host);
  }
}

document.addEventListener("DOMContentLoaded", mount);
window.addEventListener("pageshow", (event) => {
  if (event.persisted) mount();
});
