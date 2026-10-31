const form = document.querySelector("#scan-form");
const button = document.querySelector("#scan-button");
const status = document.querySelector("#status");
const results = document.querySelector("#results");

function showStatus(message, kind = "") {
  status.textContent = message;
  status.className = `status ${kind}`;
}

function renderFindings(items) {
  const container = document.querySelector("#findings");
  container.replaceChildren();
  if (!items.length) {
    container.innerHTML = "<p class=\"muted\">No findings reported.</p>";
    return;
  }
  for (const item of items) {
    const element = document.createElement("article");
    element.className = `finding ${item.severity}`;
    element.innerHTML = `<div class="finding-heading"><strong>${item.title}</strong><span>${item.severity}</span></div><p>${item.details}</p>`;
    container.appendChild(element);
  }
}

function renderObservations(items) {
  const container = document.querySelector("#observations");
  container.replaceChildren();
  if (!items.length) {
    container.innerHTML = "<p class=\"muted\">No observations reported.</p>";
    return;
  }
  for (const item of items) {
    const element = document.createElement("div");
    element.className = "observation";
    const port = item.port === null ? "" : `:${item.port}`;
    element.innerHTML = `<code>${item.ip}${port}</code><span>${item.source}</span><code>${item.mac}</code>`;
    container.appendChild(element);
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  button.disabled = true;
  showStatus("Scanning network…");
  const ports = document.querySelector("#ports").value
    .split(",")
    .map((port) => Number(port.trim()))
    .filter((port) => Number.isInteger(port) && port > 0 && port <= 65535);
  const payload = {
    target: document.querySelector("#target").value.trim() || null,
    ports,
    timeout: Number(document.querySelector("#timeout").value),
    include_arp_cache: document.querySelector("#arp-cache").checked,
    include_tcp_syn: document.querySelector("#tcp-syn").checked,
  };
  try {
    const response = await fetch("/api/scans", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || "Scan failed.");
    document.querySelector("#scan-target").textContent = data.target;
    const state = document.querySelector("#scan-state");
    state.textContent = data.suspicious ? "Suspicious" : "No threat detected";
    state.className = `badge ${data.suspicious ? "danger" : "safe"}`;
    renderFindings(data.findings);
    renderObservations(data.observations);
    results.classList.remove("hidden");
    showStatus("Scan complete.", "success");
  } catch (error) {
    showStatus(error.message, "error");
  } finally {
    button.disabled = false;
  }
});
