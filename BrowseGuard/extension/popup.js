// popup.js

function openDashboard() {
  chrome.tabs.create({ url: "http://localhost:3000" });
}

function updateUI(data) {
  const score = data.riskScore ?? null;
  const lastVisit = data.lastVisit ?? null;
  const history = data.visitHistory ?? [];

  const scoreEl = document.getElementById("score-number");
  const fill = document.getElementById("score-fill");
  const badge = document.getElementById("status-badge");

  if (score !== null) {
    scoreEl.textContent = score;
    fill.style.width = score + "%";

    if (score >= 80) {
      fill.style.background = "#27ae60";
      badge.textContent = "✓ Safe browsing";
      badge.className = "badge safe";
    } else if (score >= 60) {
      fill.style.background = "#f39c12";
      badge.textContent = "⚠ Moderate risk";
      badge.className = "badge warn";
    } else {
      fill.style.background = "#e74c3c";
      badge.textContent = "✕ High risk detected";
      badge.className = "badge danger";
    }
  } else {
    scoreEl.textContent = "100";
    fill.style.width = "100%";
    fill.style.background = "#27ae60";
    badge.textContent = "✓ No risks yet";
    badge.className = "badge safe";
  }

  // Stats
  const total = history.length;
  const flagged = history.filter(v => v.flagged).length;
  const safe = total - flagged;
  document.getElementById("total-visits").textContent = total;
  document.getElementById("flagged-count").textContent = flagged;
  document.getElementById("safe-count").textContent = safe;

  // Last visit
  const container = document.getElementById("last-visit-content");
  if (lastVisit && lastVisit.url) {
    const short = lastVisit.url.length > 45
      ? lastVisit.url.substring(0, 45) + "..."
      : lastVisit.url;

    let reasonsHTML = "";
    if (lastVisit.reasons && lastVisit.reasons.length > 0) {
      reasonsHTML = lastVisit.reasons.slice(0, 3)
        .map(r => `<div class="reason-item">⚠ ${r}</div>`)
        .join("");
    } else {
      reasonsHTML = `<div class="no-reason">✓ No threats detected</div>`;
    }
    container.innerHTML = `<div class="visit-url">${short}</div>${reasonsHTML}`;
  }
}

// Load immediately when popup opens
chrome.storage.local.get(["riskScore", "lastVisit", "visitHistory"], updateUI);

// Refresh every 2 seconds while popup is open
setInterval(() => {
  chrome.storage.local.get(["riskScore", "lastVisit", "visitHistory"], updateUI);
}, 2000);