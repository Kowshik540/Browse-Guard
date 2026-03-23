function goBack() {
  if (window.history.length > 1) {
    window.history.back();
  } else {
    window.location.href = "https://www.google.com";
  }
}

function getParam(search, name) {
  var prefix = name + "=";
  var parts = search.split("&");
  for (var i = 0; i < parts.length; i++) {
    var part = parts[i];
    if (part.indexOf(prefix) === 0) {
      try {
        return decodeURIComponent(part.substring(prefix.length));
      } catch(e) {
        return part.substring(prefix.length);
      }
    }
  }
  return "";
}

// Parse AI explanation into structured rows
// Expected format from backend:
// THREAT: ...
// TARGET: ...
// RISK: ...
// ACTION: LEAVE or CAUTION
function renderAI(explanation) {
  if (!explanation) return;

  var aiBox = document.getElementById("ai-box");
  var aiContent = document.getElementById("ai-content");
  if (!aiBox || !aiContent) return;

  var lines = explanation.split("\n");
  var parsed = {};
  lines.forEach(function(line) {
    var colonIdx = line.indexOf(":");
    if (colonIdx > -1) {
      var key = line.substring(0, colonIdx).trim().toUpperCase();
      var val = line.substring(colonIdx + 1).trim();
      parsed[key] = val;
    }
  });

  var html = "";

  if (parsed["THREAT"]) {
    html += '<div class="ai-row"><span class="ai-label">Threat</span><span class="ai-value">' + parsed["THREAT"] + '</span></div>';
  }
  if (parsed["TARGET"]) {
    html += '<div class="ai-row"><span class="ai-label">Target</span><span class="ai-value">' + parsed["TARGET"] + '</span></div>';
  }
  if (parsed["RISK"]) {
    html += '<div class="ai-row"><span class="ai-label">At risk</span><span class="ai-value">' + parsed["RISK"] + '</span></div>';
  }
  if (parsed["ACTION"]) {
    var actionClass = parsed["ACTION"].toUpperCase().indexOf("LEAVE") > -1 ? "ai-action-leave" : "ai-action-caution";
    var actionText  = parsed["ACTION"].toUpperCase().indexOf("LEAVE") > -1 ? "⛔ LEAVE IMMEDIATELY" : "⚠️ PROCEED WITH CAUTION";
    html += '<div><span class="' + actionClass + '">' + actionText + '</span></div>';
  }

  // Fallback — show raw text if no structured keys found
  if (!html) {
    html = '<div class="ai-raw">' + explanation + '</div>';
  }

  aiContent.innerHTML = html;
  aiBox.style.display = "block";
}

document.addEventListener("DOMContentLoaded", function() {
  var href = window.location.href;
  var qIdx = href.indexOf("?");

  if (qIdx === -1) {
    document.getElementById("url-box").textContent = "No URL data received";
    return;
  }

  var search = href.substring(qIdx + 1);

  var blockedUrl = getParam(search, "url");
  var score      = parseInt(getParam(search, "score") || "5");
  var reasonsStr = getParam(search, "reasons");
  var realName   = getParam(search, "realName");
  var realUrl    = getParam(search, "realUrl");

  // Score display
  var scoreEl = document.getElementById("score-num");
  var fillEl  = document.getElementById("score-fill");
  if (scoreEl) {
    scoreEl.textContent = score;
    scoreEl.style.color = score < 40 ? "#e74c3c" : "#f39c12";
  }
  if (fillEl) {
    fillEl.style.width = score + "%";
    fillEl.style.background = score < 40 ? "#e74c3c" : "#f39c12";
  }

  // URL — hostname only
  var urlEl = document.getElementById("url-box");
  if (urlEl) {
    if (blockedUrl) {
      try {
        urlEl.textContent = new URL(blockedUrl).hostname;
      } catch(e) {
        urlEl.textContent = blockedUrl.substring(0, 80);
      }
    } else {
      urlEl.textContent = "Unknown URL";
    }
  }

  // Reasons list
  var reasons = [];
  try { reasons = JSON.parse(reasonsStr); } catch(e) {}
  var reasonsEl = document.getElementById("reasons-box");
  if (reasonsEl && reasons.length > 0) {
    reasonsEl.innerHTML = reasons.map(function(r) {
      return '<div class="reason">⚠ ' + r + '</div>';
    }).join("");
  }

  // Real site suggestion
  if (realName && realUrl) {
    var realBox  = document.getElementById("real-site-box");
    var realNameEl = document.getElementById("real-name-el");
    var realUrlEl  = document.getElementById("real-url-el");
    var realBtn    = document.getElementById("real-site-btn");
    if (realBox)    realBox.style.display = "flex";
    if (realNameEl) realNameEl.textContent = realName;
    if (realUrlEl)  realUrlEl.textContent  = realUrl;
    if (realBtn)    realBtn.addEventListener("click", function() {
      window.location.href = realUrl;
    });
  }

  // Go back button
  var backBtn = document.getElementById("btn-back");
  if (backBtn) backBtn.addEventListener("click", goBack);

  // Continue anyway
  var continueBtn = document.getElementById("btn-continue");
  if (continueBtn) continueBtn.addEventListener("click", function() {
    if (blockedUrl) window.location.href = blockedUrl;
  });

  // Fetch AI explanation from backend
  if (blockedUrl) {
    fetch("http://127.0.0.1:5000/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: blockedUrl })
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.explanation) {
        renderAI(data.explanation);
      }
    })
    .catch(function() {});
  }
});