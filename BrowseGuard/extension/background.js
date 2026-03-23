const BACKEND_URL = "http://127.0.0.1:5000";

// -------------------------------------------------------
// KEEP SERVICE WORKER ALIVE
// Chrome MV3 kills workers after 30s — alarms prevent this
// -------------------------------------------------------
function keepAlive() {
  chrome.storage.local.get("keepAlive", () => {});
}

function setupAlarms() {
  try {
    chrome.alarms.create("keepAlive", { periodInMinutes: 0.4 });
    chrome.alarms.onAlarm.addListener((alarm) => {
      if (alarm.name === "keepAlive") {
        keepAlive();
        console.log("BrowseGuard alive:", new Date().toLocaleTimeString());
      }
    });
  } catch (e) {
    setInterval(keepAlive, 20000);
  }
}

setupAlarms();

chrome.runtime.onInstalled.addListener(() => {
  try { chrome.alarms.create("keepAlive", { periodInMinutes: 0.4 }); } catch(e) {}
  keepAlive();
  console.log("BrowseGuard installed and ready");
});

chrome.runtime.onStartup.addListener(() => {
  try { chrome.alarms.create("keepAlive", { periodInMinutes: 0.4 }); } catch(e) {}
  keepAlive();
});


// -------------------------------------------------------
// STATE
// notifiedUrls: prevents duplicate notifications per URL
// RISK_THRESHOLD: score below this triggers popup/notification
// -------------------------------------------------------
const notifiedUrls = new Set();
const RISK_THRESHOLD = 60;


// -------------------------------------------------------
// WHITELIST — these domains are always safe, never flagged
// -------------------------------------------------------
const WHITELIST = [
  'onlinesbi.sbi', 'sbi.co.in', 'sbi.bank.in', 'onlinesbi.sbi.bank.in',
  'hdfcbank.com', 'icicibank.com', 'axisbank.com', 'kotak.com',
  'paytm.com', 'phonepe.com', 'mobikwik.com',
  'netflix.com', 'instagram.com', 'whatsapp.com', 'facebook.com',
  'amazon.in', 'amazon.com', 'apple.com', 'microsoft.com',
  'google.com', 'youtube.com', 'twitter.com', 'x.com',
  'paypal.com', 'linkedin.com', 'github.com',
  'wikipedia.org', 'stackoverflow.com', 'reddit.com',
  'flipkart.com', 'zomato.com', 'swiggy.com', 'myntra.com',
  'nykaa.com', 'meesho.com', 'snapdeal.com', 'ajio.com',
  'irctc.co.in', 'uidai.gov.in', 'incometax.gov.in',
  'india.gov.in', 'mygov.in', 'makeinindia.com'
];

function isWhitelisted(domain) {
  return WHITELIST.some(w => domain.endsWith(w));
}

function isLegitBrandDomain(brand, domain) {
  const suffixes = [
    `${brand}.com`, `${brand}.in`, `${brand}.sbi`,
    `${brand}.bank.in`, `${brand}.co.in`, `${brand}.gov.in`,
    `${brand}.net`, `${brand}.org`, `${brand}.co`
  ];
  return suffixes.some(s => domain.endsWith(s));
}


// -------------------------------------------------------
// LISTENER 1: webNavigation — fires BEFORE page loads
// Shows Chrome notification for risky URLs
// Works even if the page never loads
// -------------------------------------------------------
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;
  const url = details.url;
  if (!url.startsWith("http")) return;
  if (notifiedUrls.has(url)) return; // prevent duplicates

  const result = quickRiskCheck(url);

  // Save score immediately so popup icon updates instantly
  chrome.storage.local.set({
    riskScore: result.score,
    lastVisit: {
      url,
      score: result.score,
      flagged: result.flagged,
      reasons: result.reasons,
      explanation: ""
    }
  });

  // Save to history
  chrome.storage.local.get(["visitHistory"], (r) => {
    const history = r.visitHistory || [];
    history.unshift({
      url,
      score: result.score,
      flagged: result.flagged,
      time: new Date().toISOString()
    });
    if (history.length > 50) history.pop();
    chrome.storage.local.set({ visitHistory: history });
  });

  // Redirect to warning page if very high risk
  if (result.score < 50 && details.tabId) {
    blockIfRisky(details.tabId, url);
  }
  
  // Show notification once — only if score < 60
  if (result.score < RISK_THRESHOLD) {
    notifiedUrls.add(url);
    setTimeout(() => notifiedUrls.delete(url), 30000);

    const msg = result.realSite
      ? (result.reasons[0] || "Suspicious URL") + " | Real site: " + result.realSite.url
      : result.reasons.slice(0, 2).join(" | ") || "Suspicious URL detected";

    chrome.notifications.create("bg-" + Date.now(), {
      type: "basic",
      iconUrl: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
      title: "\u26a0\ufe0f Risk Detected \u2014 Score: " + result.score + "/100",
      message: msg,
      priority: 2
    });
  }
});

// Catches redirects that onBeforeNavigate misses
chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  if (!details.url.startsWith("http")) return;

  // Only process redirects, not initial navigations
  const isRedirect = details.transitionQualifiers &&
    details.transitionQualifiers.includes("server_redirect");
  if (!isRedirect) return;

  const url = details.url;
  if (notifiedUrls.has(url)) return;

  const result = quickRiskCheck(url);
  if (result.score < RISK_THRESHOLD) {
    notifiedUrls.add(url);
    setTimeout(() => notifiedUrls.delete(url), 30000);

    chrome.notifications.create("bg-redirect-" + Date.now(), {
      type: "basic",
      iconUrl: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
      title: "\u26a0\ufe0f Redirect Risk \u2014 Score: " + result.score + "/100",
      message: "Redirected to suspicious URL: " + url.substring(0, 60),
      priority: 2
    });
  }
});


// -------------------------------------------------------
// LISTENER 2: onUpdated — fires AFTER page fully loads
// Analyzes page content + injects overlay popup
// -------------------------------------------------------
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete") return;
  if (!tab.url || !tab.url.startsWith("http")) return;

  const url = tab.url;
  const urlResult = quickRiskCheck(url);

  // Step 1: Analyze page content (runs inside the page)
  let pageResult = { score: 100, reasons: [], flagged: false };
  try {
    const injected = await chrome.scripting.executeScript({
      target: { tabId },
      func: analyzePageContent,
      args: []
    });
    if (injected && injected[0] && injected[0].result) {
      pageResult = injected[0].result;
    }
  } catch(e) {
    console.log("Page analysis error:", e.message);
  }

  // Step 2: Combine URL score + page content score (take the lower)
  const combinedScore = Math.max(5, Math.min(urlResult.score, pageResult.score));
  const combinedReasons = [...urlResult.reasons, ...pageResult.reasons];
  const combinedFlagged = urlResult.flagged || pageResult.flagged;

  // Update storage with combined result
  chrome.storage.local.set({
    riskScore: combinedScore,
    lastVisit: {
      url,
      score: combinedScore,
      flagged: combinedFlagged,
      reasons: combinedReasons,
      explanation: ""
    }
  });

  // Update history
  chrome.storage.local.get(["visitHistory"], (r) => {
    const history = r.visitHistory || [];
    const idx = history.findIndex(v => v.url === url);
    if (idx !== -1) {
      history[idx].score = combinedScore;
      history[idx].flagged = combinedFlagged;
    } else {
      history.unshift({
        url,
        score: combinedScore,
        flagged: combinedFlagged,
        time: new Date().toISOString()
      });
    }
    if (history.length > 50) history.pop();
    chrome.storage.local.set({ visitHistory: history });
  });

  // Step 3: Inject overlay ONLY if score < 60
  if (combinedScore < RISK_THRESHOLD) {
    try {
      await chrome.scripting.executeScript({
        target: { tabId },
        func: showRiskOverlay,
        args: [{
          score: combinedScore,
          reasons: combinedReasons,
          flagged: combinedFlagged,
          url,
          realSite: urlResult.realSite,
          explanation: ""
        }]
      });
    } catch(e) {
      console.log("Overlay inject error:", e.message);
    }
  }

  // Step 4: Backend check — Google Safe Browsing + PhishTank + Groq AI
  // Runs in background, updates overlay with AI explanation when done
  try {
    const response = await fetch(`${BACKEND_URL}/check`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    if (!response.ok) return;
    const data = await response.json();

    // Take lowest (most conservative) score
    const finalScore = Math.max(5, Math.min(combinedScore, data.score));
    const finalReasons = [...new Set([...combinedReasons, ...data.reasons])];
    const finalFlagged = combinedFlagged || data.flagged;
    const finalRealSite = urlResult.realSite || null;

    // Update storage with final result including AI explanation
    chrome.storage.local.set({
      riskScore: finalScore,
      lastVisit: {
        url,
        score: finalScore,
        flagged: finalFlagged,
        reasons: finalReasons,
        explanation: data.explanation || ""
      }
    });

    // Update history with final score
    chrome.storage.local.get(["visitHistory"], (r) => {
      const history = r.visitHistory || [];
      const idx = history.findIndex(v => v.url === url);
      if (idx !== -1) {
        history[idx].score = finalScore;
        history[idx].flagged = finalFlagged;
      }
      chrome.storage.local.set({ visitHistory: history });
    });

    // Re-inject overlay with full AI explanation — only if score < 60
    if (finalScore < RISK_THRESHOLD) {
      try {
        await chrome.scripting.executeScript({
          target: { tabId },
          func: showRiskOverlay,
          args: [{
            score: finalScore,
            reasons: finalReasons,
            flagged: finalFlagged,
            url,
            realSite: finalRealSite,
            explanation: data.explanation || ""
          }]
        });
      } catch(e) {
        console.log("Final overlay inject error:", e.message);
      }
    }

  } catch (err) {
    console.log("Backend not reachable:", err.message);
  }
});


// -------------------------------------------------------
// TYPOSQUAT LOOKUP TABLE
// fake domain (lowercase, no www) → { name, url }
// -------------------------------------------------------
const TYPOSQUAT_MAP = {
  // GitHub
  'guthi.com':    { name: 'GitHub', url: 'https://github.com' },
  'githb.com':    { name: 'GitHub', url: 'https://github.com' },
  'gihub.com':    { name: 'GitHub', url: 'https://github.com' },
  'githubb.com':  { name: 'GitHub', url: 'https://github.com' },
  'githup.com':   { name: 'GitHub', url: 'https://github.com' },
  'gitub.com':    { name: 'GitHub', url: 'https://github.com' },
  'gihtub.com':   { name: 'GitHub', url: 'https://github.com' },
  'gthub.com':    { name: 'GitHub', url: 'https://github.com' },
  'gtihub.com':   { name: 'GitHub', url: 'https://github.com' },
  'githubs.com':  { name: 'GitHub', url: 'https://github.com' },
  'guthib.com':   { name: 'GitHub', url: 'https://github.com' },
  'gitbub.com':   { name: 'GitHub', url: 'https://github.com' },
  'githib.com':   { name: 'GitHub', url: 'https://github.com' },
  'githhub.com':  { name: 'GitHub', url: 'https://github.com' },
  'githuub.com':  { name: 'GitHub', url: 'https://github.com' },
  'girhub.com':   { name: 'GitHub', url: 'https://github.com' },
  'giltub.com':   { name: 'GitHub', url: 'https://github.com' },
  'githuv.com':   { name: 'GitHub', url: 'https://github.com' },
  'githug.com':   { name: 'GitHub', url: 'https://github.com' },
  'guthub.com':   { name: 'GitHub', url: 'https://github.com' },
  'gethub.com':   { name: 'GitHub', url: 'https://github.com' },
  'git-hub.com':  { name: 'GitHub', url: 'https://github.com' },
  // Google
  'gogle.com':    { name: 'Google', url: 'https://www.google.com' },
  'googl.com':    { name: 'Google', url: 'https://www.google.com' },
  'gooogle.com':  { name: 'Google', url: 'https://www.google.com' },
  'googie.com':   { name: 'Google', url: 'https://www.google.com' },
  'goggle.com':   { name: 'Google', url: 'https://www.google.com' },
  'googlr.com':   { name: 'Google', url: 'https://www.google.com' },
  'goolge.com':   { name: 'Google', url: 'https://www.google.com' },
  'googell.com':  { name: 'Google', url: 'https://www.google.com' },
  'googled.com':  { name: 'Google', url: 'https://www.google.com' },
  'ggoogle.com':  { name: 'Google', url: 'https://www.google.com' },
  // Gmail
  'gmai.com':     { name: 'Gmail', url: 'https://mail.google.com' },
  'gmal.com':     { name: 'Gmail', url: 'https://mail.google.com' },
  'gmial.com':    { name: 'Gmail', url: 'https://mail.google.com' },
  'gmaill.com':   { name: 'Gmail', url: 'https://mail.google.com' },
  'gmali.com':    { name: 'Gmail', url: 'https://mail.google.com' },
  'gnail.com':    { name: 'Gmail', url: 'https://mail.google.com' },
  'gmil.com':     { name: 'Gmail', url: 'https://mail.google.com' },
  // YouTube
  'youttube.com': { name: 'YouTube', url: 'https://www.youtube.com' },
  'youtub.com':   { name: 'YouTube', url: 'https://www.youtube.com' },
  'yutube.com':   { name: 'YouTube', url: 'https://www.youtube.com' },
  'youtobe.com':  { name: 'YouTube', url: 'https://www.youtube.com' },
  'youtubee.com': { name: 'YouTube', url: 'https://www.youtube.com' },
  'youtueb.com':  { name: 'YouTube', url: 'https://www.youtube.com' },
  'yootube.com':  { name: 'YouTube', url: 'https://www.youtube.com' },
  'youtue.com':   { name: 'YouTube', url: 'https://www.youtube.com' },
  'yotube.com':   { name: 'YouTube', url: 'https://www.youtube.com' },
  // Facebook
  'facebok.com':  { name: 'Facebook', url: 'https://www.facebook.com' },
  'faceboook.com':{ name: 'Facebook', url: 'https://www.facebook.com' },
  'facebock.com': { name: 'Facebook', url: 'https://www.facebook.com' },
  'facbook.com':  { name: 'Facebook', url: 'https://www.facebook.com' },
  'faecbook.com': { name: 'Facebook', url: 'https://www.facebook.com' },
  'facebbok.com': { name: 'Facebook', url: 'https://www.facebook.com' },
  'faceook.com':  { name: 'Facebook', url: 'https://www.facebook.com' },
  'faceboo.com':  { name: 'Facebook', url: 'https://www.facebook.com' },
  'facepook.com': { name: 'Facebook', url: 'https://www.facebook.com' },
  // Instagram
  'instagran.com':  { name: 'Instagram', url: 'https://www.instagram.com' },
  'instagam.com':   { name: 'Instagram', url: 'https://www.instagram.com' },
  'instragram.com': { name: 'Instagram', url: 'https://www.instagram.com' },
  'instgram.com':   { name: 'Instagram', url: 'https://www.instagram.com' },
  'instagrm.com':   { name: 'Instagram', url: 'https://www.instagram.com' },
  'insagram.com':   { name: 'Instagram', url: 'https://www.instagram.com' },
  'instagrame.com': { name: 'Instagram', url: 'https://www.instagram.com' },
  'lnstagram.com':  { name: 'Instagram', url: 'https://www.instagram.com' },
  // Twitter / X
  'twiter.com':   { name: 'Twitter', url: 'https://www.twitter.com' },
  'twtter.com':   { name: 'Twitter', url: 'https://www.twitter.com' },
  'twittter.com': { name: 'Twitter', url: 'https://www.twitter.com' },
  'twiiter.com':  { name: 'Twitter', url: 'https://www.twitter.com' },
  'twitterr.com': { name: 'Twitter', url: 'https://www.twitter.com' },
  'twitte.com':   { name: 'Twitter', url: 'https://www.twitter.com' },
  'twittr.com':   { name: 'Twitter', url: 'https://www.twitter.com' },
  // LinkedIn
  'linkedln.com': { name: 'LinkedIn', url: 'https://www.linkedin.com' },
  'linkedn.com':  { name: 'LinkedIn', url: 'https://www.linkedin.com' },
  'linkin.com':   { name: 'LinkedIn', url: 'https://www.linkedin.com' },
  'linkdin.com':  { name: 'LinkedIn', url: 'https://www.linkedin.com' },
  'linkeden.com': { name: 'LinkedIn', url: 'https://www.linkedin.com' },
  'linkendin.com':{ name: 'LinkedIn', url: 'https://www.linkedin.com' },
  // Amazon
  'amazom.com':   { name: 'Amazon', url: 'https://www.amazon.in' },
  'amazoon.com':  { name: 'Amazon', url: 'https://www.amazon.in' },
  'arnazon.com':  { name: 'Amazon', url: 'https://www.amazon.in' },
  'anazon.com':   { name: 'Amazon', url: 'https://www.amazon.in' },
  'amzon.com':    { name: 'Amazon', url: 'https://www.amazon.in' },
  'amazn.com':    { name: 'Amazon', url: 'https://www.amazon.in' },
  'amozon.com':   { name: 'Amazon', url: 'https://www.amazon.in' },
  'amazone.com':  { name: 'Amazon', url: 'https://www.amazon.in' },
  'amazzon.com':  { name: 'Amazon', url: 'https://www.amazon.in' },
  'amazin.com':   { name: 'Amazon', url: 'https://www.amazon.in' },
  'amason.com':   { name: 'Amazon', url: 'https://www.amazon.in' },
  'amazom.in':    { name: 'Amazon', url: 'https://www.amazon.in' },
  'amazoon.in':   { name: 'Amazon', url: 'https://www.amazon.in' },
  'amzon.in':     { name: 'Amazon', url: 'https://www.amazon.in' },
  // PayPal
  'paypall.com':  { name: 'PayPal', url: 'https://www.paypal.com' },
  'payp4l.com':   { name: 'PayPal', url: 'https://www.paypal.com' },
  'paipal.com':   { name: 'PayPal', url: 'https://www.paypal.com' },
  'paypl.com':    { name: 'PayPal', url: 'https://www.paypal.com' },
  'paypol.com':   { name: 'PayPal', url: 'https://www.paypal.com' },
  'papyal.com':   { name: 'PayPal', url: 'https://www.paypal.com' },
  'paypaal.com':  { name: 'PayPal', url: 'https://www.paypal.com' },
  // Netflix
  'netfilx.com':  { name: 'Netflix', url: 'https://www.netflix.com' },
  'netflex.com':  { name: 'Netflix', url: 'https://www.netflix.com' },
  'netlfix.com':  { name: 'Netflix', url: 'https://www.netflix.com' },
  'n3tflix.com':  { name: 'Netflix', url: 'https://www.netflix.com' },
  'netfliix.com': { name: 'Netflix', url: 'https://www.netflix.com' },
  'netflx.com':   { name: 'Netflix', url: 'https://www.netflix.com' },
  'neflix.com':   { name: 'Netflix', url: 'https://www.netflix.com' },
  'nettflix.com': { name: 'Netflix', url: 'https://www.netflix.com' },
  // Flipkart
  'flickart.com': { name: 'Flipkart', url: 'https://www.flipkart.com' },
  'fipkart.com':  { name: 'Flipkart', url: 'https://www.flipkart.com' },
  'flipcart.com': { name: 'Flipkart', url: 'https://www.flipkart.com' },
  'fliokart.com': { name: 'Flipkart', url: 'https://www.flipkart.com' },
  'flipkat.com':  { name: 'Flipkart', url: 'https://www.flipkart.com' },
  'flipkert.com': { name: 'Flipkart', url: 'https://www.flipkart.com' },
  'flikpart.com': { name: 'Flipkart', url: 'https://www.flipkart.com' },
  // Paytm
  'paytrn.com':   { name: 'Paytm', url: 'https://www.paytm.com' },
  'paitm.com':    { name: 'Paytm', url: 'https://www.paytm.com' },
  'paytmm.com':   { name: 'Paytm', url: 'https://www.paytm.com' },
  'paytim.com':   { name: 'Paytm', url: 'https://www.paytm.com' },
  'paymt.com':    { name: 'Paytm', url: 'https://www.paytm.com' },
  'patym.com':    { name: 'Paytm', url: 'https://www.paytm.com' },
  // Zomato
  'zomatto.com':  { name: 'Zomato', url: 'https://www.zomato.com' },
  'zomat0.com':   { name: 'Zomato', url: 'https://www.zomato.com' },
  'zoomato.com':  { name: 'Zomato', url: 'https://www.zomato.com' },
  'zomto.com':    { name: 'Zomato', url: 'https://www.zomato.com' },
  'zmato.com':    { name: 'Zomato', url: 'https://www.zomato.com' },
  // Swiggy
  'swigy.com':    { name: 'Swiggy', url: 'https://www.swiggy.com' },
  'swwiggy.com':  { name: 'Swiggy', url: 'https://www.swiggy.com' },
  'swiiggy.com':  { name: 'Swiggy', url: 'https://www.swiggy.com' },
  'sviggy.com':   { name: 'Swiggy', url: 'https://www.swiggy.com' },
  'siwggy.com':   { name: 'Swiggy', url: 'https://www.swiggy.com' },
  // Discord
  'discrod.com':  { name: 'Discord', url: 'https://discord.com' },
  'discordd.com': { name: 'Discord', url: 'https://discord.com' },
  'discor.com':   { name: 'Discord', url: 'https://discord.com' },
  'doscord.com':  { name: 'Discord', url: 'https://discord.com' },
  'disscord.com': { name: 'Discord', url: 'https://discord.com' },
  'dicord.com':   { name: 'Discord', url: 'https://discord.com' },
  'discard.com':  { name: 'Discord', url: 'https://discord.com' },
  // Reddit
  'reddt.com':    { name: 'Reddit', url: 'https://www.reddit.com' },
  'reddlt.com':   { name: 'Reddit', url: 'https://www.reddit.com' },
  'rediit.com':   { name: 'Reddit', url: 'https://www.reddit.com' },
  'reditt.com':   { name: 'Reddit', url: 'https://www.reddit.com' },
  'redditt.com':  { name: 'Reddit', url: 'https://www.reddit.com' },
  'redit.com':    { name: 'Reddit', url: 'https://www.reddit.com' },
  'readit.com':   { name: 'Reddit', url: 'https://www.reddit.com' },
  // WhatsApp
  'whatsap.com':   { name: 'WhatsApp', url: 'https://www.whatsapp.com' },
  'whatssapp.com': { name: 'WhatsApp', url: 'https://www.whatsapp.com' },
  'watsapp.com':   { name: 'WhatsApp', url: 'https://www.whatsapp.com' },
  'whatsappp.com': { name: 'WhatsApp', url: 'https://www.whatsapp.com' },
  'whatsaap.com':  { name: 'WhatsApp', url: 'https://www.whatsapp.com' },
  'whatapp.com':   { name: 'WhatsApp', url: 'https://www.whatsapp.com' },
  'whtsapp.com':   { name: 'WhatsApp', url: 'https://www.whatsapp.com' },
  'wahtsapp.com':  { name: 'WhatsApp', url: 'https://www.whatsapp.com' },
  // SBI
  'onlinesbi.com':    { name: 'SBI Bank', url: 'https://www.onlinesbi.sbi' },
  'sbi-online.com':   { name: 'SBI Bank', url: 'https://www.onlinesbi.sbi' },
  'sbionline.com':    { name: 'SBI Bank', url: 'https://www.onlinesbi.sbi' },
  'sbionline.in':     { name: 'SBI Bank', url: 'https://www.onlinesbi.sbi' },
  'sbi-netbanking.com': { name: 'SBI Bank', url: 'https://www.onlinesbi.sbi' },
  // HDFC
  'hdfcbnak.com':     { name: 'HDFC Bank', url: 'https://www.hdfcbank.com' },
  'hdfcbankk.com':    { name: 'HDFC Bank', url: 'https://www.hdfcbank.com' },
  'hdfc-bank.com':    { name: 'HDFC Bank', url: 'https://www.hdfcbank.com' },
  'hdfbank.com':      { name: 'HDFC Bank', url: 'https://www.hdfcbank.com' },
  'hdfcbonk.com':     { name: 'HDFC Bank', url: 'https://www.hdfcbank.com' },
  // ICICI
  'icicibnak.com':    { name: 'ICICI Bank', url: 'https://www.icicibank.com' },
  'icici-bank.com':   { name: 'ICICI Bank', url: 'https://www.icicibank.com' },
  'icicibankk.com':   { name: 'ICICI Bank', url: 'https://www.icicibank.com' },
  'icicbank.com':     { name: 'ICICI Bank', url: 'https://www.icicibank.com' },
  // Microsoft
  'microsft.com':     { name: 'Microsoft', url: 'https://www.microsoft.com' },
  'mircosoft.com':    { name: 'Microsoft', url: 'https://www.microsoft.com' },
  'microsodt.com':    { name: 'Microsoft', url: 'https://www.microsoft.com' },
  'microsoftt.com':   { name: 'Microsoft', url: 'https://www.microsoft.com' },
  'microsfot.com':    { name: 'Microsoft', url: 'https://www.microsoft.com' },
  'microsot.com':     { name: 'Microsoft', url: 'https://www.microsoft.com' },
  'micosoft.com':     { name: 'Microsoft', url: 'https://www.microsoft.com' },
  // Apple
  'aple.com':    { name: 'Apple', url: 'https://www.apple.com' },
  'applee.com':  { name: 'Apple', url: 'https://www.apple.com' },
  'aplle.com':   { name: 'Apple', url: 'https://www.apple.com' },
  'apples.com':  { name: 'Apple', url: 'https://www.apple.com' },
  'appile.com':  { name: 'Apple', url: 'https://www.apple.com' },
  'aplpe.com':   { name: 'Apple', url: 'https://www.apple.com' },
  'appple.com':  { name: 'Apple', url: 'https://www.apple.com' },
  'appel.com':   { name: 'Apple', url: 'https://www.apple.com' },
  'appie.com':   { name: 'Apple', url: 'https://www.apple.com' },
  // Spotify
  'sportify.com':  { name: 'Spotify', url: 'https://www.spotify.com' },
  'spotfy.com':    { name: 'Spotify', url: 'https://www.spotify.com' },
  'sp0tify.com':   { name: 'Spotify', url: 'https://www.spotify.com' },
  'spotifyy.com':  { name: 'Spotify', url: 'https://www.spotify.com' },
  'spottify.com':  { name: 'Spotify', url: 'https://www.spotify.com' },
  'spotfiy.com':   { name: 'Spotify', url: 'https://www.spotify.com' },
  // Myntra
  'myntraa.com':  { name: 'Myntra', url: 'https://www.myntra.com' },
  'myntra.in':    { name: 'Myntra', url: 'https://www.myntra.com' },
  'mynttra.com':  { name: 'Myntra', url: 'https://www.myntra.com' },
  'mintra.com':   { name: 'Myntra', url: 'https://www.myntra.com' },
  'mymtra.com':   { name: 'Myntra', url: 'https://www.myntra.com' },
  // Nykaa
  'nykaaa.com':   { name: 'Nykaa', url: 'https://www.nykaa.com' },
  'nykaa.in':     { name: 'Nykaa', url: 'https://www.nykaa.com' },
  'nykkaa.com':   { name: 'Nykaa', url: 'https://www.nykaa.com' },
  'nykka.com':    { name: 'Nykaa', url: 'https://www.nykaa.com' },
  // IRCTC
  'irtc.co.in':        { name: 'IRCTC', url: 'https://www.irctc.co.in' },
  'irctcc.co.in':      { name: 'IRCTC', url: 'https://www.irctc.co.in' },
  'irctc.com':         { name: 'IRCTC', url: 'https://www.irctc.co.in' },
  'irctconline.com':   { name: 'IRCTC', url: 'https://www.irctc.co.in' },
  'irctcbook.com':     { name: 'IRCTC', url: 'https://www.irctc.co.in' },
  'irctc-booking.com': { name: 'IRCTC', url: 'https://www.irctc.co.in' },
  // ChatGPT / OpenAI
  'chatgp.com':    { name: 'ChatGPT', url: 'https://chatgpt.com' },
  'chatgptt.com':  { name: 'ChatGPT', url: 'https://chatgpt.com' },
  'chatgbt.com':   { name: 'ChatGPT', url: 'https://chatgpt.com' },
  'chatgot.com':   { name: 'ChatGPT', url: 'https://chatgpt.com' },
  'chaatgpt.com':  { name: 'ChatGPT', url: 'https://chatgpt.com' },
  'opena1.com':    { name: 'OpenAI', url: 'https://openai.com' },
  'openaii.com':   { name: 'OpenAI', url: 'https://openai.com' },
  'opneai.com':    { name: 'OpenAI', url: 'https://openai.com' },
  'open-ai.com':   { name: 'OpenAI', url: 'https://openai.com' },
};

// -------------------------------------------------------
// QUICK LOCAL RISK CHECK
// Runs instantly — no API, pure JS pattern matching
// -------------------------------------------------------
function quickRiskCheck(url) {
  let score = 100;
  const reasons = [];
  let realSite = null;

  try {
    const lower = url.toLowerCase();
    const domain = new URL(url).hostname.toLowerCase();
    const path = new URL(url).pathname.toLowerCase();
    const cleanDomain = domain.replace(/^www\./, '');

    // Whitelisted — always safe
    if (isWhitelisted(domain)) {
      return { score: 100, flagged: false, reasons: [], realSite: null };
    }

    // Typosquat check — runs FIRST before all other checks
    if (TYPOSQUAT_MAP[cleanDomain]) {
      const match = TYPOSQUAT_MAP[cleanDomain];
      score -= 75;
      reasons.push(`Possible typo — did you mean '${match.name}' (${match.url.replace('https://', '')})?`);
      realSite = { name: match.name, url: match.url };
    }

    // No HTTPS
    if (url.startsWith("http://")) {
      score -= 20;
      reasons.push("No SSL encryption (HTTP not HTTPS)");
    }

    // Raw IP address
    if (/^\d+\.\d+\.\d+\.\d+/.test(domain)) {
      score -= 35;
      reasons.push("Raw IP address used instead of domain name");
    }

    // Suspicious TLDs
    const badTlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
                     '.click', '.download', '.loan', '.win', '.party', '.racing'];
    if (badTlds.some(t => domain.endsWith(t))) {
      score -= 25;
      reasons.push("Suspicious domain extension (commonly used in scams)");
    }

    // Brand impersonation with real site recommendation
    const brandMap = {
      'google':    { real: 'https://www.google.com',      name: 'Google' },
      'facebook':  { real: 'https://www.facebook.com',    name: 'Facebook' },
      'amazon':    { real: 'https://www.amazon.in',       name: 'Amazon' },
      'apple':     { real: 'https://www.apple.com',       name: 'Apple' },
      'microsoft': { real: 'https://www.microsoft.com',   name: 'Microsoft' },
      'paypal':    { real: 'https://www.paypal.com',      name: 'PayPal' },
      'netflix':   { real: 'https://www.netflix.com',     name: 'Netflix' },
      'instagram': { real: 'https://www.instagram.com',   name: 'Instagram' },
      'whatsapp':  { real: 'https://www.whatsapp.com',    name: 'WhatsApp' },
      'twitter':   { real: 'https://www.twitter.com',     name: 'Twitter' },
      'flipkart':  { real: 'https://www.flipkart.com',    name: 'Flipkart' },
      'myntra':    { real: 'https://www.myntra.com',      name: 'Myntra' },
      'sbi':       { real: 'https://www.onlinesbi.sbi',   name: 'SBI Bank' },
      'hdfc':      { real: 'https://www.hdfcbank.com',    name: 'HDFC Bank' },
      'icici':     { real: 'https://www.icicibank.com',   name: 'ICICI Bank' },
      'paytm':     { real: 'https://www.paytm.com',       name: 'Paytm' },
      'phonepe':   { real: 'https://www.phonepe.com',     name: 'PhonePe' },
      'zomato':    { real: 'https://www.zomato.com',      name: 'Zomato' },
      'swiggy':    { real: 'https://www.swiggy.com',      name: 'Swiggy' },
      'youtube':   { real: 'https://www.youtube.com',     name: 'YouTube' },
      'linkedin':  { real: 'https://www.linkedin.com',    name: 'LinkedIn' }
    };

    for (const [brand, info] of Object.entries(brandMap)) {
      if (domain.includes(brand) && !isLegitBrandDomain(brand, domain)) {
        score -= 35;
        reasons.push(`Fake '${info.name}' site — NOT the real ${info.name}`);
        realSite = { name: info.name, url: info.real };
        break;
      }
    }

    // Misspelled brands (leet speak)
    const leetMap = {
      'amaz0n':    { real: 'https://www.amazon.in',      name: 'Amazon' },
      'g00gle':    { real: 'https://www.google.com',     name: 'Google' },
      'g0ogle':    { real: 'https://www.google.com',     name: 'Google' },
      'paypa1':    { real: 'https://www.paypal.com',     name: 'PayPal' },
      'paypai':    { real: 'https://www.paypal.com',     name: 'PayPal' },
      'micros0ft': { real: 'https://www.microsoft.com',  name: 'Microsoft' },
      'netfl1x':   { real: 'https://www.netflix.com',    name: 'Netflix' },
      'faceb00k':  { real: 'https://www.facebook.com',   name: 'Facebook' },
      'appl3':     { real: 'https://www.apple.com',      name: 'Apple' },
      'fl1pkart':  { real: 'https://www.flipkart.com',   name: 'Flipkart' },
      'flickart':  { real: 'https://www.flipkart.com',   name: 'Flipkart' },
      'fllpkart':  { real: 'https://www.flipkart.com',   name: 'Flipkart' },
      'flipkart0': { real: 'https://www.flipkart.com',   name: 'Flipkart' }
    };

    for (const [fake, info] of Object.entries(leetMap)) {
      if (domain.includes(fake)) {
        score -= 40;
        reasons.push(`Misspelled '${info.name}' detected — possible impersonation`);
        if (!realSite) realSite = { name: info.name, url: info.real };
        break;
      }
    }

    // Too many hyphens
    const hyphens = (domain.match(/-/g) || []).length;
    if (hyphens >= 3) { score -= 25; reasons.push("Multiple hyphens in domain name"); }
    else if (hyphens === 2) { score -= 12; }

    // Too many subdomains
    const dots = (domain.match(/\./g) || []).length;
    if (dots >= 4) { score -= 25; reasons.push("Excessive subdomains — suspicious structure"); }

    // Dangerous file downloads
    const dangerExt = ['.exe', '.bat', '.cmd', '.msi', '.vbs', '.scr', '.apk', '.ps1'];
    if (dangerExt.some(e => path.endsWith(e))) {
      score -= 40;
      reasons.push("URL links to a dangerous file download");
    }

    // Scam keywords in URL
    const scamWords = ['free-iphone', 'win-prize', 'claim-prize', 'lucky-draw',
                       'instant-cash', 'lottery', 'jackpot', 'free-gift',
                       'winner', 'giveaway', 'free-recharge', 'cash-reward'];
    const foundScam = scamWords.filter(w => lower.includes(w));
    if (foundScam.length >= 2) {
      score -= 35; reasons.push(`Scam keywords in URL: ${foundScam.slice(0, 2).join(', ')}`);
    } else if (foundScam.length === 1) {
      score -= 18; reasons.push(`Scam keyword in URL: ${foundScam[0]}`);
    }

    // Sensitive data keywords in URL
    const sensitiveWords = ['otp', 'cvv', 'aadhaar', 'pan-card',
                            'bank-detail', 'kyc', 'verify-account', 'ifsc'];
    const foundSensitive = sensitiveWords.filter(w => lower.includes(w));
    if (foundSensitive.length >= 2) {
      score -= 30; reasons.push(`Sensitive keywords in URL: ${foundSensitive.slice(0, 2).join(', ')}`);
    } else if (foundSensitive.length === 1) {
      score -= 12; reasons.push(`Sensitive keyword in URL: ${foundSensitive[0]}`);
    }

    // Very long URL
    if (url.length > 200) { score -= 25; reasons.push("Unusually long URL — possible obfuscation"); }
    else if (url.length > 120) { score -= 12; }

    // @ symbol trick
    if (lower.includes('@')) {
      score -= 25; reasons.push("@ symbol in URL — classic phishing trick");
    }

    // Redirect patterns
    if (['redirect', 'redir', 'goto', 'click?url='].some(w => lower.includes(w))) {
      score -= 20; reasons.push("URL contains a redirect");
    }

  } catch (e) {
    console.log("quickRiskCheck error:", e);
  }

  return { score: Math.max(score, 5), flagged: score < 100, reasons, realSite };
}


// -------------------------------------------------------
// PAGE CONTENT ANALYZER
// Injected into the loaded page — checks DOM for risks
// -------------------------------------------------------
function analyzePageContent() {
  let score = 100;
  const reasons = [];

  try {
    const body = document.body;
    if (!body) return { score: 100, reasons: [], flagged: false };

    const text = body.innerText.toLowerCase();
    const title = document.title.toLowerCase();
    const forms = document.querySelectorAll("form");
    const inputs = document.querySelectorAll("input");
    const images = document.querySelectorAll("img");

    // Check for sensitive input fields
    const hasOtp      = Array.from(inputs).some(i => (i.placeholder||i.name||i.id||"").toLowerCase().includes("otp"));
    const hasAadhaar  = Array.from(inputs).some(i => (i.placeholder||i.name||i.id||"").toLowerCase().includes("aadhaar"));
    const hasPan      = Array.from(inputs).some(i => (i.placeholder||i.name||i.id||"").toLowerCase().includes("pan"));
    const hasCvv      = Array.from(inputs).some(i => (i.placeholder||i.name||i.id||"").toLowerCase().includes("cvv"));
    const hasPassword = Array.from(inputs).some(i => i.type === "password");
    const hasBank     = Array.from(inputs).some(i => {
      const v = (i.placeholder||i.name||i.id||"").toLowerCase();
      return v.includes("account number") || v.includes("ifsc");
    });

    if (hasOtp)     { score -= 25; reasons.push("Page asks for OTP — verify this is a trusted site"); }
    if (hasAadhaar) { score -= 30; reasons.push("Page asks for Aadhaar number — very sensitive"); }
    if (hasPan)     { score -= 25; reasons.push("Page asks for PAN card number"); }
    if (hasCvv)     { score -= 35; reasons.push("Page asks for CVV — never enter on unverified sites"); }
    if (hasBank)    { score -= 35; reasons.push("Page asks for bank account / IFSC code"); }

    // Urgency pressure tactics
    const urgency = ['act now', 'limited time', 'expires today', 'urgent action',
      'act immediately', 'verify now', 'account suspended', 'account blocked',
      'last chance', 'final warning', 'within 24 hours', 'within 48 hours'];
    const foundUrgency = urgency.filter(w => text.includes(w));
    if (foundUrgency.length >= 2) { score -= 25; reasons.push("Urgency pressure tactics on page"); }
    else if (foundUrgency.length === 1) { score -= 12; reasons.push(`Urgency language: "${foundUrgency[0]}"`); }

    // Scam phrases in page text
    const scamPhrases = ['you have won', 'congratulations you', 'free iphone',
      'claim your prize', 'lucky winner', 'you are selected',
      'free gift', 'you have been chosen', 'instant cash', 'cash prize'];
    const foundScam = scamPhrases.filter(w => text.includes(w));
    if (foundScam.length >= 2) { score -= 30; reasons.push("Multiple scam phrases on page"); }
    else if (foundScam.length === 1) { score -= 15; reasons.push(`Scam phrase: "${foundScam[0]}"`); }

    // Broken images (sign of copied fake site)
    const brokenImgs = Array.from(images).filter(img => !img.complete || img.naturalWidth === 0);
    if (brokenImgs.length >= 3) { score -= 15; reasons.push("Multiple broken images — possibly a copied fake site"); }

    // Form submits to a different domain
    const currentDomain = window.location.hostname;
    const suspiciousForms = Array.from(forms).filter(form => {
      const action = form.action || "";
      if (!action || action.startsWith("#") || action.startsWith("/")) return false;
      try {
        const fd = new URL(action).hostname;
        return fd !== currentDomain && fd !== "";
      } catch { return false; }
    });
    if (suspiciousForms.length > 0) { score -= 30; reasons.push("Form submits data to a different domain — data theft risk"); }

    // Page title impersonates a known brand
    const knownBrands = ['sbi', 'hdfc', 'icici', 'paypal', 'amazon',
                         'flipkart', 'paytm', 'google', 'facebook', 'phonepe'];
    const domain = window.location.hostname.toLowerCase();
    for (const brand of knownBrands) {
      if (title.includes(brand) && !domain.includes(brand)) {
        score -= 30;
        reasons.push(`Page title claims to be '${brand}' but URL doesn't match`);
        break;
      }
    }

    // No privacy policy on login page
    if (hasPassword || hasOtp) {
      const hasPrivacy = text.includes("privacy policy") || text.includes("terms of service");
      const hasContact = text.includes("contact us") || text.includes("support@");
      if (!hasPrivacy && !hasContact) {
        score -= 15; reasons.push("No privacy policy or contact info on login page");
      }
    }

    // Fake security badges
    const fakeTrust = ['100% secure', '100% safe', 'hack proof',
                       'certified secure', 'safe checkout guaranteed'];
    if (fakeTrust.filter(w => text.includes(w)).length >= 2) {
      score -= 15; reasons.push("Excessive fake security claims on page");
    }

  } catch (e) {
    console.log("analyzePageContent error:", e);
  }

  return { score: Math.max(score, 5), reasons, flagged: score < 100 };
}


// -------------------------------------------------------
// SHOW RISK OVERLAY
// iframe overlay — independent of page DOM
// Survives redirects via 500ms re-injection for 10 seconds
// -------------------------------------------------------
function showRiskOverlay(data) {
  // Remove any existing overlay
  const existing = document.getElementById("browseguard-frame");
  if (existing) existing.remove();

  const score = data.score;
  const scoreColor = score < 40 ? "#e74c3c" : score < 60 ? "#f39c12" : "#27ae60";
  const reasons = data.reasons || [];
  const realSite = data.realSite || null;
  const explanation = data.explanation || "";

  const reasonsHTML = reasons.length > 0
    ? reasons.map(r => `
        <div style="font-size:12px;color:#555;padding:5px 8px;background:#fff5f5;
                    border-left:3px solid ${scoreColor};border-radius:0 6px 6px 0;margin-bottom:4px">
          ${r}
        </div>`).join("")
    : `<div style="font-size:12px;color:#888;font-style:italic">Analyzing threats...</div>`;

  const realSiteHTML = realSite ? `
    <div style="background:#e8f5e9;border-radius:8px;padding:10px;margin-bottom:12px;
                display:flex;align-items:center;justify-content:space-between">
      <div style="flex:1">
        <div style="font-size:11px;color:#388e3c;font-weight:700;margin-bottom:3px">✅ REAL WEBSITE</div>
        <div style="font-size:12px;color:#1b5e20;font-weight:600">${realSite.name}</div>
        <div style="font-size:10px;color:#388e3c;margin-top:2px">${realSite.url}</div>
      </div>
      <button onclick="window.top.location.href='${realSite.url}'"
        style="background:#27ae60;color:#fff;border:none;padding:8px 12px;
               border-radius:8px;cursor:pointer;font-size:12px;font-weight:700;
               white-space:nowrap;margin-left:10px;flex-shrink:0">
        Go There →
      </button>
    </div>` : '';

  // -------------------------------------------------------
  // PARSE STRUCTURED AI RESPONSE
  // Expected format from Groq:
  // THREAT: ...
  // TARGET: ...
  // RISK: ...
  // ACTION: LEAVE or CAUTION
  // -------------------------------------------------------
  function parseAIResponse(text) {
    if (!text) return null;
    const lines = text.split('\n');
    const parsed = {};
    lines.forEach(line => {
      if (line.startsWith('THREAT:')) parsed.threat = line.replace('THREAT:', '').trim();
      if (line.startsWith('TARGET:')) parsed.target = line.replace('TARGET:', '').trim();
      if (line.startsWith('RISK:'))   parsed.risk   = line.replace('RISK:', '').trim();
      if (line.startsWith('ACTION:')) parsed.action = line.replace('ACTION:', '').trim();
    });
    return Object.keys(parsed).length >= 2 ? parsed : null;
  }

  const aiParsed = parseAIResponse(explanation);

  // Build AI explanation HTML — structured if parsed, plain text fallback
  let explanationHTML = '';

  if (aiParsed) {
    // Structured threat report
    const actionBadge = aiParsed.action === 'LEAVE'
      ? `<div style="font-size:11px;background:#e74c3c;color:white;padding:3px 10px;
                    border-radius:4px;display:inline-block;margin-top:6px;font-weight:700">
           ⛔ LEAVE IMMEDIATELY
         </div>`
      : `<div style="font-size:11px;background:#f39c12;color:white;padding:3px 10px;
                    border-radius:4px;display:inline-block;margin-top:6px;font-weight:700">
           ⚠️ PROCEED WITH CAUTION
         </div>`;

    explanationHTML = `
      <div style="background:#fff8e1;border-radius:8px;padding:10px;margin-bottom:12px">
        <div style="font-size:11px;font-weight:700;color:#e65100;margin-bottom:8px;
                    letter-spacing:0.3px">🤖 AI THREAT ANALYSIS</div>
        ${aiParsed.threat ? `
          <div style="font-size:12px;color:#333;margin-bottom:5px;line-height:1.4">
            <span style="font-weight:700;color:#555">Threat: </span>${aiParsed.threat}
          </div>` : ''}
        ${aiParsed.target ? `
          <div style="font-size:12px;color:#555;margin-bottom:5px;line-height:1.4">
            <span style="font-weight:700">Target: </span>${aiParsed.target}
          </div>` : ''}
        ${aiParsed.risk ? `
          <div style="font-size:12px;color:#555;margin-bottom:4px;line-height:1.4">
            <span style="font-weight:700">At risk: </span>${aiParsed.risk}
          </div>` : ''}
        ${actionBadge}
      </div>`;

  } else if (explanation && explanation !== "Analyzing with AI...") {
    // Plain text fallback
    explanationHTML = `
      <div style="font-size:12px;color:#333;background:#fff8e1;padding:8px;
                  border-radius:6px;margin-bottom:12px;line-height:1.5">
        🤖 ${explanation}
      </div>`;

  } else {
    // Loading state
    explanationHTML = `
      <div style="font-size:12px;color:#999;font-style:italic;margin-bottom:12px">
        🤖 AI analysis loading...
      </div>`;
  }

  const iframeHTML = `<!DOCTYPE html>
<html><head><style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body {
    font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
    background:transparent;
  }
  .card {
    background:#fff;
    border:2px solid ${scoreColor};
    border-radius:14px;
    padding:18px;
    width:320px;
    box-shadow:0 8px 32px rgba(0,0,0,0.25);
  }
</style></head>
<body>
<div class="card">

  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
    <div style="display:flex;align-items:center;gap:8px">
      <span style="font-size:22px">⚠️</span>
      <strong style="color:${scoreColor};font-size:15px">Risk Detected</strong>
    </div>
    <button onclick="window.frameElement.parentElement.remove()"
      style="background:none;border:none;font-size:20px;color:#bbb;padding:0;cursor:pointer">✕</button>
  </div>

  <div style="background:#f8f8f8;border-radius:10px;padding:12px;text-align:center;margin-bottom:12px">
    <div style="font-size:38px;font-weight:700;color:${scoreColor};line-height:1">
      ${score}<span style="font-size:14px;color:#999">/100</span>
    </div>
    <div style="font-size:11px;color:#999;margin-top:4px">Risk Score</div>
    <div style="height:6px;background:#eee;border-radius:3px;margin-top:8px;overflow:hidden">
      <div style="height:100%;width:${score}%;background:${scoreColor};border-radius:3px"></div>
    </div>
  </div>

  <div style="margin-bottom:10px">${reasonsHTML}</div>

  ${explanationHTML}

  ${realSiteHTML}

  <div style="display:flex;gap:8px">
    <button onclick="window.top.history.back();window.frameElement.parentElement.remove()"
      style="flex:1;background:${scoreColor};color:#fff;border:none;
             padding:10px;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer">
      Leave Now
    </button>
    <button onclick="window.frameElement.parentElement.remove()"
      style="flex:1;background:#f0f0f0;color:#444;border:none;
             padding:10px;border-radius:8px;font-size:13px;cursor:pointer">
      Stay Anyway
    </button>
  </div>

</div>
</body></html>`;

  function injectFrame() {
    const iframe = document.createElement("iframe");
    iframe.id = "browseguard-frame";
    iframe.setAttribute("sandbox", "allow-scripts allow-top-navigation allow-same-origin");
    iframe.style.cssText = `
      position:fixed !important;
      top:20px !important;
      right:20px !important;
      width:344px !important;
      height:560px !important;
      border:none !important;
      z-index:2147483647 !important;
      border-radius:14px !important;
      background:transparent !important;
    `;
    iframe.srcdoc = iframeHTML;
    document.documentElement.appendChild(iframe);
  }

  injectFrame();

  // Re-inject every 500ms for 10 seconds to survive page redirects
  let count = 0;
  const reinjector = setInterval(() => {
    count++;
    if (count > 20) { clearInterval(reinjector); return; }
    if (!document.getElementById("browseguard-frame")) {
      injectFrame();
    }
  }, 500);
}


async function blockIfRisky(tabId, url) {
  const result = quickRiskCheck(url);
  if (result.score >= 50) return;

  const warningUrl = chrome.runtime.getURL("warning.html") +
    "?url=" + encodeURIComponent(url) +
    "&score=" + result.score +
    "&reasons=" + encodeURIComponent(JSON.stringify(result.reasons.slice(0, 3))) +
    (result.realSite ? "&realName=" + encodeURIComponent(result.realSite.name) +
                       "&realUrl=" + encodeURIComponent(result.realSite.url) : "");

  try {
    await chrome.tabs.update(tabId, { url: warningUrl });
  } catch(e) {
    console.log("Block error:", e.message);
  }
}