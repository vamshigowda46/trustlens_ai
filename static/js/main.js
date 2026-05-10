/**
 * TrustLens AI – main.js
 * Handles: AJAX scans, trust score animation, result rendering,
 *          chatbot UI, red flags, loader helpers, auto-dismiss alerts
 */

// ── AJAX Helper ────────────────────────────────────────────────────────────────
async function postScan(endpoint, payload) {
  const res = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (!res.ok) throw new Error('Network error ' + res.status);
  return res.json();
}

// ── Loader Helpers ─────────────────────────────────────────────────────────────
function showLoader(loaderId, defaultId) {
  const loader  = document.getElementById(loaderId);
  const def     = document.getElementById(defaultId);
  const panel   = document.getElementById('resultPanel');
  if (loader) loader.style.display = 'block';
  if (def)    def.style.display    = 'none';
  if (panel)  panel.style.display  = 'none';
}

function hideLoader(loaderId) {
  const loader = document.getElementById(loaderId);
  if (loader) loader.style.display = 'none';
}

function showDefaultState(defaultId, msg) {
  const def = document.getElementById(defaultId);
  if (!def) return;
  def.style.display = 'block';
  const p = def.querySelector('p');
  if (p && msg) p.textContent = msg;
}

// ── Trust Score Animation ──────────────────────────────────────────────────────
function animateTrustScore(score) {
  const circumference = 408.4;
  const offset = circumference - (score / 100) * circumference;
  const color = score >= 90 ? '#00ff88' : score >= 60 ? '#ffd700' : '#ff3366';

  // Counter
  const numEl = document.getElementById('trustNum');
  if (numEl) {
    let current = 0;
    const step = Math.max(1, Math.ceil(score / 40));
    const timer = setInterval(() => {
      current = Math.min(current + step, score);
      numEl.textContent = current;
      numEl.style.color = color;
      if (current >= score) clearInterval(timer);
    }, 30);
  }

  // SVG circle
  const circle = document.getElementById('trustCircle');
  if (circle) {
    circle.style.stroke = color;
    circle.style.strokeDashoffset = circumference;
    requestAnimationFrame(() => requestAnimationFrame(() => {
      circle.style.strokeDashoffset = offset;
    }));
  }

  // Linear bar
  const bar = document.getElementById('trustBar');
  if (bar) {
    bar.style.background = color;
    setTimeout(() => { bar.style.width = score + '%'; }, 100);
  }

  // Risk label
  const riskEl = document.getElementById('riskLabel');
  if (riskEl) {
    const map = { safe: ['✓ Safe', '#00ff88'], suspicious: ['⚠ Suspicious', '#ffd700'], dangerous: ['✗ Dangerous', '#ff3366'] };
    const key = score >= 90 ? 'safe' : score >= 60 ? 'suspicious' : 'dangerous';
    riskEl.textContent = map[key][0];
    riskEl.style.color = map[key][1];
  }
}

// ── Result Badge ───────────────────────────────────────────────────────────────
function setResultBadge(result) {
  const badge = document.getElementById('resultBadge');
  if (!badge) return;
  const safe = ['SAFE', 'VERIFIED'];
  const warn = ['SUSPICIOUS', 'NOT FOUND', 'SUSPENDED'];
  badge.className = 'result-badge';
  if (safe.includes(result)) {
    badge.classList.add('badge-safe');
    badge.innerHTML = `<i class="bi bi-shield-check"></i> ${result}`;
  } else if (warn.includes(result)) {
    badge.classList.add('badge-warning');
    badge.innerHTML = `<i class="bi bi-exclamation-triangle"></i> ${result}`;
  } else {
    badge.classList.add('badge-danger');
    badge.innerHTML = `<i class="bi bi-shield-x"></i> ${result}`;
  }
}

// ── Keyword Tags ───────────────────────────────────────────────────────────────
function renderKeywords(keywords) {
  const wrap = document.getElementById('keywordsWrap');
  const list = document.getElementById('keywordsList');
  if (!wrap || !list) return;
  if (keywords && keywords.length > 0) {
    list.innerHTML = keywords.map(kw =>
      `<span class="keyword-tag"><i class="bi bi-exclamation-circle me-1"></i>${kw}</span>`
    ).join('');
    wrap.style.display = 'block';
  } else {
    wrap.style.display = 'none';
  }
}

// ── Main Render Function ───────────────────────────────────────────────────────
function renderResult(data) {
  const panel = document.getElementById('resultPanel');
  if (!panel) return;
  panel.style.display = 'block';

  const titles = {
    'FAKE':       '🚨 Fake Job Detected',
    'SAFE':       '✅ Appears Safe',
    'SCAM':       '🚨 Scam Message Detected',
    'FRAUDULENT': '🚨 Fraudulent Loan App',
    'DANGEROUS':  '🚨 Dangerous URL',
    'SUSPICIOUS': '⚠️ Suspicious – Proceed with Caution',
    'VERIFIED':   '✅ Verified & Registered',
    'NOT FOUND':  '⚠️ Not Found in Database',
    'BLACKLISTED':'🚨 Blacklisted Entity',
    'SUSPENDED':  '⚠️ Suspended Entity',
    'ERROR':      '❌ Analysis Error'
  };

  const resultText = document.getElementById('resultText');
  if (resultText) resultText.textContent = titles[data.result] || data.result;

  const explanationText = document.getElementById('explanationText');
  if (explanationText) explanationText.textContent = data.explanation || '';

  animateTrustScore(data.trust_score || 0);
  setResultBadge(data.result);
  renderKeywords(data.keywords || []);
}

// ── Chatbot ────────────────────────────────────────────────────────────────────
let chatOpen = false;

function toggleChat() {
  chatOpen = !chatOpen;
  const win = document.getElementById('chatWindow');
  const icon = document.getElementById('chatFabIcon');
  if (!win) return;
  if (chatOpen) {
    win.style.display = 'flex';
    if (icon) icon.className = 'bi bi-x-lg';
    document.getElementById('chatInput')?.focus();
  } else {
    win.style.display = 'none';
    if (icon) icon.className = 'bi bi-robot';
  }
}

function sendQuick(msg) {
  const input = document.getElementById('chatInput');
  if (input) { input.value = msg; sendChat(); }
}

async function sendChat() {
  const input = document.getElementById('chatInput');
  const messages = document.getElementById('chatMessages');
  if (!input || !messages) return;

  const msg = input.value.trim();
  if (!msg) return;
  input.value = '';

  // Hide quick buttons after first message
  const quickBtns = document.getElementById('quickBtns');
  if (quickBtns) quickBtns.style.display = 'none';

  // Add user message
  const userDiv = document.createElement('div');
  userDiv.className = 'chat-msg user';
  userDiv.textContent = msg;
  messages.appendChild(userDiv);
  messages.scrollTop = messages.scrollHeight;

  // Typing indicator
  const typing = document.createElement('div');
  typing.className = 'chat-typing';
  typing.id = 'typingIndicator';
  typing.innerHTML = '<span></span><span></span><span></span>';
  messages.appendChild(typing);
  messages.scrollTop = messages.scrollHeight;

  try {
    const res = await fetch('/api/chatbot', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: msg })
    });

    // Remove typing indicator
    const t = document.getElementById('typingIndicator');
    if (t) t.remove();

    // Parse response — works even on 4xx/5xx
    let responseText = 'Sorry, I could not process that.';
    try {
      const data = await res.json();
      responseText = data.response || responseText;
    } catch(e) {}

    // Add bot response
    const botDiv = document.createElement('div');
    botDiv.className = 'chat-msg bot';
    botDiv.innerHTML = responseText
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/\n/g, '<br>');
    messages.appendChild(botDiv);

  } catch(e) {
    const t = document.getElementById('typingIndicator');
    if (t) t.remove();
    const errDiv = document.createElement('div');
    errDiv.className = 'chat-msg bot';
    errDiv.textContent = 'Connection error. Please check your internet and try again.';
    messages.appendChild(errDiv);
  }

  messages.scrollTop = messages.scrollHeight;
}

// ── DOMContentLoaded ───────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  // Auto-dismiss flash alerts after 4s
  document.querySelectorAll('.alert.fade.show').forEach(alert => {
    setTimeout(() => {
      try { bootstrap.Alert.getOrCreateInstance(alert).close(); } catch(e) {}
    }, 4000);
  });

  // Animate trust bars on page load (history/dashboard)
  document.querySelectorAll('.trust-bar').forEach(bar => {
    const w = bar.style.width;
    bar.style.width = '0%';
    setTimeout(() => { bar.style.width = w; }, 300 + Math.random() * 200);
  });

  // Smooth scroll for anchor links
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function(e) {
      const target = document.querySelector(this.getAttribute('href'));
      if (target) { e.preventDefault(); target.scrollIntoView({ behavior: 'smooth' }); }
    });
  });

  // Close sidebar on mobile when clicking outside
  document.addEventListener('click', (e) => {
    const sidebar = document.getElementById('sidebar');
    const toggle  = document.getElementById('sidebarToggle');
    if (sidebar && sidebar.classList.contains('open') &&
        !sidebar.contains(e.target) && toggle && !toggle.contains(e.target)) {
      sidebar.classList.remove('open');
    }
  });
});
