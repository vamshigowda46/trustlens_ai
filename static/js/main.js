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
/** Trust score → color (aligned with server _risk_level bands). */
function trustScoreColor(score) {
  const s = Number(score) || 0;
  if (s >= 71) return '#00ff88';
  if (s >= 51) return '#00d4ff';
  if (s >= 31) return '#ffb020';
  return '#ff3366';
}

/** Label under trust meter (4 bands). */
function trustScoreLabel(score) {
  const s = Number(score) || 0;
  if (s >= 71) return '✓ Safe';
  if (s >= 51) return '◆ Moderate Risk';
  if (s >= 31) return '⚠ Suspicious';
  return '✗ Dangerous';
}

/** Tier slug from 0–100 score (matches server `trust_tier` / `_trust_tier_slug`). */
function trustTierFromScore(score) {
  const s = Number(score) || 0;
  if (s >= 71) return 'safe';
  if (s >= 51) return 'moderate';
  if (s >= 31) return 'suspicious';
  return 'dangerous';
}

/**
 * Unified presentation for trust-based UI (badge, colors, headline).
 * Dangerous tier uses red only; Safe uses green only.
 */
function trustPresentationFromScore(score) {
  const tier = trustTierFromScore(score);
  const map = {
    safe: {
      color: '#00ff88',
      badgeClass: 'badge-safe',
      badgeText: 'SAFE',
      headline: 'Trust band: safe — posting aligns with legitimate hiring patterns.',
    },
    moderate: {
      color: '#00d4ff',
      badgeClass: 'badge-moderate',
      badgeText: 'MODERATE RISK',
      headline: 'Trust band: moderate risk — verify employer and role details independently.',
    },
    suspicious: {
      color: '#ffb020',
      badgeClass: 'badge-suspicious-tier',
      badgeText: 'SUSPICIOUS',
      headline: 'Trust band: suspicious — multiple caution signals; do not share personal or payment data yet.',
    },
    dangerous: {
      color: '#ff3366',
      badgeClass: 'badge-danger',
      badgeText: 'DANGEROUS',
      headline: 'Trust band: dangerous — treat as a likely scam until proven otherwise on official channels.',
    },
  };
  return { tier, ...map[tier] };
}

function animateTrustScore(score) {
  const circumference = 408.4;
  const offset = circumference - (score / 100) * circumference;
  const color = trustScoreColor(score);

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
    riskEl.textContent = trustScoreLabel(score);
    riskEl.style.color = color;
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
const CHAT_STORAGE_KEY = 'trustlens_chat_turns_v1';
let chatOpen = false;
let voiceRecognition = null;

function escapeChatHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function formatBotMessageHtml(text) {
  const esc = escapeChatHtml(text);
  return esc
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/\n/g, '<br>');
}

function loadChatTurns() {
  try {
    const raw = sessionStorage.getItem(CHAT_STORAGE_KEY);
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr : [];
  } catch (e) {
    return [];
  }
}

function saveChatTurns(turns) {
  try {
    sessionStorage.setItem(CHAT_STORAGE_KEY, JSON.stringify(turns.slice(-6)));
  } catch (e) { /* quota */ }
}

function getSpeechRecognitionCtor() {
  return window.SpeechRecognition || window.webkitSpeechRecognition;
}

function stopVoiceInput() {
  const rec = voiceRecognition;
  voiceRecognition = null;
  if (rec) {
    try {
      rec.stop();
    } catch (e) { /* already stopped */ }
  }
  const btn = document.getElementById('chatMicBtn');
  const micIcon = document.getElementById('chatMicIcon');
  btn?.classList.remove('listening');
  if (micIcon) micIcon.className = 'bi bi-mic-fill';
}

function toggleVoiceChat() {
  const Ctor = getSpeechRecognitionCtor();
  const btn = document.getElementById('chatMicBtn');
  const input = document.getElementById('chatInput');
  if (!Ctor) {
    alert('Voice input needs a Chromium-based browser (Chrome or Edge) with microphone access.');
    return;
  }
  if (voiceRecognition) {
    stopVoiceInput();
    return;
  }
  voiceRecognition = new Ctor();
  voiceRecognition.lang = 'en-IN';
  voiceRecognition.interimResults = false;
  voiceRecognition.continuous = false;
  voiceRecognition.maxAlternatives = 1;

  voiceRecognition.onstart = () => {
    btn?.classList.add('listening');
    const micIcon = document.getElementById('chatMicIcon');
    if (micIcon) micIcon.className = 'bi bi-mic-mute-fill';
  };
  voiceRecognition.onend = () => {
    voiceRecognition = null;
    btn?.classList.remove('listening');
    const micIcon = document.getElementById('chatMicIcon');
    if (micIcon) micIcon.className = 'bi bi-mic-fill';
  };
  voiceRecognition.onerror = () => {
    stopVoiceInput();
  };
  voiceRecognition.onresult = (event) => {
    const text = (event.results[0] && event.results[0][0] && event.results[0][0].transcript) || '';
    if (input && text.trim()) {
      const cur = input.value.trim();
      input.value = cur ? `${cur} ${text.trim()}` : text.trim();
      input.focus();
    }
  };
  try {
    voiceRecognition.start();
  } catch (e) {
    stopVoiceInput();
  }
}

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
    stopVoiceInput();
  }
}

function sendQuick(msg) {
  const input = document.getElementById('chatInput');
  if (input) {
    input.value = msg;
    sendChat();
  }
}

async function sendChat() {
  const input = document.getElementById('chatInput');
  const messages = document.getElementById('chatMessages');
  if (!input || !messages) return;

  const msg = (input.value || '').trim();
  if (!msg) return;
  input.value = '';
  input.style.height = 'auto';

  const quickBtns = document.getElementById('quickBtns');
  if (quickBtns) quickBtns.style.display = 'none';

  const userDiv = document.createElement('div');
  userDiv.className = 'chat-msg user';
  userDiv.textContent = msg;
  messages.appendChild(userDiv);
  messages.scrollTop = messages.scrollHeight;

  const typing = document.createElement('div');
  typing.className = 'chat-typing';
  typing.id = 'typingIndicator';
  typing.innerHTML = '<span></span><span></span><span></span>';
  messages.appendChild(typing);
  messages.scrollTop = messages.scrollHeight;

  const priorTurns = loadChatTurns();
  const historyPayload = priorTurns.slice(-3);

  try {
    const res = await fetch('/api/chatbot', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: msg, history: historyPayload })
    });

    const t = document.getElementById('typingIndicator');
    if (t) t.remove();

    let responseText = 'Sorry, I could not process that.';
    try {
      const data = await res.json();
      responseText = data.response || responseText;
    } catch (e) { /* */ }

    priorTurns.push({ user: msg, bot: responseText });
    saveChatTurns(priorTurns);

    const botDiv = document.createElement('div');
    botDiv.className = 'chat-msg bot typing-reveal';
    botDiv.innerHTML = formatBotMessageHtml(responseText);
    messages.appendChild(botDiv);
  } catch (e) {
    const t = document.getElementById('typingIndicator');
    if (t) t.remove();
    const errDiv = document.createElement('div');
    errDiv.className = 'chat-msg bot typing-reveal';
    errDiv.textContent = 'Connection error. Please check your internet and try again.';
    messages.appendChild(errDiv);
  }

  messages.scrollTop = messages.scrollHeight;
}

// ── DOMContentLoaded ───────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  const micBtn = document.getElementById('chatMicBtn');
  if (micBtn) micBtn.addEventListener('click', () => toggleVoiceChat());

  const chatInput = document.getElementById('chatInput');
  if (chatInput && chatInput.tagName === 'TEXTAREA') {
    const autoResize = () => {
      chatInput.style.height = 'auto';
      chatInput.style.height = Math.min(120, chatInput.scrollHeight) + 'px';
    };
    chatInput.addEventListener('input', autoResize);
  }

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
