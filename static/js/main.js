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

// ── Chatbot (Grok API via server + DB threads) ───────────────────────────────
const CHAT_STORAGE_KEY = 'trustlens_chat_turns_v1';
const CHAT_CONV_STORAGE = 'trustlens_chat_conversation_id_v1';
let chatOpen = false;
let voiceRecognition = null;
let currentConversationId = null;
let chatShellReady = false;

function getCsrfToken() {
  const m = document.querySelector('meta[name="csrf-token"]');
  return m ? m.getAttribute('content') || '' : '';
}

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

function renderMarkdownToSafeHtml(text) {
  const raw = String(text || '');
  if (window.marked && window.DOMPurify) {
    try {
      let dirty;
      if (typeof marked.parse === 'function') {
        dirty = marked.parse(raw, { breaks: true, headerIds: false });
      } else if (typeof marked === 'function') {
        dirty = marked(raw, { breaks: true });
      } else {
        dirty = raw;
      }
      return DOMPurify.sanitize(dirty, { USE_PROFILES: { html: true } });
    } catch (e) {
      /* fall through */
    }
  }
  return formatBotMessageHtml(raw);
}

function trustPillClass(score) {
  const n = Number(score) || 0;
  if (n >= 70) return 'chat-trust-pill';
  if (n >= 45) return 'chat-trust-pill warn';
  return 'chat-trust-pill bad';
}

function chatScrollToBottom() {
  const messages = document.getElementById('chatMessages');
  if (!messages) return;
  requestAnimationFrame(() => {
    messages.scrollTop = messages.scrollHeight;
  });
}

function appendUserMessage(text) {
  const messages = document.getElementById('chatMessages');
  if (!messages) return;
  const ts = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const wrap = document.createElement('div');
  wrap.className = 'chat-msg-wrap user-align';
  wrap.innerHTML = `
    <div class="chat-msg user"></div>
    <div class="chat-msg-meta"><span class="chat-msg-ts">${escapeChatHtml(ts)}</span></div>`;
  wrap.querySelector('.chat-msg').textContent = text;
  messages.appendChild(wrap);
  chatScrollToBottom();
}

function appendBotShell() {
  const messages = document.getElementById('chatMessages');
  const wrap = document.createElement('div');
  wrap.className = 'chat-msg-wrap';
  const ts = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  wrap.innerHTML = `
    <div class="chat-msg bot typing-reveal"></div>
    <div class="chat-msg-meta">
      <span class="chat-msg-ts">${escapeChatHtml(ts)}</span>
      <span class="chat-trust-meta"></span>
      <div class="chat-msg-actions">
        <button type="button" class="js-chat-copy">Copy</button>
      </div>
    </div>`;
  messages.appendChild(wrap);
  chatScrollToBottom();
  return wrap;
}

function wireCopyButton(wrap, plainText) {
  const btn = wrap.querySelector('.js-chat-copy');
  if (!btn) return;
  btn.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(plainText || '');
      btn.textContent = 'Copied';
      setTimeout(() => { btn.textContent = 'Copy'; }, 1600);
    } catch (e) {
      btn.textContent = 'Copy failed';
      setTimeout(() => { btn.textContent = 'Copy'; }, 1600);
    }
  });
}

function setTypingIndicator(show) {
  const messages = document.getElementById('chatMessages');
  if (!messages) return;
  let el = document.getElementById('typingIndicator');
  if (show) {
    if (el) return;
    el = document.createElement('div');
    el.id = 'typingIndicator';
    el.className = 'chat-typing';
    el.innerHTML = '<span></span><span></span><span></span>';
    messages.appendChild(el);
    chatScrollToBottom();
  } else if (el) {
    el.remove();
  }
}

async function chatApi(path, options = {}) {
  const headers = Object.assign(
    { 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() },
    options.headers || {}
  );
  const res = await fetch(path, Object.assign({}, options, { headers }));
  return res;
}

async function refreshThreadList() {
  const list = document.getElementById('chatThreadList');
  if (!list) return;
  try {
    const res = await chatApi('/api/chat/conversations', { method: 'GET' });
    const data = await res.json().catch(() => ({}));
    const rows = data.conversations || [];
    list.innerHTML = '';
    rows.forEach((c) => {
      const b = document.createElement('button');
      b.type = 'button';
      b.className = 'chat-thread-item' + (Number(c.id) === Number(currentConversationId) ? ' active' : '');
      b.textContent = c.title || ('Chat ' + c.id);
      b.dataset.id = String(c.id);
      b.addEventListener('click', () => selectConversation(Number(c.id)));
      list.appendChild(b);
    });
  } catch (e) {
    /* ignore */
  }
}

async function ensureConversation() {
  if (currentConversationId) return currentConversationId;
  const res = await chatApi('/api/chat/conversations', {
    method: 'POST',
    body: JSON.stringify({ title: 'New chat' }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || !data.id) {
    throw new Error(data.error || 'Could not start chat');
  }
  currentConversationId = data.id;
  try {
    sessionStorage.setItem(CHAT_CONV_STORAGE, String(currentConversationId));
  } catch (e) { /* */ }
  await refreshThreadList();
  return currentConversationId;
}

async function selectConversation(cid) {
  currentConversationId = cid;
  try {
    sessionStorage.setItem(CHAT_CONV_STORAGE, String(cid));
  } catch (e) { /* */ }
  await refreshThreadList();
  const messages = document.getElementById('chatMessages');
  if (!messages) return;
  messages.innerHTML = '';
  const res = await chatApi(`/api/chat/conversations/${cid}/messages`, { method: 'GET' });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    messages.innerHTML = '<div class="chat-msg bot">Could not load messages.</div>';
    return;
  }
  const list = data.messages || [];
  if (!list.length) {
    messages.innerHTML = `
      <div class="chat-msg-wrap">
        <div class="chat-msg bot">
          <p><strong>New chat</strong> — ask about scams, URLs, or jobs.</p>
        </div>
        <div class="chat-msg-meta"><span class="chat-msg-ts">now</span></div>
      </div>`;
    return;
  }
  list.forEach((m) => {
    const role = m.role;
    const content = m.content || '';
    const ts = m.created_at ? String(m.created_at).slice(11, 16) : '';
    if (role === 'user') {
      appendUserMessage(content);
      return;
    }
    if (role !== 'assistant') return;
    let meta = {};
    try {
      meta = m.meta ? JSON.parse(m.meta) : {};
    } catch (e) {
      meta = {};
    }
    const wrap = appendBotShell();
    const bubble = wrap.querySelector('.chat-msg');
    bubble.innerHTML = renderMarkdownToSafeHtml(content);
    const pillHost = wrap.querySelector('.chat-trust-meta');
    if (pillHost && meta.trust_score != null) {
      const span = document.createElement('span');
      span.className = trustPillClass(meta.trust_score);
      span.textContent = `Trust ${meta.trust_score}/100`;
      pillHost.appendChild(span);
    }
    wireCopyButton(wrap, content);
  });
  chatScrollToBottom();
}

async function initTrustLensChat() {
  if (chatShellReady) return;
  chatShellReady = true;
  try {
    const saved = sessionStorage.getItem(CHAT_CONV_STORAGE);
    if (saved) currentConversationId = Number(saved);
  } catch (e) { /* */ }

  document.getElementById('chatNewThread')?.addEventListener('click', async () => {
    currentConversationId = null;
    try {
      sessionStorage.removeItem(CHAT_CONV_STORAGE);
    } catch (e) { /* */ }
    const cid = await ensureConversation();
    const messages = document.getElementById('chatMessages');
    if (messages) messages.innerHTML = '';
    await selectConversation(cid);
  });

  document.getElementById('chatClearBtn')?.addEventListener('click', async () => {
    if (!currentConversationId) return;
    if (!confirm('Delete this conversation?')) return;
    const res = await chatApi(`/api/chat/conversations/${currentConversationId}`, { method: 'DELETE' });
    if (!res.ok) return;
    currentConversationId = null;
    try {
      sessionStorage.removeItem(CHAT_CONV_STORAGE);
    } catch (e) { /* */ }
    await refreshThreadList();
    const messages = document.getElementById('chatMessages');
    if (messages) messages.innerHTML = '';
    await ensureConversation();
    if (currentConversationId) await selectConversation(currentConversationId);
  });

  document.getElementById('chatRegenerateBtn')?.addEventListener('click', () => {
    sendChat({ regenerate: true });
  });

  await refreshThreadList();
  let rows = [];
  try {
    const r = await chatApi('/api/chat/conversations', { method: 'GET' });
    const d = await r.json();
    rows = d.conversations || [];
  } catch (e) { /* */ }

  if (rows.length === 0) {
    await ensureConversation();
  } else if (!currentConversationId || !rows.some((x) => Number(x.id) === Number(currentConversationId))) {
    currentConversationId = rows[0].id;
    try {
      sessionStorage.setItem(CHAT_CONV_STORAGE, String(currentConversationId));
    } catch (e) { /* */ }
  }
  if (currentConversationId) {
    await selectConversation(currentConversationId);
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
    initTrustLensChat().catch(() => {});
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

async function sendChat(opts) {
  const options = opts || {};
  const input = document.getElementById('chatInput');
  const messages = document.getElementById('chatMessages');
  if (!input || !messages) return;

  if (!getCsrfToken()) {
    alert('Security token missing — please refresh the page after login.');
    return;
  }

  const regenerate = !!options.regenerate;
  let msg = (input.value || '').trim();
  if (!regenerate && !msg) return;

  const quickBtns = document.getElementById('quickBtns');
  if (quickBtns) quickBtns.style.display = 'none';

  if (!regenerate) {
    input.value = '';
    input.style.height = 'auto';
    appendUserMessage(msg);
  }

  setTypingIndicator(true);

  let priorTurns = [];
  try {
    const raw = sessionStorage.getItem(CHAT_STORAGE_KEY);
    const arr = JSON.parse(raw);
    priorTurns = Array.isArray(arr) ? arr : [];
  } catch (e) {
    priorTurns = [];
  }
  const historyPayload = priorTurns.slice(-3);

  try {
    await ensureConversation();
    const res = await chatApi('/api/chatbot', {
      method: 'POST',
      body: JSON.stringify({
        message: msg,
        history: historyPayload,
        conversation_id: currentConversationId,
        regenerate,
      }),
    });

    setTypingIndicator(false);

    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const errText = data.error || data.response || `Request failed (${res.status})`;
      const wrap = appendBotShell();
      wrap.querySelector('.chat-msg').textContent = errText;
      await refreshThreadList();
      chatScrollToBottom();
      return;
    }

    let responseText = data.response || 'Sorry, I could not process that.';
    const meta = data.meta || {};
    if (data.conversation_id) {
      currentConversationId = data.conversation_id;
      try {
        sessionStorage.setItem(CHAT_CONV_STORAGE, String(currentConversationId));
      } catch (e) { /* */ }
    }

    if (!regenerate) {
      priorTurns.push({ user: msg, bot: responseText });
      try {
        sessionStorage.setItem(CHAT_STORAGE_KEY, JSON.stringify(priorTurns.slice(-6)));
      } catch (e) { /* */ }
    } else {
      const botNodes = messages.querySelectorAll('.chat-msg-wrap .chat-msg.bot');
      const lastBot = botNodes[botNodes.length - 1];
      const wrap = lastBot ? lastBot.closest('.chat-msg-wrap') : null;
      wrap?.remove();
    }

    const wrap = appendBotShell();
    const bubble = wrap.querySelector('.chat-msg');
    bubble.innerHTML = renderMarkdownToSafeHtml(responseText);
    const pillHost = wrap.querySelector('.chat-trust-meta');
    if (pillHost && meta.trust_score != null) {
      const span = document.createElement('span');
      span.className = trustPillClass(meta.trust_score);
      span.textContent = `Trust ${meta.trust_score}/100`;
      pillHost.appendChild(span);
    }
    wireCopyButton(wrap, responseText);
    await refreshThreadList();
  } catch (e) {
    setTypingIndicator(false);
    const wrap = appendBotShell();
    wrap.querySelector('.chat-msg').textContent = 'Connection error. Please try again.';
  }

  chatScrollToBottom();
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
