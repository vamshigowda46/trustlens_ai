"""
TrustLens AI – ai_engine.py
NLP fraud detection: TF-IDF + Logistic Regression + keyword analysis
Features: red flag explainer, chatbot responses
"""
import re, os, logging
import requests
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

logger = logging.getLogger(__name__)
GSB_KEY = os.environ.get('GOOGLE_SAFE_BROWSING_KEY', '')

# ── Training Data ──────────────────────────────────────────────────────────────
JOB_TEXTS = [
    "work from home earn 50000 per month no experience needed urgent hiring",
    "data entry job earn lakhs weekly payment guaranteed no interview",
    "part time job registration fee required earn 1 lakh per month",
    "urgent hiring work from home earn 80000 monthly fee required",
    "lottery winner claim prize send otp bank details now",
    "make money online no skills required daily payment whatsapp",
    "earn 5000 per day from home simple typing work no experience",
    "software engineer python django 3 years experience bangalore",
    "marketing manager mba required 5 years experience mumbai",
    "data scientist machine learning tensorflow full time position",
    "product manager agile scrum experience required hyderabad",
    "frontend developer react javascript 2 years experience",
    "free job no fee required legitimate company apply now",
    "government job notification official recruitment board",
    "full stack developer nodejs react 3 years experience pune",
]
JOB_LABELS = [1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0]

MSG_TEXTS = [
    "congratulations you won lottery send otp to claim prize",
    "urgent your account will be blocked click link verify now",
    "dear customer send registration fee to activate upi account",
    "you have won 10 lakh rupees click here to claim instantly",
    "otp for transaction do not share with anyone",
    "guaranteed profit trading investment double money",
    "dear user your kyc is expired update now or account blocked",
    "win iphone 15 click here free gift limited offer act now",
    "your order has been shipped track here delivery tomorrow",
    "meeting scheduled for tomorrow at 10am please confirm",
    "your electricity bill is due please pay before due date",
    "happy birthday have a great day",
    "your flight is confirmed check in opens 24 hours before",
    "salary credited to your account please check",
]
MSG_LABELS = [1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0]

# ── Keyword Lists ──────────────────────────────────────────────────────────────
FRAUD_KEYWORDS = [
    "urgent payment", "registration fee", "guaranteed profit", "click link now",
    "otp", "lottery winner", "instant loan", "trading profit", "work from home earn",
    "earn lakhs", "no experience needed", "send your details", "claim prize",
    "verify account", "blocked account", "double money", "risk free",
    "100% profit", "whatsapp now", "limited time offer", "act now",
    "bank details", "aadhar card", "pan card required", "fee required",
    "advance fee", "processing fee", "refundable deposit", "kyc expired",
    "account suspended", "free gift", "win iphone", "click here immediately",
]

LOAN_SCAM_KEYWORDS = [
    "instant loan", "no documents", "guaranteed approval", "same day loan",
    "no credit check", "advance fee", "processing fee upfront", "loan approved",
    "whatsapp loan", "telegram loan", "earn daily", "high interest",
]

PHISHING_KEYWORDS = [
    "verify your account", "click here immediately", "your account suspended",
    "confirm your details", "unusual activity", "security alert",
    "update payment", "prize winner", "free gift", "act immediately",
]

# ── Red Flag Rules (Explainable AI) ───────────────────────────────────────────
RED_FLAG_RULES = [
    {
        "label": "Unrealistic Salary Offered",
        "icon": "bi-currency-rupee", "color": "var(--neon-red)",
        "patterns": ["earn lakhs", "earn 50000", "earn 80000", "earn 1 lakh",
                     "earn 5000 per day", "weekly payment", "daily payment", "guaranteed income"],
        "severity": "HIGH"
    },
    {
        "label": "Upfront Fee / Registration Fee Required",
        "icon": "bi-cash-coin", "color": "var(--neon-red)",
        "patterns": ["registration fee", "fee required", "advance fee", "processing fee",
                     "refundable deposit", "activation fee", "pay to join"],
        "severity": "CRITICAL"
    },
    {
        "label": "No Experience / Qualification Required",
        "icon": "bi-person-x", "color": "var(--neon-yellow)",
        "patterns": ["no experience needed", "no qualification", "no interview",
                     "anyone can apply", "no skills required"],
        "severity": "MEDIUM"
    },
    {
        "label": "Urgency / Pressure Tactics",
        "icon": "bi-alarm", "color": "var(--neon-red)",
        "patterns": ["urgent", "act now", "limited time", "hurry", "last chance",
                     "only today", "expires soon", "immediate"],
        "severity": "HIGH"
    },
    {
        "label": "WhatsApp / Telegram Only Contact",
        "icon": "bi-chat-dots", "color": "var(--neon-yellow)",
        "patterns": ["whatsapp", "telegram", "contact on whatsapp",
                     "whatsapp now", "telegram group"],
        "severity": "HIGH"
    },
    {
        "label": "Requests Personal / Bank Details",
        "icon": "bi-shield-exclamation", "color": "var(--neon-red)",
        "patterns": ["bank details", "aadhar card", "pan card", "send your details",
                     "account number", "ifsc code", "otp", "cvv"],
        "severity": "CRITICAL"
    },
    {
        "label": "Guaranteed Profit / Risk-Free Returns",
        "icon": "bi-graph-up-arrow", "color": "var(--neon-red)",
        "patterns": ["guaranteed profit", "guaranteed return", "risk free", "100% profit",
                     "double money", "triple your investment", "no risk"],
        "severity": "CRITICAL"
    },
    {
        "label": "Lottery / Prize / Winner Claim",
        "icon": "bi-trophy", "color": "var(--neon-red)",
        "patterns": ["lottery winner", "you have won", "claim prize", "lucky winner",
                     "prize money", "won rupees", "selected winner"],
        "severity": "CRITICAL"
    },
    {
        "label": "Suspicious Link / Phishing URL",
        "icon": "bi-link-45deg", "color": "var(--neon-red)",
        "patterns": ["click link now", "click here immediately", "verify now",
                     "http://", "bit.ly", "tinyurl", ".tk", ".ml"],
        "severity": "HIGH"
    },
    {
        "label": "Too-Good-To-Be-True Offer",
        "icon": "bi-star-fill", "color": "var(--neon-yellow)",
        "patterns": ["work from home earn", "earn from mobile", "earn while sleeping",
                     "passive income guaranteed", "make money online easy"],
        "severity": "HIGH"
    },
]

# ── Model Training ─────────────────────────────────────────────────────────────
def _train(texts, labels):
    vec = TfidfVectorizer(ngram_range=(1, 2), max_features=500)
    X = vec.fit_transform(texts)
    clf = LogisticRegression(max_iter=1000)
    clf.fit(X, labels)
    return vec, clf

job_vec, job_clf = _train(JOB_TEXTS, JOB_LABELS)
msg_vec, msg_clf = _train(MSG_TEXTS, MSG_LABELS)

# ── Helpers ────────────────────────────────────────────────────────────────────
def _keyword_hits(text, keywords):
    text_lower = text.lower()
    return [kw for kw in keywords if kw in text_lower]

def _score_from_prob(fraud_prob):
    return max(0, min(100, int((1 - fraud_prob) * 100)))

def _risk_level(score):
    """Trust score bands (0–100) used across scan UIs."""
    if score >= 71:
        return "Safe"
    if score >= 51:
        return "Moderate Risk"
    if score >= 31:
        return "Suspicious"
    return "Dangerous"


def _trust_tier_slug(score):
    """Short key for CSS / clients."""
    if score >= 71:
        return "safe"
    if score >= 51:
        return "moderate"
    if score >= 31:
        return "suspicious"
    return "dangerous"


def _model_confidence_from_fraud_prob(fraud_prob):
    """How strongly the model leans fake vs legitimate (0–100)."""
    p = float(fraud_prob)
    return max(0, min(100, int(round(abs(p - 0.5) * 200))))

def get_red_flags(text):
    """Return triggered red flag dicts for explainable AI output."""
    text_lower = text.lower()
    triggered = []
    for rule in RED_FLAG_RULES:
        if any(p in text_lower for p in rule["patterns"]):
            triggered.append({
                "label": rule["label"],
                "icon": rule["icon"],
                "color": rule["color"],
                "severity": rule["severity"]
            })
    return triggered


def _collect_job_warnings(full_text: str, salary: str, company_found: bool, company: str) -> list:
    """Structured warning chips for the Fake Job UI."""
    t = full_text.lower()
    salary_l = (salary or "").lower()
    warnings = []

    fake_domain_patterns = (
        r"\.tk\b", r"\.ml\b", r"\.ga\b", r"\.cf\b", r"\.gq\b",
        r"bit\.ly/", r"tinyurl\.", r"t\.me/", r"wa\.me/", r"@\w+\.(tk|ml|xyz)\b",
    )
    if any(re.search(p, t) for p in fake_domain_patterns):
        warnings.append({
            "id": "fake_domains",
            "label": "Suspicious domain / short link",
            "detail": "The text contains disposable TLDs or URL shorteners often used in scams.",
            "icon": "bi-globe2",
        })

    high_pay_hints = (
        "80000", "80,000", "90000", "1 lakh", "2 lakh", "50000", "50,000",
        "70000", "70,000", "60000", "60,000", "5000 per day", "earn 5000",
        "weekly payment", "daily payment", "per month", "lpa",
    )
    easy_role_hints = ("no experience", "data entry", "typing work", "simple task", "whatsapp only", "anyone can")
    if any(x in salary_l or x in t for x in high_pay_hints) and any(x in t for x in easy_role_hints):
        warnings.append({
            "id": "suspicious_salary",
            "label": "Suspicious salary vs. role",
            "detail": "Very high pay combined with minimal requirements is a common job-scam pattern.",
            "icon": "bi-currency-rupee",
        })

    if "urgent" in t and any(w in t for w in ("hiring", "vacancy", "apply now", "limited seat", "act now")):
        warnings.append({
            "id": "urgent_hiring",
            "label": "Urgent hiring pressure",
            "detail": "Aggressive urgency ('limited seats', 'apply now') is used to bypass careful review.",
            "icon": "bi-alarm-fill",
        })

    payment_patterns = (
        "registration fee", "processing fee", "advance fee", "pay to join",
        "activation fee", "send money", "wire transfer", "upi payment",
        "paytm", "google pay", "account number", "ifsc",
    )
    if any(p in t for p in payment_patterns):
        warnings.append({
            "id": "payment_requests",
            "label": "Payment or money transfer",
            "detail": "Legitimate employers rarely ask for upfront fees or informal transfers before hiring.",
            "icon": "bi-cash-stack",
        })

    if company and company.strip() and not company_found:
        warnings.append({
            "id": "no_company_presence",
            "label": "Weak company presence online",
            "detail": "The employer name did not match prominent Google results — verify on official careers pages.",
            "icon": "bi-building-x",
        })

    return warnings


def _build_job_ai_explanation(
    score, risk_level, fraud_prob, model_result, warnings, red_flags, google_data, hits,
):
    """Narrative explanation aligned with trust tier and signals."""
    lines = []
    lines.append(
        f"TrustLens scored this posting **{score}/100** ({risk_level}). "
        f"The model estimates a **{fraud_prob * 100:.0f}%** fraud likelihood "
        f"({'classified as FAKE' if model_result == 'FAKE' else 'classified as likely legitimate'})."
    )

    if risk_level == "Safe":
        lines.append(
            "Overall language and structure look consistent with genuine job ads: "
            "no dominant fee scams, coercion, or impersonation patterns in the scan."
        )
    elif risk_level == "Moderate Risk":
        lines.append(
            "Some mixed signals appear. Review salary claims, contact channels, and whether the employer "
            "matches an official website before sharing personal documents."
        )
    elif risk_level == "Suspicious":
        lines.append(
            "Multiple cautionary signals overlap. Treat as high risk until you confirm the company "
            "through an independent source (official site, LinkedIn, or known HR email)."
        )
    else:
        lines.append(
            "Strong scam-style patterns detected. Do not pay any fee or share ID, bank, or OTP details "
            "based on this posting alone."
        )

    if warnings:
        lines.append("**Raised indicators:** " + "; ".join(w["label"] for w in warnings) + ".")

    if hits:
        lines.append(f"Keyword hits include: {', '.join(hits[:6])}.")

    if red_flags:
        lines.append(
            "Rule-based checks flagged: "
            + ", ".join(r["label"] for r in red_flags[:5])
            + ("." if len(red_flags) <= 5 else ", and more.")
        )

    if google_data.get("found"):
        lines.append("Google search suggested recognizable web presence for the company name.")
    elif (google_data.get("info") or "").lower().startswith("could not"):
        lines.append("Company verification via Google was inconclusive (network or blocking).")
    elif google_data.get("info"):
        lines.append(f"Company check: {google_data['info']}")

    return "\n\n".join(lines)


# ── Detection Functions ────────────────────────────────────────────────────────
def detect_fake_job(title, company, salary, description):
    text = f"{title} {company} {salary} {description}"
    prob = job_clf.predict_proba(job_vec.transform([text]))[0][1]
    hits = _keyword_hits(text, FRAUD_KEYWORDS)
    red_flags = get_red_flags(text)

    if hits:
        prob = min(1.0, prob + 0.15 * len(hits))

    # ── Google company verification ──
    google_data = _google_search_company(company) if company.strip() else {"found": False, "info": "No company name provided", "url": ""}
    if not google_data["found"] and company.strip():
        prob = min(1.0, prob + 0.25)

    score = _score_from_prob(prob)
    result = "FAKE" if prob > 0.5 else "SAFE"
    risk_level = _risk_level(score)
    trust_tier = _trust_tier_slug(score)
    confidence = _model_confidence_from_fraud_prob(prob)
    warnings = _collect_job_warnings(text, salary, google_data["found"], company)

    explanation = _build_job_ai_explanation(
        score, risk_level, prob, result, warnings, red_flags, google_data, hits,
    )

    return {
        "result": result,
        "trust_score": score,
        "risk_level": risk_level,
        "trust_tier": trust_tier,
        "confidence": confidence,
        "warnings": warnings,
        "explanation": explanation,
        "keywords": hits[:8],
        "red_flags": red_flags,
        "company_found": google_data["found"],
        "google_info": google_data["info"],
        "google_url": google_data["url"],
    }

def detect_scam_message(message):
    prob = msg_clf.predict_proba(msg_vec.transform([message]))[0][1]
    hits = _keyword_hits(message, FRAUD_KEYWORDS + PHISHING_KEYWORDS)
    red_flags = get_red_flags(message)

    if hits:
        prob = min(1.0, prob + 0.12 * len(hits))

    score = _score_from_prob(prob)
    result = "SCAM" if prob > 0.5 else "SAFE"
    scam_types = []
    msg_lower = message.lower()
    if any(w in msg_lower for w in ["otp", "bank", "account", "upi"]):
        scam_types.append("Banking/UPI Scam")
    if any(w in msg_lower for w in ["lottery", "winner", "prize", "won"]):
        scam_types.append("Lottery Scam")
    if any(w in msg_lower for w in ["click", "link", "verify", "http"]):
        scam_types.append("Phishing")
    if any(w in msg_lower for w in ["loan", "credit", "emi"]):
        scam_types.append("Loan Scam")
    if any(w in msg_lower for w in ["invest", "profit", "trading", "return"]):
        scam_types.append("Investment Scam")

    explanation = (
        f"Detected as {', '.join(scam_types) if scam_types else 'General Scam'}. "
        f"Keywords: {', '.join(hits[:5])}." if result == "SCAM"
        else "Message appears safe. No major scam indicators found."
    )
    return {
        "result": result, "trust_score": score, "risk_level": _risk_level(score),
        "explanation": explanation, "keywords": hits[:8],
        "scam_types": scam_types, "red_flags": red_flags
    }

def detect_loan_app(app_name, permissions, interest_rate):
    text = f"{app_name} {permissions}"
    hits = _keyword_hits(text, LOAN_SCAM_KEYWORDS)
    red_flags = get_red_flags(text)

    fraud_score = len(hits) * 15

    # ── Google Play + RBI check ──
    google_data = _google_search_loan_app(app_name) if app_name.strip() else {"on_play_store": False, "rbi_mention": False, "info": "", "url": ""}
    if not google_data["on_play_store"]:
        fraud_score += 40
    if google_data["rbi_mention"]:
        fraud_score = max(0, fraud_score - 20)

    try:
        rate = float(interest_rate)
        if rate > 36:
            fraud_score += 40
        elif rate > 24:
            fraud_score += 20
    except (ValueError, TypeError):
        pass

    dangerous_perms = ["contacts", "sms", "camera", "location", "storage", "call logs"]
    perm_hits = [p for p in dangerous_perms if p in str(permissions).lower()]
    fraud_score += len(perm_hits) * 8

    fraud_prob = min(fraud_score / 100, 1.0)
    score = _score_from_prob(fraud_prob)
    result = "FRAUDULENT" if fraud_prob > 0.5 else "SAFE"

    issues = []
    if not google_data["on_play_store"]:
        issues.append(f"'{app_name}' NOT found on Google Play Store")
    if perm_hits:
        issues.append(f"Dangerous permissions: {', '.join(perm_hits)}")
    if hits:
        issues.append(f"Suspicious keywords: {', '.join(hits[:3])}")

    explanation = "; ".join(issues) if issues else "Loan app appears legitimate."

    return {
        "result": result, "trust_score": score, "risk_level": _risk_level(score),
        "explanation": explanation, "keywords": hits + perm_hits, "red_flags": red_flags,
        "on_play_store": google_data["on_play_store"],
        "rbi_mention": google_data["rbi_mention"],
        "google_info": google_data["info"],
        "google_url": google_data["url"]
    }

def _check_google_safe_browsing(url: str) -> dict:
    """Call Google Safe Browsing API. Returns {'safe': bool, 'threats': list}"""
    if not GSB_KEY or GSB_KEY == 'your_google_key':
        return {'safe': None, 'threats': []}  # not configured — skip
    try:
        payload = {
            "client": {"clientId": "trustlens-ai", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                 "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        r = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_KEY}",
            json=payload, timeout=5)
        data = r.json()
        threats = [m['threatType'] for m in data.get('matches', [])]
        return {'safe': len(threats) == 0, 'threats': threats}
    except Exception as e:
        logger.warning("GSB API error: %s", e)
        return {'safe': None, 'threats': []}

def scan_website(url):
    url_lower = url.lower()
    issues = []
    fraud_score = 0

    # ── Google Safe Browsing ──
    gsb = _check_google_safe_browsing(url)
    gsb_checked = gsb['safe'] is not None
    if gsb['threats']:
        for t in gsb['threats']:
            issues.append(f"Google Safe Browsing: {t.replace('_', ' ').title()} detected")
        fraud_score += 80

    # ── Local heuristic checks ──
    if not url_lower.startswith("https://"):
        issues.append("No HTTPS (insecure connection)")
        fraud_score += 30

    suspicious_words = ["login", "verify", "secure", "update", "confirm", "account",
                        "banking", "paypal", "amazon", "netflix", "free", "prize"]
    domain_hits = [w for w in suspicious_words if w in url_lower]
    if domain_hits:
        issues.append(f"Suspicious words in URL: {', '.join(domain_hits)}")
        fraud_score += len(domain_hits) * 10

    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
        issues.append("IP address used instead of domain name")
        fraud_score += 35

    if url.count('.') > 4:
        issues.append("Excessive subdomains detected")
        fraud_score += 20

    if any(ext in url_lower for ext in ['.tk', '.ml', '.ga', '.cf', '.gq']):
        issues.append("Free/suspicious TLD detected")
        fraud_score += 25

    # ── Google Intelligence ──
    try:
        from intel_engine import fetch_website_intelligence
        intel = fetch_website_intelligence(url)
    except Exception as e:
        logger.warning("Intel engine error: %s", e)
        intel = None

    # Apply intel score adjustment
    if intel:
        adj = intel.get("intel_score_adj", 0)
        if adj < 0:
            fraud_score += abs(adj)   # more dangerous
        else:
            fraud_score = max(0, fraud_score - adj)  # safer
        if intel.get("scam_alert"):
            issues.append("Google Intelligence: Scam/fraud reports found online")

    fraud_prob = min(fraud_score / 100, 1.0)
    score = _score_from_prob(fraud_prob)

    if score >= 90:
        result = "SAFE"
    elif score >= 60:
        result = "SUSPICIOUS"
    else:
        result = "DANGEROUS"

    explanation = "; ".join(issues) if issues else "URL appears safe. No threats detected."
    if gsb_checked and not gsb['threats']:
        explanation = "✓ Google Safe Browsing: Clean. " + explanation

    return {
        "result": result, "trust_score": score, "risk_level": _risk_level(score),
        "explanation": explanation, "issues": issues,
        "gsb_checked": gsb_checked,
        "intel": intel
    }

# ── Chatbot Response Engine ────────────────────────────────────────────────────
CHATBOT_KB = [
    {
        "triggers": ["fake job", "identify fake job", "how to spot fake job", "job scam"],
        "response": "🔍 **How to Identify Fake Jobs:**\n\n• They ask for a registration or processing fee upfront\n• Salary is unrealistically high (₹50,000+/month for simple tasks)\n• No interview required — instant selection\n• Contact only via WhatsApp or Telegram\n• Vague job description with no company details\n• Requests Aadhaar/PAN/bank details early\n\n✅ Use our **Fake Job Detector** to scan any job posting instantly!"
    },
    {
        "triggers": ["phishing", "avoid phishing", "phishing attack", "phishing link"],
        "response": "🛡️ **How to Avoid Phishing Attacks:**\n\n• Always check the URL — look for HTTPS and correct domain spelling\n• Never click links in unsolicited SMS or WhatsApp messages\n• Banks never ask for OTP, CVV, or password via message\n• Hover over links to see the real destination\n• Use our **Website Scanner** to verify any suspicious URL\n\n⚠️ When in doubt, go directly to the official website!"
    },
    {
        "triggers": ["website safe", "is this website safe", "check website", "url safe"],
        "response": "🌐 **To Check if a Website is Safe:**\n\n• Look for 🔒 HTTPS in the address bar\n• Check for spelling mistakes in the domain (e.g., amaz0n.com)\n• Avoid sites with free TLDs like .tk, .ml, .ga\n• Don't enter personal info on sites with IP addresses as URLs\n\n✅ Use our **Website Scanner** — paste the URL and get an instant AI safety report!"
    },
    {
        "triggers": ["otp scam", "otp fraud", "otp", "bank fraud"],
        "response": "🏦 **OTP / Banking Scam Alert:**\n\n• Your bank will NEVER ask for your OTP, PIN, or password\n• Never share OTP with anyone — not even 'bank officials'\n• Scammers pose as bank employees to steal OTPs\n• If you receive an unexpected OTP, your account may be targeted\n\n🚨 If you've shared an OTP, call your bank immediately to block transactions!"
    },
    {
        "triggers": ["loan scam", "fake loan app", "loan fraud", "instant loan"],
        "response": "💰 **Loan App Scam Warning:**\n\n• Legitimate lenders are registered with RBI\n• Never pay an 'advance fee' or 'processing fee' before getting a loan\n• Avoid apps that demand access to contacts, SMS, and call logs\n• Interest rates above 36% per annum are predatory\n• Verify using our **RBI/SEBI Verifier** before applying\n\n✅ Use our **Loan App Detector** to check any app instantly!"
    },
    {
        "triggers": ["investment scam", "trading scam", "fake trading", "guaranteed returns"],
        "response": "📈 **Investment / Trading Scam Signs:**\n\n• No legitimate investment guarantees profit\n• 'Double your money in 30 days' is always a scam\n• Fake trading apps show fake profits to lure more deposits\n• Always verify brokers on SEBI's official website\n• Use our **RBI/SEBI Verifier** to check any platform\n\n⚠️ SEBI registered brokers: Zerodha, Groww, Upstox, Angel One"
    },
    {
        "triggers": ["lottery scam", "lottery fraud", "won prize", "lucky winner"],
        "response": "🎰 **Lottery / Prize Scam:**\n\n• You cannot win a lottery you never entered\n• Legitimate lotteries never ask for fees to claim prizes\n• These messages are designed to steal your money and identity\n• Never share personal details or pay any amount\n\n🚨 Use our **Scam Message Detector** to analyze any suspicious message!"
    },
    {
        "triggers": ["rbi", "sebi", "verify company", "registered company", "check app"],
        "response": "🏛️ **RBI / SEBI Verification:**\n\n• RBI regulates: Banks, NBFCs, Payment apps (PhonePe, Paytm, GPay)\n• SEBI regulates: Stock brokers, Investment platforms (Zerodha, Groww)\n• Always verify before investing or taking a loan\n\n✅ Use our **RBI/SEBI Verifier** — search any company name or app instantly!"
    },
    {
        "triggers": ["hello", "hi", "hey", "help", "what can you do"],
        "response": "👋 **Hello! I'm TrustLens AI Assistant.**\n\nI can help you with:\n\n🔍 Identifying fake jobs\n📱 Detecting scam messages\n🌐 Checking website safety\n💰 Spotting loan scams\n📈 Avoiding investment fraud\n🏛️ Verifying RBI/SEBI companies\n📷 **QR Scam Scanner** for suspicious payment codes\n🗺️ **Threat Map** for India-focused scam activity\n\nAsk me anything about digital fraud or cybersecurity — I remember our recent messages in this session."
    },
    {
        "triggers": ["qr code", "qr scam", "upi qr", "scan qr", "qr scanner"],
        "response": "📷 **QR / UPI safety:**\n\n• Never scan random QR codes from strangers or \"prize\" messages\n• Check the payee (pa=) name in UPI links before paying\n• Scammers use pre-filled amounts (`am=`) and urgent wording\n• If a QR opens a website, verify the domain first\n\n✅ Open **QR Scam Scanner** — upload a screenshot or paste the raw `upi://` text for an instant risk check."
    },
    {
        "triggers": ["threat map", "cyber map", "live threat", "india threat"],
        "response": "🗺️ **Threat Map:**\n\n• Shows simulated + API-fed scam activity across Indian states (when keys are configured)\n• Use filters to focus on phishing, malware, OTP scams, etc.\n• Great for awareness — always verify alerts with official sources too\n\n✅ Open **Threat Map** from the sidebar and hit refresh for the latest batch."
    },
    {
        "triggers": ["report", "how to report", "report scam", "report fraud"],
        "response": "📢 **How to Report Fraud:**\n\n• Use our **Community Report** feature to report scam websites, jobs, and apps\n• Report to Cyber Crime: cybercrime.gov.in\n• Call National Cyber Crime Helpline: **1930**\n• Report UPI fraud to your bank immediately\n• File complaint at your nearest police station\n\n✅ Your reports help protect the entire community!"
    },
]

def get_chatbot_response(user_message, history=None):
    """
    Match user message to knowledge base; optional `history` is a list of
    dicts like {"user": "...", "bot": "..."} for multi-turn context.
    """
    msg_lower = user_message.lower().strip()
    combined = msg_lower
    if history:
        parts = []
        for h in history[-4:]:
            if not isinstance(h, dict):
                continue
            u, b = (h.get("user") or ""), (h.get("bot") or "")
            parts.append(u + " " + b)
        combined = (" ".join(parts) + " " + msg_lower).lower()

    # Session-style short replies (avoid matching substrings like "hi" inside "phishing")
    if history and isinstance(history[-1], dict):
        if any(w in msg_lower for w in ("thanks", "thank you", "thankyou", "thx")):
            return (
                "Glad it helped. If something still feels wrong, use the scanners before paying or sharing OTPs — "
                "and you can always ask a follow-up here; I keep the last few messages in mind for this session."
            )
        if any(w in msg_lower for w in ("bye", "goodbye", "see you")):
            return "Stay safe online. Come back anytime you want a second opinion on a link, job, or message."

    followups = ("tell me more", "more detail", "elaborate", "what else", "and then", "what should i do")
    if any(f in msg_lower for f in followups) and history:
        return (
            "🧠 **Building on our chat:**\n\n"
            "1. If it's a **link or site** → paste it into **Website Scanner**.\n"
            "2. If it's a **job or offer text** → **Fake Job Detector**.\n"
            "3. If it's an **SMS / WhatsApp** → **Scam Message**.\n"
            "4. For **money / broker / app names** → **RBI/SEBI Verifier**.\n\n"
            "Paste the exact text next — concrete details beat guesswork."
        )

    for entry in CHATBOT_KB:
        triggers = entry["triggers"]
        if any((t in msg_lower if len(t) <= 3 else t in combined) for t in triggers):
            return entry["response"]

    if any(w in msg_lower for w in ["scam", "fraud", "fake", "suspicious"]):
        return ("🔍 I detected a concern about potential fraud. Use our scan tools:\n\n"
                "• **Fake Job Detector** – for suspicious job posts\n"
                "• **Scam Message Detector** – for suspicious messages\n"
                "• **Website Scanner** – for suspicious URLs\n"
                "• **RBI/SEBI Verifier** – for financial apps\n\n"
                "Or describe your specific concern and I'll guide you!")

    return ("🤖 I'm not sure about that specific query. Try asking about:\n\n"
            "• 'How to identify fake jobs?'\n"
            "• 'How to avoid phishing?'\n"
            "• 'Is this website safe?'\n"
            "• 'What is an OTP scam?'\n"
            "• 'How to report fraud?'")


# ── QR Scam Scanner ────────────────────────────────────────────────────────────
def scan_qr_image(image_path: str) -> dict:
    """Analyze a QR code image for UPI/payment fraud."""
    qr_text = ""
    try:
        from PIL import Image
        import numpy as np
        import cv2

        pil_img = Image.open(image_path)
        gray = pil_img.convert("L")

        def _try_cv2_decode(img_rgb_or_gray):
            arr = np.asarray(img_rgb_or_gray)
            if arr.ndim == 2:
                bgr = cv2.cvtColor(arr, cv2.COLOR_GRAY2BGR)
            elif arr.shape[-1] == 4:
                bgr = cv2.cvtColor(arr, cv2.COLOR_RGBA2BGR)
            else:
                bgr = cv2.cvtColor(arr, cv2.COLOR_RGB2BGR)
            det = cv2.QRCodeDetector()
            ok, decoded, _pts = det.detectAndDecode(bgr)
            return decoded if ok and decoded else ""

        # RGB, grayscale, then contrast-normalized grayscale (helps camera photos)
        qr_text = _try_cv2_decode(pil_img.convert("RGB"))
        if not qr_text:
            qr_text = _try_cv2_decode(gray)
        if not qr_text:
            garr = np.asarray(gray)
            garr = cv2.normalize(garr, None, 0, 255, cv2.NORM_MINMAX)
            qr_text = _try_cv2_decode(garr)

        if not qr_text:
            try:
                import zxingcpp
                results = zxingcpp.read_barcodes(pil_img)
                qr_text = results[0].text if results else ""
            except Exception:
                pass
    except Exception as e:
        logger.warning("QR image scan error: %s", e)
        qr_text = ""

    if not qr_text:
        return {
            "result": "UNREADABLE",
            "trust_score": 50,
            "risk_level": _risk_level(50),
            "qr_text": "",
            "explanation": "Could not decode QR from this image. Try a sharper photo, better lighting, or paste the QR text / UPI link manually.",
            "issues": ["QR decode failed — image may be blurry, cropped, or not a QR code"],
            "red_flags": [],
        }

    return scan_qr_text(qr_text)


# NPCI-style payment URI + VPA shape (prevents "upi:gibberish" scoring as safe)
_UPI_PAY_URI = re.compile(r"^\s*upi://pay\?", re.I)
# VPA: local@psp — PSP is typically bank / UPI app handle (letters + digits)
_VPA_PATTERN = re.compile(
    r"^[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z][a-zA-Z0-9.\-]{1,63}$"
)


def _extract_upi_pa(qr_text: str) -> str:
    from urllib.parse import unquote

    m = re.search(r"(?:^|[?&])pa=([^&]+)", qr_text, re.I)
    if not m:
        return ""
    return unquote(m.group(1).strip())


def _upi_structure_risk(qr_text: str) -> tuple[list, int]:
    """
    Return (issues, fraud_score_add) for malformed or non-standard UPI payloads.
    Real merchant QRs should match upi://pay?pa=vpa@psp&...
    """
    issues: list = []
    add = 0
    raw = (qr_text or "").strip()
    if not raw:
        return issues, 0
    low = raw.lower()

    if low.startswith("http://") or low.startswith("https://"):
        return issues, 0

    pa = _extract_upi_pa(raw)
    standard = bool(_UPI_PAY_URI.match(raw))
    malformed_upi_colon = low.startswith("upi:") and not low.startswith("upi://")

    # Typo / fake schemes like "upi:xxxx" without //
    if malformed_upi_colon:
        issues.append("Invalid UPI format: real payment QRs use upi://pay?… (not upi:…)")
        add += 60
    elif "upi://" in low and not standard:
        issues.append("Non-standard UPI URI: expected upi://pay? followed by parameters")
        add += 45

    if standard and not pa:
        issues.append("UPI payment link is missing the payee (pa=) field")
        add += 55

    if pa and not _VPA_PATTERN.match(pa):
        issues.append(
            f"Payee (pa) does not look like a valid UPI ID (expected name@bankhandle): {pa[:48]}"
        )
        add += 50

    # Random pasted text (not already flagged as bad upi: scheme)
    if (
        not malformed_upi_colon
        and not standard
        and not pa
        and len(raw) >= 8
        and not low.startswith("http")
        and "@" not in raw
    ):
        issues.append("Payload is not a valid UPI payment string — do not treat as a trusted payee")
        add += 45

    # Bare VPA without full URI — not necessarily fraud, but never "perfectly safe"
    if pa and _VPA_PATTERN.match(pa) and not standard and "upi://" not in low:
        issues.append("Bare UPI ID without full upi:// link — confirm payee in your UPI app before sending")
        add += 18

    return issues, min(add, 85)


def scan_qr_text(qr_text: str) -> dict:
    """Analyze decoded QR text for UPI fraud indicators."""
    issues = []
    fraud_score = 0
    text_lower = qr_text.lower()
    raw = (qr_text or "").strip()

    upi_id = _extract_upi_pa(qr_text)

    struct_issues, struct_score = _upi_structure_risk(qr_text)
    issues.extend(struct_issues)
    fraud_score += struct_score

    suspicious_upi_words = ["lottery", "prize", "win", "free", "gift", "reward",
                           "lucky", "claim", "bonus", "offer", "cashback100"]
    for word in suspicious_upi_words:
        if word in text_lower:
            issues.append(f"Suspicious keyword in QR: '{word}'")
            fraud_score += 25

    # Check for amount pre-filled (scam tactic)
    if "am=" in qr_text or "amount=" in text_lower:
        issues.append("Pre-filled amount detected — scammers pre-fill amounts")
        fraud_score += 20

    # Check for unknown/suspicious UPI handles
    suspicious_handles = [".xyz", ".tk", ".ml", "hack", "scam", "fake"]
    for h in suspicious_handles:
        if h in upi_id.lower():
            issues.append(f"Suspicious UPI handle: {upi_id}")
            fraud_score += 40

    # Non-UPI QR with payment keywords
    if "upi://" not in text_lower and any(w in text_lower for w in ["pay", "payment", "transfer"]):
        issues.append("Non-standard payment QR format")
        fraud_score += 15

    fraud_prob = min(fraud_score / 100, 1.0)
    score = _score_from_prob(fraud_prob)
    result = "DANGEROUS" if fraud_prob > 0.5 else ("SUSPICIOUS" if fraud_prob > 0.2 else "SAFE")

    if issues:
        explanation = "; ".join(issues)
    elif _UPI_PAY_URI.match(raw) and upi_id and _VPA_PATTERN.match(upi_id):
        explanation = "Standard UPI payment QR format with a valid-looking payee ID. Still verify the recipient name in your app before paying."
    else:
        explanation = "QR code appears safe. No fraud indicators found."

    return {
        "result": result,
        "trust_score": score,
        "risk_level": _risk_level(score),
        "qr_text": qr_text[:300],
        "upi_id": upi_id,
        "explanation": explanation,
        "issues": issues,
        "red_flags": get_red_flags(qr_text)
    }

# ── App Permission Analyzer ────────────────────────────────────────────────────
DANGEROUS_PERMISSIONS = {
    "READ_CONTACTS":        ("Reads your contact list", "HIGH"),
    "READ_SMS":             ("Reads all your SMS messages", "CRITICAL"),
    "SEND_SMS":             ("Can send SMS on your behalf", "CRITICAL"),
    "READ_CALL_LOG":        ("Reads your call history", "HIGH"),
    "RECORD_AUDIO":         ("Can record audio/calls", "CRITICAL"),
    "ACCESS_FINE_LOCATION": ("Tracks your exact GPS location", "HIGH"),
    "CAMERA":               ("Access to camera", "MEDIUM"),
    "READ_EXTERNAL_STORAGE":("Reads all files on device", "MEDIUM"),
    "WRITE_EXTERNAL_STORAGE":("Writes/deletes files on device", "MEDIUM"),
    "GET_ACCOUNTS":         ("Access to all device accounts", "HIGH"),
    "USE_BIOMETRIC":        ("Access to fingerprint/face data", "HIGH"),
    "PROCESS_OUTGOING_CALLS":("Intercepts outgoing calls", "CRITICAL"),
    "RECEIVE_BOOT_COMPLETED":("Auto-starts on device boot", "MEDIUM"),
    "REQUEST_INSTALL_PACKAGES":("Can install other apps silently", "CRITICAL"),
    "SYSTEM_ALERT_WINDOW":  ("Can overlay on other apps (screen overlay)", "HIGH"),
}

def _google_search_company(company_name: str) -> dict:
    """Check if a company exists via Google search (Play Store + web)."""
    result = {"found": False, "info": "", "url": ""}
    if not company_name or len(company_name.strip()) < 3:
        return result
    try:
        query = company_name.strip().replace(' ', '+')
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        r = requests.get(
            f"https://www.google.com/search?q={query}+company+india+reviews",
            headers=headers, timeout=6)
        if r.status_code == 200:
            content = r.text.lower()
            name_words = [w for w in company_name.lower().split() if len(w) > 3]
            matches = sum(1 for w in name_words if w in content)
            if matches >= max(1, len(name_words) * 0.5):
                result["found"] = True
                result["info"] = f"'{company_name}' found in Google search results"
            else:
                result["info"] = f"'{company_name}' not prominently found on Google"
            result["url"] = f"https://www.google.com/search?q={query}"
    except Exception as e:
        logger.warning("Google company lookup error: %s", e)
        result["info"] = "Could not verify company with Google"
    return result


def _google_search_loan_app(app_name: str) -> dict:
    """Check loan app on Google Play Store and RBI list."""
    result = {"on_play_store": False, "rbi_mention": False, "info": "", "url": ""}
    if not app_name or len(app_name.strip()) < 2:
        return result
    try:
        query = app_name.strip().replace(' ', '+')
        headers = {"User-Agent": "Mozilla/5.0 (Android 13; Mobile) AppleWebKit/537.36"}
        # Check Play Store
        r = requests.get(
            f"https://play.google.com/store/search?q={query}&c=apps",
            headers=headers, timeout=6)
        if r.status_code == 200:
            content = r.text.lower()
            name_words = [w for w in app_name.lower().split() if len(w) > 3]
            matches = sum(1 for w in name_words if w in content)
            if matches >= max(1, len(name_words) * 0.5):
                result["on_play_store"] = True
        # Check RBI mention via Google
        r2 = requests.get(
            f"https://www.google.com/search?q={query}+RBI+registered+NBFC+loan+app",
            headers={"User-Agent": "Mozilla/5.0"}, timeout=6)
        if r2.status_code == 200:
            c2 = r2.text.lower()
            if "rbi" in c2 and app_name.lower().split()[0] in c2:
                result["rbi_mention"] = True
        result["url"] = f"https://play.google.com/store/search?q={query}&c=apps"
        parts = []
        if result["on_play_store"]:
            parts.append("Found on Google Play Store")
        else:
            parts.append("NOT found on Google Play Store")
        if result["rbi_mention"]:
            parts.append("RBI/NBFC mention found")
        result["info"] = " · ".join(parts)
    except Exception as e:
        logger.warning("Google loan app lookup error: %s", e)
        result["info"] = "Could not verify with Google"
    return result
    """
    Search Google for app info using Custom Search or scrape-free approach.
    Uses Google Safe Browsing + a simple requests check on Play Store URL.
    Returns: {found, play_store_url, rating, installs, developer, is_on_play_store}
    """
    result = {"found": False, "play_store_url": "", "developer": "",
              "is_on_play_store": False, "google_info": ""}
    try:
        # Check if app exists on Google Play Store
        search_name = app_name.lower().replace(' ', '+').replace('-', '+')
        play_url = f"https://play.google.com/store/search?q={search_name}&c=apps"
        headers = {"User-Agent": "Mozilla/5.0 (Android 13; Mobile) AppleWebKit/537.36"}
        r = requests.get(play_url, headers=headers, timeout=6)
        if r.status_code == 200:
            content = r.text.lower()
            # Check if app name appears in Play Store results
            name_words = [w for w in app_name.lower().split() if len(w) > 3]
            matches = sum(1 for w in name_words if w in content)
            if matches >= len(name_words) * 0.6:
                result["is_on_play_store"] = True
                result["found"] = True
                result["play_store_url"] = play_url
                result["google_info"] = "Found on Google Play Store"
            else:
                result["google_info"] = "Not found on Google Play Store"
    except Exception as e:
        logger.warning("Google app lookup error: %s", e)
        result["google_info"] = "Could not verify with Google"
    return result

def analyze_app_permissions(app_name: str, permissions: list, store_rating: float = 0, installs: str = "") -> dict:
    """Analyze Android app permissions + Google Play Store verification."""
    issues = []
    fraud_score = 0
    perm_details = []

    # ── Google Play Store check ──
    google_data = _google_search_app(app_name)
    if not google_data["is_on_play_store"]:
        fraud_score += 45
        issues.append("App NOT found on Google Play Store — high fraud risk")
    else:
        issues_info = [f"Verified on Google Play Store"]

    # ── Permission analysis ──
    for perm in permissions:
        perm_upper = perm.upper().replace("ANDROID.PERMISSION.", "")
        if perm_upper in DANGEROUS_PERMISSIONS:
            desc, severity = DANGEROUS_PERMISSIONS[perm_upper]
            perm_details.append({"permission": perm_upper, "description": desc, "severity": severity})
            if severity == "CRITICAL":
                fraud_score += 25
                issues.append(f"CRITICAL permission: {perm_upper} — {desc}")
            elif severity == "HIGH":
                fraud_score += 15
            elif severity == "MEDIUM":
                fraud_score += 8

    # ── Low rating penalty ──
    try:
        rating = float(store_rating)
        if 0 < rating < 3.0:
            fraud_score += 20
            issues.append(f"Low store rating: {rating}/5")
    except (ValueError, TypeError):
        pass

    # ── Loan scam keyword check ──
    hits = _keyword_hits(app_name, LOAN_SCAM_KEYWORDS)
    if hits:
        fraud_score += len(hits) * 15
        issues.append(f"Suspicious keywords in app name: {', '.join(hits)}")

    fraud_prob = min(fraud_score / 100, 1.0)
    score = _score_from_prob(fraud_prob)

    if fraud_prob > 0.6:
        result = "FRAUDULENT"
    elif fraud_prob > 0.3:
        result = "SUSPICIOUS"
    else:
        result = "SAFE"

    explanation = "; ".join(issues[:4]) if issues else "App appears legitimate and found on Google Play Store."

    return {
        "result": result,
        "trust_score": score,
        "risk_level": _risk_level(score),
        "explanation": explanation,
        "permission_details": perm_details,
        "dangerous_count": len([p for p in perm_details if p['severity'] in ('CRITICAL', 'HIGH')]),
        "is_on_play_store": google_data["is_on_play_store"],
        "google_info": google_data["google_info"],
        "play_store_url": google_data["play_store_url"],
        "red_flags": get_red_flags(app_name + " " + " ".join(permissions))
    }
