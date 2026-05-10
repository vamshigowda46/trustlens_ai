"""
TrustLens AI – ai_engine.py
NLP fraud detection: TF-IDF + Logistic Regression + keyword analysis
Features: red flag explainer, chatbot responses
"""
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

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
    if score >= 90: return "Safe"
    if score >= 60: return "Suspicious"
    return "Dangerous"

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

# ── Detection Functions ────────────────────────────────────────────────────────
def detect_fake_job(title, company, salary, description):
    text = f"{title} {company} {salary} {description}"
    prob = job_clf.predict_proba(job_vec.transform([text]))[0][1]
    hits = _keyword_hits(text, FRAUD_KEYWORDS)
    red_flags = get_red_flags(text)

    if hits:
        prob = min(1.0, prob + 0.15 * len(hits))

    score = _score_from_prob(prob)
    result = "FAKE" if prob > 0.5 else "SAFE"
    explanation = (
        f"Suspicious keywords detected: {', '.join(hits[:5])}. High fraud probability."
        if hits else
        ("Job posting shows multiple fraud indicators." if result == "FAKE"
         else "Job posting appears legitimate with no major red flags.")
    )
    return {
        "result": result, "trust_score": score, "risk_level": _risk_level(score),
        "explanation": explanation, "keywords": hits[:8], "red_flags": red_flags
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
    try:
        rate = float(interest_rate)
        if rate > 36:
            fraud_score += 40
        elif rate > 24:
            fraud_score += 20
    except (ValueError, TypeError):
        pass

    dangerous_perms = ["contacts", "sms", "camera", "location", "storage", "call logs"]
    perm_hits = [p for p in dangerous_perms if p in permissions.lower()]
    fraud_score += len(perm_hits) * 8

    fraud_prob = min(fraud_score / 100, 1.0)
    score = _score_from_prob(fraud_prob)
    result = "FRAUDULENT" if fraud_prob > 0.5 else "SAFE"
    explanation = (
        f"Dangerous permissions: {', '.join(perm_hits)}. "
        f"Suspicious indicators: {', '.join(hits[:4])}." if result == "FRAUDULENT"
        else "Loan app appears legitimate. Interest rate and permissions seem reasonable."
    )
    return {
        "result": result, "trust_score": score, "risk_level": _risk_level(score),
        "explanation": explanation, "keywords": hits + perm_hits, "red_flags": red_flags
    }

def scan_website(url):
    url_lower = url.lower()
    issues = []
    fraud_score = 0

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

    if re.search(r'[^\w\-./:]', url.split('//')[-1].split('/')[0]):
        issues.append("Special characters in domain")
        fraud_score += 20

    fraud_prob = min(fraud_score / 100, 1.0)
    score = _score_from_prob(fraud_prob)

    if score >= 90:
        result = "SAFE"
    elif score >= 60:
        result = "SUSPICIOUS"
    else:
        result = "DANGEROUS"

    explanation = (
        "; ".join(issues) if issues
        else "URL appears safe. HTTPS present, no suspicious patterns detected."
    )
    return {
        "result": result, "trust_score": score, "risk_level": _risk_level(score),
        "explanation": explanation, "issues": issues
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
        "response": "👋 **Hello! I'm TrustLens AI Assistant.**\n\nI can help you with:\n\n🔍 Identifying fake jobs\n📱 Detecting scam messages\n🌐 Checking website safety\n💰 Spotting loan scams\n📈 Avoiding investment fraud\n🏛️ Verifying RBI/SEBI companies\n\nAsk me anything about digital fraud or cybersecurity!"
    },
    {
        "triggers": ["report", "how to report", "report scam", "report fraud"],
        "response": "📢 **How to Report Fraud:**\n\n• Use our **Community Report** feature to report scam websites, jobs, and apps\n• Report to Cyber Crime: cybercrime.gov.in\n• Call National Cyber Crime Helpline: **1930**\n• Report UPI fraud to your bank immediately\n• File complaint at your nearest police station\n\n✅ Your reports help protect the entire community!"
    },
]

def get_chatbot_response(user_message):
    """Match user message to knowledge base and return response."""
    msg_lower = user_message.lower().strip()

    for entry in CHATBOT_KB:
        if any(trigger in msg_lower for trigger in entry["triggers"]):
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
