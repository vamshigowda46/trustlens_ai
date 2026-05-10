"""
TrustLens AI – verifier.py
Intelligent RBI/SEBI/NBFC platform verification engine.
Uses: normalize, partial match, alias match, fuzzy match, clone detection.
No DB dependency — works entirely from the built-in registry.
"""
import re

# ── Normalize helper ───────────────────────────────────────────────────────────
def normalize_name(text):
    """Lowercase, strip symbols, remove common noise suffixes."""
    text = text.lower().strip()
    text = re.sub(r'[^a-z0-9\s]', ' ', text)
    noise = ['app', 'loan', 'loans', 'finance', 'fintech',
             'india', 'limited', 'ltd', 'pvt', 'inc',
             'technologies', 'technology', 'services', 'solutions', 'digital',
             'online', 'official', 'original']
    words = text.split()
    core = ' '.join(w for w in words if w not in noise).strip()
    return core if core else text

def fuzzy_match(a, b):
    """Bigram similarity ratio (0.0–1.0)."""
    a, b = a.replace(' ', ''), b.replace(' ', '')
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    def bigrams(s):
        return {s[i:i+2] for i in range(len(s) - 1)}
    ba, bb = bigrams(a), bigrams(b)
    if not ba or not bb:
        return 1.0 if (a in b or b in a) else 0.0
    return 2 * len(ba & bb) / (len(ba) + len(bb))

# ── Clone / Impersonation detection ───────────────────────────────────────────
CLONE_WORDS = re.compile(
    r'\b(profit|double|triple|earn|fast|quick|instant|cash|free|bonus|reward|'
    r'fake|clone|copy|duplicate|hack|crack|mod|unofficial|guaranteed|get rich)\b'
)
def is_suspicious_url(text):
    """
    Detect suspicious scam/phishing URLs.
    """
    text = text.lower()

    suspicious_keywords = [
        "profit", "double", "triple", "free",
        "bonus", "reward", "cash", "instant",
        "loan", "hack", "mod", "apk",
        "win", "gift", "guaranteed",
        "crypto", "investment", "rich"
    ]

    suspicious_domains = [
        ".xyz", ".top", ".click", ".live",
        ".vip", ".shop", ".loan", ".monster"
    ]

    for word in suspicious_keywords:
        if word in text:
            return True

    for domain in suspicious_domains:
        if domain in text:
            return True

    return False
def is_clone_attempt(raw_query, canonical_name, aliases):
    """Return True if query looks like a fake clone of a real app."""
    q = raw_query.lower().strip()
    # Check against canonical name and all aliases
    for name in [canonical_name.lower()] + [a.lower() for a in aliases]:
        if name in q and q != name:
            extra = q.replace(name, '').strip()
            if extra and CLONE_WORDS.search(extra):
                return True
    return False

# ── Master Registry ────────────────────────────────────────────────────────────
# (canonical_name, aliases, category, regulator, reg_type, website)
REGISTRY = [
    # ── BANKS ──────────────────────────────────────────────────────────────────
    ("State Bank of India",
     ["sbi", "yono", "yono sbi", "sbi bank", "state bank", "sbi mobile", "sbi anywhere"],
     "Public Sector Bank", "RBI", "Scheduled Commercial Bank", "sbi.co.in"),
    ("HDFC Bank",
     ["hdfc", "hdfc bank", "hdfc mobile banking", "hdfc netbanking", "hdfc mobilebanking"],
     "Private Sector Bank", "RBI", "Scheduled Commercial Bank", "hdfcbank.com"),
    ("ICICI Bank",
     ["icici", "imobile", "imobile pay", "icici bank", "icici netbanking"],
     "Private Sector Bank", "RBI", "Scheduled Commercial Bank", "icicibank.com"),
    ("Axis Bank",
     ["axis", "axis bank", "axis mobile", "axis netbanking", "axis pay"],
     "Private Sector Bank", "RBI", "Scheduled Commercial Bank", "axisbank.com"),
    ("Kotak Mahindra Bank",
     ["kotak", "kotak bank", "kotak 811", "kotak mobile banking", "kotak mahindra"],
     "Private Sector Bank", "RBI", "Scheduled Commercial Bank", "kotak.com"),
    ("Punjab National Bank",
     ["pnb", "pnb bank", "pnb one", "punjab national"],
     "Public Sector Bank", "RBI", "Scheduled Commercial Bank", "pnb.co.in"),
    ("Bank of Baroda",
     ["bob", "bank of baroda", "bob world", "baroda"],
     "Public Sector Bank", "RBI", "Scheduled Commercial Bank", "bankofbaroda.in"),
    ("Canara Bank",
     ["canara", "canara bank", "canarabank"],
     "Public Sector Bank", "RBI", "Scheduled Commercial Bank", "canarabank.in"),
    ("IndusInd Bank",
     ["indusind", "indusind bank", "indusind mobile"],
     "Private Sector Bank", "RBI", "Scheduled Commercial Bank", "indusind.com"),
    ("Yes Bank",
     ["yes bank", "yes mobile", "yesbank"],
     "Private Sector Bank", "RBI", "Scheduled Commercial Bank", "yesbank.in"),
    ("Federal Bank",
     ["federal bank", "fedmobile", "federal"],
     "Private Sector Bank", "RBI", "Scheduled Commercial Bank", "federalbank.co.in"),
    ("IDFC First Bank",
     ["idfc", "idfc first", "idfc bank", "idfc first bank"],
     "Private Sector Bank", "RBI", "Scheduled Commercial Bank", "idfcfirstbank.com"),
    ("RBL Bank",
     ["rbl", "rbl bank", "rbl mobank"],
     "Private Sector Bank", "RBI", "Scheduled Commercial Bank", "rblbank.com"),

    # ── UPI / PAYMENT APPS ─────────────────────────────────────────────────────
    ("PhonePe",
     ["phonepe", "phone pe", "phonepay", "phone pay"],
     "UPI Payment App", "RBI", "Payment Aggregator / NBFC", "phonepe.com"),
    ("Paytm",
     ["paytm", "paytm bank", "paytm payments bank", "paytm wallet", "paytm money"],
     "Payment App / NBFC", "RBI", "Payments Bank", "paytm.com"),
    ("Google Pay",
     ["gpay", "google pay", "googlepay", "tez", "google tez"],
     "UPI Payment App", "RBI", "Payment Aggregator", "pay.google.com"),
    ("Amazon Pay",
     ["amazon pay", "amazonpay", "amazon wallet"],
     "UPI Payment App", "RBI", "Payment Aggregator", "amazon.in/pay"),
    ("CRED",
     ["cred", "cred app", "cred pay", "cred upi"],
     "Fintech / Credit Card App", "RBI", "NBFC / Payment Aggregator", "cred.club"),
    ("MobiKwik",
     ["mobikwik", "mobi kwik", "mobikwik wallet", "mobikwik zip"],
     "Digital Wallet", "RBI", "Prepaid Payment Instrument", "mobikwik.com"),
    ("Freecharge",
     ["freecharge", "free charge"],
     "Digital Wallet", "RBI", "Prepaid Payment Instrument", "freecharge.in"),
    ("Airtel Payments Bank",
     ["airtel payments bank", "airtel bank", "airtel money", "airtel thanks"],
     "Payments Bank", "RBI", "Payments Bank", "airtel.in/bank"),
    ("Jio Payments Bank",
     ["jio payments bank", "jio bank", "jio money"],
     "Payments Bank", "RBI", "Payments Bank", "jio.com"),
    ("BHIM",
     ["bhim", "bhim upi", "bhim app"],
     "UPI App", "RBI", "NPCI UPI App", "bhimupi.org.in"),

    # ── STOCK BROKERS / SEBI ───────────────────────────────────────────────────
    ("Zerodha",
     ["zerodha", "kite", "kite zerodha", "zerodha kite", "coin zerodha", "zerodha coin"],
     "Stock Broker", "SEBI", "SEBI Registered Broker", "zerodha.com"),
    ("Groww",
     ["groww", "groww app", "groww invest", "groww stocks", "groww mutual fund"],
     "Investment Platform", "SEBI", "SEBI Registered Broker", "groww.in"),
    ("Upstox",
     ["upstox", "upstox pro", "rksv", "upstox app"],
     "Stock Broker", "SEBI", "SEBI Registered Broker", "upstox.com"),
    ("Angel One",
     ["angel one", "angel broking", "angelone", "angel app", "angel bee"],
     "Stock Broker", "SEBI", "SEBI Registered Broker", "angelone.in"),
    ("5paisa",
     ["5paisa", "5 paisa", "fivepaisa"],
     "Stock Broker", "SEBI", "SEBI Registered Broker", "5paisa.com"),
    ("HDFC Securities",
     ["hdfc securities", "hdfcsec", "hdfc sec"],
     "Stock Broker", "SEBI", "SEBI Registered Broker", "hdfcsec.com"),
    ("ICICI Direct",
     ["icici direct", "icicidirect", "icici securities"],
     "Stock Broker", "SEBI", "SEBI Registered Broker", "icicidirect.com"),
    ("SBI Securities",
     ["sbi securities", "sbisec", "sbi cap securities"],
     "Stock Broker", "SEBI", "SEBI Registered Broker", "sbisec.co.in"),
    ("Axis Direct",
     ["axis direct", "axisdirect"],
     "Stock Broker", "SEBI", "SEBI Registered Broker", "axisdirect.in"),
    ("Kotak Securities",
     ["kotak securities", "kotak sec", "kotak stock"],
     "Stock Broker", "SEBI", "SEBI Registered Broker", "kotaksecurities.com"),
    ("Motilal Oswal",
     ["motilal oswal", "motilal", "mosl", "mo investor"],
     "Stock Broker", "SEBI", "SEBI Registered Broker", "motilaloswal.com"),
    ("Sharekhan",
     ["sharekhan", "share khan"],
     "Stock Broker", "SEBI", "SEBI Registered Broker", "sharekhan.com"),
    ("Edelweiss",
     ["edelweiss", "edelweiss broking", "nuvama"],
     "Stock Broker", "SEBI", "SEBI Registered Broker", "edelweiss.in"),
    ("Dhan",
     ["dhan", "dhan app", "dhan trading"],
     "Stock Broker", "SEBI", "SEBI Registered Broker", "dhan.co"),
    ("Fyers",
     ["fyers", "fyers one"],
     "Stock Broker", "SEBI", "SEBI Registered Broker", "fyers.in"),
    ("Samco",
     ["samco", "samco securities"],
     "Stock Broker", "SEBI", "SEBI Registered Broker", "samco.in"),
    ("Mstock",
     ["mstock", "m stock", "mirae asset mstock"],
     "Stock Broker", "SEBI", "SEBI Registered Broker", "mstock.mirae-asset.com"),

    # ── MUTUAL FUNDS ───────────────────────────────────────────────────────────
    ("Nippon India Mutual Fund",
     ["nippon", "nippon india", "reliance mutual fund", "nippon mf"],
     "Mutual Fund", "SEBI", "SEBI Registered AMC", "nipponindiamf.com"),
    ("SBI Mutual Fund",
     ["sbi mutual fund", "sbi mf", "sbimf"],
     "Mutual Fund", "SEBI", "SEBI Registered AMC", "sbimf.com"),
    ("HDFC Mutual Fund",
     ["hdfc mutual fund", "hdfc mf", "hdfcmf"],
     "Mutual Fund", "SEBI", "SEBI Registered AMC", "hdfcfund.com"),
    ("Mirae Asset",
     ["mirae", "mirae asset", "mirae mutual fund"],
     "Mutual Fund", "SEBI", "SEBI Registered AMC", "miraeassetmf.co.in"),
    ("Paytm Money",
     ["paytm money", "paytmmoney"],
     "Investment Platform", "SEBI", "SEBI Registered Broker", "paytmmoney.com"),
    ("Coin by Zerodha",
     ["coin", "zerodha coin", "coin app"],
     "Mutual Fund Platform", "SEBI", "SEBI Registered", "coin.zerodha.com"),
    ("ET Money",
     ["et money", "etmoney", "economic times money"],
     "Mutual Fund Platform", "SEBI", "SEBI Registered", "etmoney.com"),
    ("Kuvera",
     ["kuvera", "kuvera app"],
     "Mutual Fund Platform", "SEBI", "SEBI Registered", "kuvera.in"),
    ("Scripbox",
     ["scripbox", "script box"],
     "Mutual Fund Platform", "SEBI", "SEBI Registered", "scripbox.com"),
    ("INDmoney",
     ["indmoney", "ind money", "ind money app"],
     "Wealth Management", "SEBI", "SEBI Registered", "indmoney.com"),
    ("Smallcase",
     ["smallcase", "small case"],
     "Investment Platform", "SEBI", "SEBI Registered RA", "smallcase.com"),

    # ── NBFC / LENDING ─────────────────────────────────────────────────────────
    ("Bajaj Finance",
     ["bajaj finance", "bajaj finserv", "bajaj emi", "bajaj markets", "bajaj allianz"],
     "NBFC", "RBI", "Systemically Important NBFC", "bajajfinserv.in"),
    ("Tata Capital",
     ["tata capital", "tata finance", "tata money"],
     "NBFC", "RBI", "RBI Registered NBFC", "tatacapital.com"),
    ("Muthoot Finance",
     ["muthoot", "muthoot finance", "imuthoot", "muthoot gold loan"],
     "NBFC", "RBI", "RBI Registered NBFC", "muthootfinance.com"),
    ("Manappuram Finance",
     ["manappuram", "manappuram finance", "manappuram gold"],
     "NBFC", "RBI", "RBI Registered NBFC", "manappuram.com"),
    ("Mahindra Finance",
     ["mahindra finance", "mmfsl", "mahindra rural"],
     "NBFC", "RBI", "RBI Registered NBFC", "mahindrafinance.com"),
    ("L&T Finance",
     ["l&t finance", "lt finance", "l and t finance"],
     "NBFC", "RBI", "RBI Registered NBFC", "ltfs.com"),
    ("Shriram Finance",
     ["shriram", "shriram finance", "shriram transport", "shriram city"],
     "NBFC", "RBI", "RBI Registered NBFC", "shriramfinance.com"),
    ("Cholamandalam Finance",
     ["chola", "cholamandalam", "chola finance", "chola ms"],
     "NBFC", "RBI", "RBI Registered NBFC", "cholamandalam.com"),
    ("HDB Financial Services",
     ["hdb", "hdb financial", "hdbfs"],
     "NBFC", "RBI", "RBI Registered NBFC", "hdbfs.com"),
    ("Aditya Birla Finance",
     ["aditya birla", "aditya birla finance", "abfl", "ab capital"],
     "NBFC", "RBI", "RBI Registered NBFC", "adityabirlacapital.com"),

    # ── DIGITAL LENDING / FINTECH ──────────────────────────────────────────────
    ("Navi",
     ["navi", "navi app", "navi loans", "navi mutual fund", "navi finserv"],
     "Digital Lending / Fintech", "RBI", "RBI Registered NBFC", "navi.com"),
    ("KreditBee",
     ["kreditbee", "kredit bee", "kreditbee loan"],
     "Digital Lending", "RBI", "RBI Registered NBFC", "kreditbee.in"),
    ("MoneyView",
     ["moneyview", "money view", "moneyview loan"],
     "Digital Lending", "RBI", "RBI Registered NBFC", "moneyview.in"),
    ("LazyPay",
     ["lazypay", "lazy pay", "lazypay credit"],
     "BNPL / Digital Credit", "RBI", "RBI Registered NBFC", "lazypay.in"),
    ("Slice",
     ["slice", "slice card", "slice app", "sliceit"],
     "BNPL / Fintech", "RBI", "RBI Registered NBFC", "sliceit.in"),
    ("Jupiter",
     ["jupiter", "jupiter money", "jupiter bank"],
     "Neobank / Fintech", "RBI", "RBI Partner Bank", "jupiter.money"),
    ("Fi Money",
     ["fi", "fi money", "fi app", "fi bank"],
     "Neobank / Fintech", "RBI", "RBI Partner Bank", "fi.money"),
    ("Niyo",
     ["niyo", "niyo global", "niyo money"],
     "Neobank / Fintech", "RBI", "RBI Partner Bank", "niyo.co"),
    ("EarlySalary",
     ["earlysalary", "early salary", "early salary loan", "fibe"],
     "Digital Lending", "RBI", "RBI Registered NBFC", "earlysalary.com"),
    ("CASHe",
     ["cashe", "cashe loan", "cash e"],
     "Digital Lending", "RBI", "RBI Registered NBFC", "cashe.com"),
    ("PaySense",
     ["paysense", "pay sense", "paysense loan"],
     "Digital Lending", "RBI", "RBI Registered NBFC", "gopaysense.com"),
    ("Stashfin",
     ["stashfin", "stash fin"],
     "Digital Lending", "RBI", "RBI Registered NBFC", "stashfin.com"),
    ("Kissht",
     ["kissht", "kissht loan"],
     "Digital Lending", "RBI", "RBI Registered NBFC", "kissht.com"),
    ("ZestMoney",
     ["zestmoney", "zest money"],
     "BNPL / Digital Credit", "RBI", "RBI Registered NBFC", "zestmoney.in"),
    ("Lendingkart",
     ["lendingkart", "lending kart"],
     "SME Lending", "RBI", "RBI Registered NBFC", "lendingkart.com"),
    ("Capital Float",
     ["capital float", "capitalfloat"],
     "SME Lending", "RBI", "RBI Registered NBFC", "capitalfloat.com"),
    ("Indifi",
     ["indifi", "indifi loan"],
     "SME Lending", "RBI", "RBI Registered NBFC", "indifi.com"),

    # ── INSURANCE ──────────────────────────────────────────────────────────────
    ("PolicyBazaar",
     ["policybazaar", "policy bazaar", "pb fintech"],
     "Insurance Aggregator", "IRDAI", "IRDAI Registered Broker", "policybazaar.com"),
    ("Acko",
     ["acko", "acko insurance", "acko general"],
     "Digital Insurance", "IRDAI", "IRDAI Registered Insurer", "acko.com"),
    ("Digit Insurance",
     ["digit", "go digit", "digit insurance"],
     "Digital Insurance", "IRDAI", "IRDAI Registered Insurer", "godigit.com"),
]

# ── Pre-build search index ─────────────────────────────────────────────────────
_INDEX = []
for idx, entry in enumerate(REGISTRY):
    canonical = entry[0]
    aliases   = entry[1]
    _INDEX.append((normalize_name(canonical), idx))
    for alias in aliases:
        _INDEX.append((normalize_name(alias), idx))

def is_suspicious_url(text):
    text = text.lower()

    suspicious_keywords = [
        "profit", "double", "triple", "free",
        "bonus", "reward", "cash", "instant",
        "loan", "hack", "mod", "apk",
        "win", "gift", "guaranteed"
    ]

    suspicious_domains = [
        ".xyz", ".top", ".click", ".live",
        ".vip", ".shop"
    ]

    for word in suspicious_keywords:
        if word in text:
            return True

    for domain in suspicious_domains:
        if domain in text:
            return True

    return False
def verify_platform(query):
    """
    Main verification function.
    Returns a rich dict with result, confidence, details.
    """
    if not query or not query.strip():
        return _not_found(query or "")

    raw_query  = query.strip()
    norm_query = normalize_name(raw_query)
    # Detect suspicious URLs first
    
    

    # ── Fast path: check raw query against every registry entry for clone ──
    # This catches "Groww Profit Double" before normalization strips keywords
    raw_lower = raw_query.lower()
    for idx, entry in enumerate(REGISTRY):
        cname, caliases = entry[0], entry[1]
        if is_clone_attempt(raw_query, cname, caliases):
            _, _, category, regulator, reg_type, website = entry
            return {
                "result":       "SUSPICIOUS CLONE",
                "trust_score":  15,
                "risk_level":   "Dangerous",
                "confidence":   90,
                "found":        True,
                "is_clone":     True,
                "matched_name": cname,
                "category":     category,
                "regulator":    regulator,
                "reg_type":     reg_type,
                "website":      website,
                "match_type":   "clone",
                "explanation":  (
                    f"'{raw_query}' appears to be impersonating '{cname}', "
                    f"a legitimate {regulator}-registered platform. "
                    f"This looks like a FAKE CLONE app. Do NOT use it."
                )
            }

    best_score      = 0.0
    best_idx        = -1
    best_match_type = ""

    for (norm_alias, reg_idx) in _INDEX:
        if not norm_alias:
            continue

        # 1. Exact match
        if norm_query == norm_alias:
            best_score      = 1.0
            best_idx        = reg_idx
            best_match_type = "exact"
            break

        # 2. Substring match
        if norm_alias in norm_query or norm_query in norm_alias:
            longer  = max(len(norm_alias), len(norm_query))
            shorter = min(len(norm_alias), len(norm_query))
            score   = min((shorter / longer) + 0.2, 0.95)
            if score > best_score:
                best_score      = score
                best_idx        = reg_idx
                best_match_type = "partial"

        # 3. Fuzzy — only when no strong match yet
        if best_score < 0.85:
            fscore = fuzzy_match(norm_query, norm_alias)
            if fscore > best_score and fscore >= 0.65:
                best_score      = fscore
                best_idx        = reg_idx
                best_match_type = "fuzzy"

    if best_idx == -1 or best_score < 0.55:
        return _not_found(raw_query)

    canonical_name, aliases, category, regulator, reg_type, website = REGISTRY[best_idx]

    # Clone / impersonation check
    if is_clone_attempt(raw_query, canonical_name, aliases):
        return {
            "result":       "SUSPICIOUS CLONE",
            "trust_score":  15,
            "risk_level":   "Dangerous",
            "confidence":   round(best_score * 100),
            "found":        True,
            "is_clone":     True,
            "matched_name": canonical_name,
            "category":     category,
            "regulator":    regulator,
            "reg_type":     reg_type,
            "website":      website,
            "match_type":   best_match_type,
            "explanation":  (
                f"'{raw_query}' appears to be impersonating '{canonical_name}', "
                f"a legitimate {regulator}-registered platform. "
                f"This looks like a FAKE CLONE app. Do NOT use it."
            )
        }

    confidence = round(best_score * 100)
    if confidence >= 85:
        result, trust_score, risk_level = "VERIFIED", 95, "Safe"
    elif confidence >= 65:
        result, trust_score, risk_level = "LIKELY VERIFIED", 75, "Suspicious"
    else:
        result, trust_score, risk_level = "POSSIBLY VERIFIED", 60, "Suspicious"

    return {
        "result":       result,
        "trust_score":  trust_score,
        "risk_level":   risk_level,
        "confidence":   confidence,
        "found":        True,
        "is_clone":     False,
        "matched_name": canonical_name,
        "category":     category,
        "regulator":    regulator,
        "reg_type":     reg_type,
        "website":      website,
        "match_type":   best_match_type,
        "explanation":  (
            f"'{canonical_name}' is registered with {regulator} as a {reg_type}. "
            f"Official website: {website}. Confidence: {confidence}%."
        )
    }


def _not_found(query):
    return {
        "result":       "NOT VERIFIED",
        "trust_score":  10,
        "risk_level":   "Dangerous",
        "confidence":   0,
        "found":        False,
        "is_clone":     False,
        "matched_name": None,
        "category":     None,
        "regulator":    None,
        "reg_type":     None,
        "website":      None,
        "match_type":   "none",
        "explanation":  (
            f"'{query}' was not found in our RBI/SEBI/IRDAI verified database. "
            "This does NOT mean it is fraudulent — it may be a newer platform. "
            "Always verify directly on rbi.org.in or sebi.gov.in before investing."
        )
    }
