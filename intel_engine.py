"""
TrustLens AI – intel_engine.py
Google Search Intelligence for website reputation analysis.
Uses: Wikipedia API, Reddit API, DuckDuckGo (no-key fallback), VirusTotal API.
All external calls are non-blocking with timeouts and silent fallbacks.
"""
import os, re, logging, json
import requests
from urllib.parse import urlparse, quote_plus

logger = logging.getLogger(__name__)

VT_KEY     = os.environ.get('VIRUSTOTAL_API_KEY', '')
SERPER_KEY = os.environ.get('SERPER_API_KEY', '')

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

# ── Helpers ────────────────────────────────────────────────────────────────────
def _domain(url: str) -> str:
    try:
        return urlparse(url).netloc.replace('www.', '')
    except Exception:
        return url

SCAM_WORDS    = ["scam", "fraud", "phishing", "fake", "cheat", "hack", "malware",
                 "virus", "spam", "complaint", "warning", "dangerous", "blacklist",
                 "reported", "beware", "avoid", "illegal", "stolen", "deceptive"]
TRUSTED_WORDS = ["official", "verified", "legitimate", "trusted", "safe", "secure",
                 "certified", "authorized", "genuine", "reputable", "established"]

def _sentiment_score(texts: list) -> dict:
    """Score a list of text snippets for scam vs trust signals."""
    combined = " ".join(texts).lower()
    scam_hits    = [w for w in SCAM_WORDS    if w in combined]
    trusted_hits = [w for w in TRUSTED_WORDS if w in combined]
    return {
        "scam_signals":    scam_hits,
        "trusted_signals": trusted_hits,
        "scam_count":      len(scam_hits),
        "trusted_count":   len(trusted_hits),
    }

# ── VirusTotal ─────────────────────────────────────────────────────────────────
def _virustotal_scan(url: str) -> dict:
    result = {"checked": False, "malicious": 0, "suspicious": 0,
              "harmless": 0, "undetected": 0, "engines": [], "permalink": ""}
    if not VT_KEY or VT_KEY == 'your_virustotal_key':
        return result
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        r = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": VT_KEY}, timeout=8)
        if r.status_code == 200:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            results = r.json()["data"]["attributes"]["last_analysis_results"]
            result.update({
                "checked":    True,
                "malicious":  stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless":   stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "permalink":  f"https://www.virustotal.com/gui/url/{url_id}",
                "engines":    [k for k, v in results.items()
                               if v["category"] in ("malicious", "suspicious")][:5]
            })
        elif r.status_code == 404:
            # Submit for analysis
            requests.post("https://www.virustotal.com/api/v3/urls",
                          headers={"x-apikey": VT_KEY},
                          data={"url": url}, timeout=5)
    except Exception as e:
        logger.warning("VirusTotal error: %s", e)
    return result

# ── DuckDuckGo Instant Answer (no key needed) ──────────────────────────────────
def _ddg_search(query: str, max_results: int = 5) -> list:
    """Use DuckDuckGo HTML search as a free fallback."""
    results = []
    try:
        r = requests.get(
            f"https://html.duckduckgo.com/html/?q={quote_plus(query)}",
            headers=HEADERS, timeout=7)
        if r.status_code == 200:
            snippets = re.findall(r'class="result__snippet"[^>]*>(.*?)</a>', r.text, re.DOTALL)
            titles   = re.findall(r'class="result__a"[^>]*>(.*?)</a>', r.text, re.DOTALL)
            links    = re.findall(r'class="result__url"[^>]*>(.*?)</span>', r.text, re.DOTALL)
            for i in range(min(max_results, len(snippets))):
                results.append({
                    "title":   re.sub(r'<[^>]+>', '', titles[i]).strip()   if i < len(titles)   else "",
                    "snippet": re.sub(r'<[^>]+>', '', snippets[i]).strip() if i < len(snippets) else "",
                    "url":     links[i].strip()                             if i < len(links)    else "",
                })
    except Exception as e:
        logger.warning("DDG search error: %s", e)
    return results

# ── Serper API (optional, better results) ─────────────────────────────────────
def _serper_search(query: str, max_results: int = 5) -> list:
    results = []
    if not SERPER_KEY or SERPER_KEY == 'your_serper_key':
        return results
    try:
        r = requests.post(
            "https://google.serper.dev/search",
            headers={"X-API-KEY": SERPER_KEY, "Content-Type": "application/json"},
            json={"q": query, "num": max_results}, timeout=6)
        if r.status_code == 200:
            for item in r.json().get("organic", [])[:max_results]:
                results.append({
                    "title":   item.get("title", ""),
                    "snippet": item.get("snippet", ""),
                    "url":     item.get("link", ""),
                })
    except Exception as e:
        logger.warning("Serper error: %s", e)
    return results

def _web_search(query: str, max_results: int = 5) -> list:
    """Use Serper if configured, else DuckDuckGo."""
    results = _serper_search(query, max_results)
    if not results:
        results = _ddg_search(query, max_results)
    return results

# ── Reddit search ──────────────────────────────────────────────────────────────
def _reddit_search(domain: str) -> list:
    results = []
    try:
        r = requests.get(
            f"https://www.reddit.com/search.json?q={quote_plus(domain)}&sort=relevance&limit=5",
            headers={"User-Agent": "TrustLensAI/1.0"}, timeout=6)
        if r.status_code == 200:
            for post in r.json().get("data", {}).get("children", [])[:5]:
                d = post["data"]
                results.append({
                    "title":     d.get("title", ""),
                    "subreddit": d.get("subreddit", ""),
                    "score":     d.get("score", 0),
                    "url":       f"https://reddit.com{d.get('permalink', '')}",
                    "snippet":   d.get("selftext", "")[:200],
                })
    except Exception as e:
        logger.warning("Reddit search error: %s", e)
    return results

# ── Wikipedia domain lookup ────────────────────────────────────────────────────
def _wikipedia_domain(domain: str) -> dict:
    result = {"found": False, "title": "", "summary": "", "url": ""}
    try:
        # Search Wikipedia for the domain/company name
        company = domain.split('.')[0].replace('-', ' ')
        sr = requests.get(
            f"https://en.wikipedia.org/w/api.php?action=query&list=search"
            f"&srsearch={quote_plus(company)}&format=json&srlimit=1",
            headers={"User-Agent": "TrustLensAI/1.0"}, timeout=5)
        if sr.status_code == 200:
            hits = sr.json().get("query", {}).get("search", [])
            if hits:
                title = hits[0]["title"]
                pr = requests.get(
                    f"https://en.wikipedia.org/api/rest_v1/page/summary/{quote_plus(title)}",
                    headers={"User-Agent": "TrustLensAI/1.0"}, timeout=5)
                if pr.status_code == 200:
                    data = pr.json()
                    result.update({
                        "found":   True,
                        "title":   data.get("title", ""),
                        "summary": data.get("extract", "")[:400],
                        "url":     data.get("content_urls", {}).get("desktop", {}).get("page", "")
                    })
    except Exception as e:
        logger.warning("Wikipedia domain lookup error: %s", e)
    return result

# ── Main Intelligence Function ─────────────────────────────────────────────────
def fetch_website_intelligence(url: str) -> dict:
    """
    Fetch Google intelligence for a URL.
    Returns structured intel: scam reports, reviews, VT results, Reddit, Wikipedia.
    """
    domain = _domain(url)
    intel  = {
        "domain":          domain,
        "scam_results":    [],
        "review_results":  [],
        "news_results":    [],
        "reddit_posts":    [],
        "wikipedia":       {},
        "virustotal":      {},
        "sentiment":       {},
        "intel_score_adj": 0,   # positive = safer, negative = more dangerous
        "scam_alert":      False,
        "reputation":      "Unknown",
        "ai_summary":      "",
    }

    # 1. Scam / complaint search
    intel["scam_results"] = _web_search(f"{domain} scam fraud complaint review", 5)

    # 2. General reviews
    intel["review_results"] = _web_search(f"{domain} review legitimate safe", 4)

    # 3. News
    intel["news_results"] = _web_search(f"{domain} news warning phishing malware", 3)

    # 4. Reddit
    intel["reddit_posts"] = _reddit_search(domain)

    # 5. Wikipedia
    intel["wikipedia"] = _wikipedia_domain(domain)

    # 6. VirusTotal
    intel["virustotal"] = _virustotal_scan(url)

    # 7. Sentiment analysis across all results
    all_texts = (
        [r["snippet"] for r in intel["scam_results"]]   +
        [r["snippet"] for r in intel["review_results"]] +
        [r["snippet"] for r in intel["news_results"]]   +
        [p["title"]   for p in intel["reddit_posts"]]   +
        [intel["wikipedia"].get("summary", "")]
    )
    intel["sentiment"] = _sentiment_score(all_texts)

    # 8. Score adjustment based on intel
    adj = 0
    sc  = intel["sentiment"]["scam_count"]
    tc  = intel["sentiment"]["trusted_count"]
    vt  = intel["virustotal"]

    if vt.get("checked"):
        if vt["malicious"] > 0:
            adj -= (vt["malicious"] * 8)
            intel["scam_alert"] = True
        if vt["suspicious"] > 0:
            adj -= (vt["suspicious"] * 4)
        if vt["harmless"] > 10:
            adj += 15

    if sc >= 5:
        adj -= 30
        intel["scam_alert"] = True
    elif sc >= 3:
        adj -= 15
    elif sc >= 1:
        adj -= 8

    if tc >= 3:
        adj += 12
    elif tc >= 1:
        adj += 5

    if intel["wikipedia"]["found"]:
        adj += 10  # Wikipedia presence = some legitimacy

    intel["intel_score_adj"] = max(-50, min(20, adj))

    # 9. Reputation label
    if intel["scam_alert"] or adj <= -25:
        intel["reputation"] = "Dangerous"
    elif adj <= -10:
        intel["reputation"] = "Suspicious"
    elif adj >= 10:
        intel["reputation"] = "Trusted"
    else:
        intel["reputation"] = "Unverified"

    # 10. AI summary
    intel["ai_summary"] = _build_summary(domain, intel)

    return intel


def _build_summary(domain: str, intel: dict) -> str:
    parts = []
    vt = intel["virustotal"]

    if vt.get("checked"):
        if vt["malicious"] > 0:
            parts.append(f"VirusTotal flagged by {vt['malicious']} security engines as malicious.")
        elif vt["suspicious"] > 0:
            parts.append(f"VirusTotal marked suspicious by {vt['suspicious']} engines.")
        else:
            parts.append("VirusTotal: No threats detected.")

    sc = intel["sentiment"]["scam_count"]
    tc = intel["sentiment"]["trusted_count"]
    if sc > 0:
        parts.append(f"Found {sc} scam/fraud signal(s) in web search results: "
                     f"{', '.join(intel['sentiment']['scam_signals'][:4])}.")
    if tc > 0:
        parts.append(f"Found {tc} trust signal(s): "
                     f"{', '.join(intel['sentiment']['trusted_signals'][:3])}.")

    if intel["wikipedia"]["found"]:
        parts.append(f"Wikipedia: {intel['wikipedia']['summary'][:200]}")

    if intel["reddit_posts"]:
        parts.append(f"{len(intel['reddit_posts'])} Reddit discussion(s) found about this domain.")

    if not parts:
        parts.append(f"No significant intelligence found for {domain}. Exercise caution with unknown sites.")

    return " ".join(parts)
