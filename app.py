"""
TrustLens AI – app.py
"""
import os,logging

import secrets
from dotenv import load_dotenv
from urllib.parse import urlparse
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_mysqldb import MySQL
#from flask_limiter import Limiter
#from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import ai_engine, verifier, threat_intel
from services import chat_service, chat_store

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-fallback-key')
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB upload limit

# ── MySQL ──────────────────────────────────────────────────────────────────────
_mysql_url = os.environ.get('MYSQL_URL')
if _mysql_url:
    _p = urlparse(_mysql_url)
    app.config['MYSQL_HOST']     = _p.hostname
    app.config['MYSQL_USER']     = _p.username
    app.config['MYSQL_PASSWORD'] = _p.password
    app.config['MYSQL_DB']       = _p.path.lstrip('/')
    app.config['MYSQL_PORT']     = _p.port or 3306
else:
    app.config['MYSQL_HOST']     = os.environ.get('MYSQL_HOST', 'localhost')
    app.config['MYSQL_USER']     = os.environ.get('MYSQL_USER', 'root')
    app.config['MYSQL_PASSWORD'] = os.environ.get('MYSQL_PASSWORD', '2007')
    app.config['MYSQL_DB']       = os.environ.get('MYSQL_DB', 'trustlens_ai')
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)

_CHAT_SCHEMA_READY = False


@app.before_request
def _ensure_session_csrf():
    if "user_id" in session and not session.get("csrf_token"):
        session["csrf_token"] = secrets.token_hex(32)


# ── Rate Limiter ───────────────────────────────────────────────────────────────
# limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "60 per hour"],
                #  storage_uri="memory://")

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ── Helpers ────────────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to continue.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def _require_chat_csrf():
    """JSON chat APIs require X-CSRF-Token matching session (double-submit)."""
    if request.headers.get("X-CSRF-Token", "") != session.get("csrf_token"):
        return jsonify({"error": "CSRF validation failed", "code": "csrf"}), 403
    return None


def _ensure_chat_schema():
    global _CHAT_SCHEMA_READY
    if _CHAT_SCHEMA_READY:
        return
    try:
        cur = mysql.connection.cursor()
        chat_store.ensure_schema(cur)
        mysql.connection.commit()
        cur.close()
        _CHAT_SCHEMA_READY = True
    except Exception as e:
        logger.warning("Chat schema init failed (conversations may be unavailable): %s", e)
        _CHAT_SCHEMA_READY = True


def save_scan(user_id, scan_type, input_text, result, trust_score, explanation):
    try:
        cur = mysql.connection.cursor()
        cur.execute(
            "INSERT INTO scans (user_id, scan_type, input_text, result, trust_score, explanation) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (user_id, scan_type, str(input_text)[:500], result, trust_score, str(explanation)[:1000])
        )
        mysql.connection.commit()
        cur.close()
    except Exception as e:
        logger.error("save_scan error: %s", e)

def get_dashboard_stats(uid):
    """Dashboard aggregates (no recent list / no 7-day series — charts use by_type + breakdown)."""
    cur = mysql.connection.cursor()
    cur.execute("SELECT COUNT(*) as total FROM scans WHERE user_id=%s", (uid,))
    total = cur.fetchone()['total']
    cur.execute(
        "SELECT COUNT(*) as c FROM scans WHERE user_id=%s "
        "AND result IN ('FAKE','SCAM','FRAUDULENT','DANGEROUS','SUSPICIOUS','BLACKLISTED','NOT FOUND')", (uid,))
    scam_count = cur.fetchone()['c']
    cur.execute("SELECT COUNT(*) as c FROM scans WHERE user_id=%s AND result IN ('SAFE','VERIFIED')", (uid,))
    safe_count = cur.fetchone()['c']
    cur.execute("SELECT scan_type, COUNT(*) as c FROM scans WHERE user_id=%s GROUP BY scan_type", (uid,))
    by_type = cur.fetchall()
    cur.execute("SELECT COUNT(*) as c FROM scans WHERE user_id=%s AND DATE(timestamp)=CURDATE()", (uid,))
    today_count = cur.fetchone()['c']

    cur.execute("SELECT result, COUNT(*) as c FROM scans WHERE user_id=%s GROUP BY result", (uid,))
    rb_rows = cur.fetchall()
    cur.close()

    safe_r = {'SAFE', 'VERIFIED'}
    dangerous_r = {'FAKE', 'SCAM', 'FRAUDULENT', 'DANGEROUS', 'BLACKLISTED'}
    rb_safe = rb_suspicious = rb_dangerous = 0
    for row in rb_rows:
        r = (row.get('result') or '').strip()
        c = int(row.get('c') or 0)
        if r in safe_r:
            rb_safe += c
        elif r in dangerous_r:
            rb_dangerous += c
        else:
            rb_suspicious += c

    result_breakdown = {'safe': rb_safe, 'suspicious': rb_suspicious, 'dangerous': rb_dangerous}

    return total, scam_count, safe_count, by_type, today_count, result_breakdown

# ── Security headers ───────────────────────────────────────────────────────────
@app.after_request
def security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# ── Public Routes ──────────────────────────────────────────────────────────────
@app.route('/')
def index():
    # Authenticated users should always land on the main dashboard.
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
#@limiter.limit("10 per hour")
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()[:80]
        email    = request.form.get('email', '').strip()[:120]
        password = request.form.get('password', '')
        if not username or not email or not password or len(password) < 6:
            flash('All fields required. Password min 6 chars.', 'danger')
            return redirect(url_for('register'))
        cur = mysql.connection.cursor()
        cur.execute("SELECT id FROM users WHERE email=%s OR username=%s", (email, username))
        if cur.fetchone():
            flash('Username or email already exists.', 'danger')
            cur.close()
            return redirect(url_for('register'))
        cur.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                    (username, email, generate_password_hash(password)))
        mysql.connection.commit()
        cur.close()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
#@limiter.limit("500 per hour")

def login():
    # If already logged in, avoid bouncing users to scanners/login.
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email    = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cur.fetchone()
        cur.close()
        if user and check_password_hash(user['password'], password):
            session['user_id']  = user['id']
            session['username'] = user['username']
            session['csrf_token'] = secrets.token_hex(32)
            flash(f"Welcome back, {user['username']}!", 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid credentials.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('index'))

# ── Protected Pages ────────────────────────────────────────────────────────────
@app.route('/dashboard')
@login_required
def dashboard():
    uid = session['user_id']
    total, scam_count, safe_count, by_type, today_count, result_breakdown = get_dashboard_stats(uid)
    return render_template(
        'dashboard.html',
        total=total,
        scam_count=scam_count,
        safe_count=safe_count,
        by_type=by_type,
        today_count=today_count,
        result_breakdown=result_breakdown,
    )

@app.route('/fake-job')
@login_required
def fake_job():
    return render_template('fake_job.html')

@app.route('/scam-message')
@login_required
def scam_message():
    return render_template('scam_message.html')

@app.route('/rbi-sebi')
@login_required
def rbi_sebi():
    return render_template('rbi_sebi.html')

@app.route('/loan-app')
@login_required
def loan_app():
    return render_template('loan_app.html')

@app.route('/website-scanner')
@login_required
def website_scanner():
    return render_template('website_scanner.html')

@app.route('/threat-map')
@login_required
def threat_map():
    return render_template('threat_map.html')


@app.route('/api/threats')
@login_required
def api_threats():
    """Aggregated threat intelligence for the live threat map."""
    try:
        return jsonify(threat_intel.get_live_threats())
    except Exception as e:
        logger.error("api_threats error: %s", e)
        return jsonify({
            "threats": [], "total": 0, "state_counts": {}, "type_counts": {},
            "sev_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
            "updated_at": 0, "sources": [], "error": "Could not load threat data.",
        })

@app.route('/qr-scanner')
@login_required
def qr_scanner():
    return render_template('qr_scanner.html')

@app.route('/app-analyzer')
@login_required
def app_analyzer():
    return render_template('app_analyzer.html')

@app.route('/report-fraud')
@login_required
def report_fraud():
    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT fr.*, u.username FROM fraud_reports fr "
        "JOIN users u ON fr.user_id=u.id ORDER BY fr.timestamp DESC LIMIT 50")
    reports = cur.fetchall()
    cur.close()
    return render_template('report_fraud.html', reports=reports)

@app.route('/history')
@login_required
def history():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM scans WHERE user_id=%s ORDER BY timestamp DESC", (session['user_id'],))
    scans = cur.fetchall()
    cur.close()
    return render_template('history.html', scans=scans)

# ── Scan APIs ──────────────────────────────────────────────────────────────────
@app.route('/api/scan/job', methods=['POST'])
@login_required
#@limiter.limit("30 per hour")
def api_scan_job():
    data = request.get_json() or {}
    res  = ai_engine.detect_fake_job(
        data.get('title', '')[:200], data.get('company', '')[:200],
        data.get('salary', '')[:100], data.get('description', '')[:2000])
    save_scan(session['user_id'], 'Fake Job',
              f"Job: {data.get('title')} at {data.get('company')}",
              res['result'], res['trust_score'], res['explanation'])
    return jsonify(res)

@app.route('/api/scan/message', methods=['POST'])
@login_required
#@limiter.limit("30 per hour")
def api_scan_message():
    data = request.get_json() or {}
    msg  = data.get('message', '')[:2000]
    res  = ai_engine.detect_scam_message(msg)
    save_scan(session['user_id'], 'Scam Message', msg[:200],
              res['result'], res['trust_score'], res['explanation'])
    return jsonify(res)

@app.route('/api/scan/verify', methods=['POST'])
@login_required
#@limiter.limit("30 per hour")
def api_verify():
    data  = request.get_json(force=True) or {}
    query = data.get('query', '').strip()[:200]
    res   = verifier.verify_platform(query)
    save_scan(session['user_id'], 'RBI/SEBI Check', query,
              res['result'], res['trust_score'], res['explanation'])
    return jsonify(res)

@app.route('/api/scan/loan', methods=['POST'])
@login_required
#@limiter.limit("30 per hour")
def api_scan_loan():
    data = request.get_json() or {}
    res  = ai_engine.detect_loan_app(
        data.get('app_name', '')[:200],
        data.get('permissions', '')[:500],
        data.get('interest_rate', 0))
    save_scan(session['user_id'], 'Loan App', data.get('app_name', ''),
              res['result'], res['trust_score'], res['explanation'])
    return jsonify(res)

@app.route('/api/scan/website', methods=['POST'])
@login_required
#@limiter.limit("30 per hour")
def api_scan_website():
    data = request.get_json() or {}
    url  = data.get('url', '')[:500]
    res  = ai_engine.scan_website(url)
    save_scan(session['user_id'], 'Website Scan', url,
              res['result'], res['trust_score'], res['explanation'])
    return jsonify(res)

@app.route('/api/scan/qr', methods=['POST'])
@login_required
#@limiter.limit("20 per hour")
def api_scan_qr():
    if 'image' not in request.files:
        return jsonify({'error': 'No image uploaded'}), 400
    f = request.files['image']
    if not f or not allowed_file(f.filename):
        return jsonify({'error': 'Invalid file type'}), 400
    filename = secure_filename(f.filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    f.save(filepath)
    res = ai_engine.scan_qr_image(filepath)
    save_scan(session['user_id'], 'QR Scanner', filename,
              res['result'], res['trust_score'], res['explanation'])
    try:
        os.remove(filepath)
    except Exception:
        pass
    return jsonify(res)

@app.route('/api/scan/qr-text', methods=['POST'])
@login_required
#@limiter.limit("30 per hour")
def api_scan_qr_text():
    data = request.get_json() or {}
    qr_text = data.get('qr_text', '').strip()[:1000]
    if not qr_text:
        return jsonify({'error': 'No QR text provided'}), 400
    res = ai_engine.scan_qr_text(qr_text)
    save_scan(session['user_id'], 'QR Scanner', qr_text[:200],
              res['result'], res['trust_score'], res['explanation'])
    return jsonify(res)

@app.route('/api/scan/app', methods=['POST'])
@login_required
#@limiter.limit("20 per hour")
def api_scan_app():
    data = request.get_json() or {}
    res  = ai_engine.analyze_app_permissions(
        data.get('app_name', '')[:200],
        data.get('permissions', []),
        data.get('store_rating', 0),
        data.get('installs', ''))
    save_scan(session['user_id'], 'App Analyzer', data.get('app_name', ''),
              res['result'], res['trust_score'], res['explanation'])
    return jsonify(res)

# ── Chatbot (Grok / xAI + DB conversations) ────────────────────────────────────
@app.route('/api/chatbot', methods=['POST'])
@login_required
#@limiter.limit("60 per hour")
def api_chatbot():
    bad = _require_chat_csrf()
    if bad:
        return bad
    _ensure_chat_schema()
    uid = session['user_id']
    data = request.get_json(silent=True) or {}
    regenerate = bool(data.get('regenerate'))

    history_client = data.get('history')
    if not isinstance(history_client, list):
        history_client = []
    history_client = history_client[-6:]

    try:
        cid_raw = data.get('conversation_id')
        cid = int(cid_raw) if cid_raw not in (None, '', 0, '0') else None
    except (TypeError, ValueError):
        cid = None

    cur = mysql.connection.cursor()
    try:
        if cid is not None and not chat_store.conversation_owned(cur, cid, uid):
            cid = None

        if regenerate:
            if not cid:
                return jsonify({'error': 'conversation_id required for regenerate', 'code': 'bad_request'}), 400
            if not chat_store.delete_last_assistant(cur, cid, uid):
                mysql.connection.rollback()
                return jsonify({'error': 'Nothing to regenerate', 'code': 'empty'}), 400
            user_msg = chat_store.get_last_user_message(cur, cid, uid) or ''
            user_msg = chat_service.sanitize_user_message(user_msg, 4000)
            if not user_msg:
                mysql.connection.rollback()
                return jsonify({'error': 'Missing user message', 'code': 'empty'}), 400
            hist = chat_store.fetch_messages_for_model(cur, cid, uid)
        else:
            user_msg = chat_service.sanitize_user_message(data.get('message', ''), 4000)
            if not user_msg:
                return jsonify({'response': 'Please type a message or use the microphone.'})
            if cid is None:
                cid = chat_store.create_conversation(cur, uid)
            hist = chat_store.fetch_messages_for_model(cur, cid, uid)
            if not hist:
                hist = history_client

        if "fake job" in user_msg.lower():
            bot_response = "Avoid jobs asking for money, OTPs, or personal bank details."
        elif "phishing" in user_msg.lower():
            bot_response = "Check URL spelling, HTTPS security, and avoid suspicious links."
        elif "loan" in user_msg.lower():
            bot_response = "Verify RBI registration before using loan apps."
        elif "scam" in user_msg.lower():
            bot_response = "Do not share OTPs, passwords, or banking details with unknown people."
        else:
            bot_response = "TrustLens AI recommends verifying suspicious websites, apps, jobs, and messages before trusting them."

        meta = {}

        if not regenerate:
            chat_store.append_message(cur, cid, 'user', user_msg, None)
        chat_store.append_message(cur, cid, 'assistant', bot_response, meta)
        chat_store.touch_conversation_title(cur, cid, uid, user_msg)

        try:
            cur.execute(
                'INSERT INTO chatbot_logs (user_id, user_message, bot_response) VALUES (%s, %s, %s)',
                (uid, user_msg[:500], bot_response[:2000]),
            )
        except Exception:
            pass

        mysql.connection.commit()
    except Exception as e:
        mysql.connection.rollback()
        logger.error('Chatbot error: %s', e)
        return jsonify({'response': 'Sorry, I encountered an error. Please try again.'})
    finally:
        cur.close()

    return jsonify({
        'response': bot_response,
        'conversation_id': cid,
        'meta': meta,
    })


@app.route('/api/chat/conversations', methods=['GET'])
@login_required
def api_chat_conversations_list():
    _ensure_chat_schema()
    cur = mysql.connection.cursor()
    try:
        rows = chat_store.list_conversations(cur, session['user_id'])
    finally:
        cur.close()
    return jsonify({'conversations': rows})


@app.route('/api/chat/conversations', methods=['POST'])
@login_required
#@limiter.limit('30 per hour')
def api_chat_conversations_create():
    bad = _require_chat_csrf()
    if bad:
        return bad
    _ensure_chat_schema()
    data = request.get_json(silent=True) or {}
    title = (data.get('title') or 'New chat').strip()[:200] or 'New chat'
    cid = None
    cur = mysql.connection.cursor()
    try:
        cid = chat_store.create_conversation(cur, session['user_id'], title)
        mysql.connection.commit()
    except Exception as e:
        mysql.connection.rollback()
        logger.error('create conversation: %s', e)
        return jsonify({'error': 'Could not create conversation'}), 500
    finally:
        cur.close()
    return jsonify({'id': cid, 'title': title})


@app.route('/api/chat/conversations/<int:cid>', methods=['DELETE'])
@login_required
#@limiter.limit('60 per hour')
def api_chat_conversations_delete(cid):
    bad = _require_chat_csrf()
    if bad:
        return bad
    _ensure_chat_schema()
    cur = mysql.connection.cursor()
    try:
        ok = chat_store.delete_conversation(cur, cid, session['user_id'])
        mysql.connection.commit()
    except Exception as e:
        mysql.connection.rollback()
        logger.error('delete conversation: %s', e)
        return jsonify({'error': 'Could not delete'}), 500
    finally:
        cur.close()
    if not ok:
        return jsonify({'error': 'Not found'}), 404
    return jsonify({'ok': True})


@app.route('/api/chat/conversations/<int:cid>/messages', methods=['GET'])
@login_required
def api_chat_conversations_messages(cid):
    _ensure_chat_schema()
    cur = mysql.connection.cursor()
    try:
        if not chat_store.conversation_owned(cur, cid, session['user_id']):
            return jsonify({'error': 'Not found'}), 404
        msgs = chat_store.fetch_messages_ui(cur, cid, session['user_id'])
    finally:
        cur.close()
    return jsonify({'messages': msgs})

# ── Fraud Report ───────────────────────────────────────────────────────────────
@app.route('/api/report', methods=['POST'])
@login_required
#@limiter.limit("10 per hour")
def api_report():
    data        = request.get_json() or {}
    report_type = data.get('report_type', 'other')
    target      = data.get('target', '').strip()[:500]
    description = data.get('description', '').strip()[:2000]
    if not target or not description:
        return jsonify({"error": "Target and description are required."}), 400
    cur = mysql.connection.cursor()
    cur.execute(
        "INSERT INTO fraud_reports (user_id, report_type, target, description) VALUES (%s, %s, %s, %s)",
        (session['user_id'], report_type, target, description))
    mysql.connection.commit()
    cur.close()
    return jsonify({"success": True, "message": "Report submitted. Thank you!"})

# ── Analytics ──────────────────────────────────────────────────────────────────
@app.route('/api/analytics')
@login_required
def api_analytics():
    uid = session['user_id']
    total, scam_count, safe_count, by_type, today_count, result_breakdown = get_dashboard_stats(uid)
    return jsonify({
        "total": total,
        "scam_count": scam_count,
        "safe_count": safe_count,
        "today_count": today_count,
        "by_type": by_type,
        "result_breakdown": result_breakdown,
    })

# ── WhatsApp Webhook (Twilio) ──────────────────────────────────────────────────
@app.route('/webhook/whatsapp', methods=['POST'])
def whatsapp_webhook():
    try:
        from_number = request.form.get('From', '')
        body        = request.form.get('Body', '').strip()
        if not body:
            return '', 200
        response_text, _meta = chat_service.generate_reply(body, None, use_grok=True)
        twilio_sid   = os.environ.get('TWILIO_ACCOUNT_SID')
        twilio_token = os.environ.get('TWILIO_AUTH_TOKEN')
        twilio_from  = os.environ.get('TWILIO_WHATSAPP_FROM', 'whatsapp:+14155238886')
        if twilio_sid and twilio_token:
            from twilio.rest import Client
            Client(twilio_sid, twilio_token).messages.create(
                body=response_text, from_=twilio_from, to=from_number)
        return '', 200
    except Exception as e:
        logger.error("WhatsApp webhook error: %s", e)
        return '', 200

@app.errorhandler(429)
def ratelimit_handler(e):
    return "too many requests, slow down", 429


if __name__ == '__main__':
    app.run(debug=os.environ.get('FLASK_DEBUG', 'False').lower() == 'true')