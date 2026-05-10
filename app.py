"""
TrustLens AI – app.py
Flask application: auth, scan APIs, chatbot, fraud reports, analytics
"""
import os
from dotenv import load_dotenv
from urllib.parse import urlparse
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import ai_engine
import verifier

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-fallback-key')

# ── MySQL Config ───────────────────────────────────────────────────────────────
_mysql_url = os.environ.get('MYSQL_URL')
if _mysql_url:
    _p = urlparse(_mysql_url)
    app.config['MYSQL_HOST'] = _p.hostname
    app.config['MYSQL_USER'] = _p.username
    app.config['MYSQL_PASSWORD'] = _p.password
    app.config['MYSQL_DB'] = _p.path.lstrip('/')
    app.config['MYSQL_PORT'] = _p.port or 3306
else:
    app.config['MYSQL_HOST'] = os.environ.get('MYSQL_HOST', 'localhost')
    app.config['MYSQL_USER'] = os.environ.get('MYSQL_USER', 'root')
    app.config['MYSQL_PASSWORD'] = os.environ.get('MYSQL_PASSWORD', '2007')
    app.config['MYSQL_DB'] = os.environ.get('MYSQL_DB', 'trustlens_ai')
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)

# ── Helpers ────────────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to continue.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def save_scan(user_id, scan_type, input_text, result, trust_score, explanation):
    cur = mysql.connection.cursor()
    cur.execute(
        "INSERT INTO scans (user_id, scan_type, input_text, result, trust_score, explanation) "
        "VALUES (%s, %s, %s, %s, %s, %s)",
        (user_id, scan_type, str(input_text)[:500], result, trust_score, str(explanation)[:1000])
    )
    mysql.connection.commit()
    cur.close()

def get_dashboard_stats(uid):
    cur = mysql.connection.cursor()
    cur.execute("SELECT COUNT(*) as total FROM scans WHERE user_id=%s", (uid,))
    total = cur.fetchone()['total']

    cur.execute(
        "SELECT COUNT(*) as c FROM scans WHERE user_id=%s "
        "AND result IN ('FAKE','SCAM','FRAUDULENT','DANGEROUS','SUSPICIOUS','BLACKLISTED','NOT FOUND')",
        (uid,)
    )
    scam_count = cur.fetchone()['c']

    cur.execute("SELECT COUNT(*) as c FROM scans WHERE user_id=%s AND result IN ('SAFE','VERIFIED')", (uid,))
    safe_count = cur.fetchone()['c']

    cur.execute("SELECT scan_type, COUNT(*) as c FROM scans WHERE user_id=%s GROUP BY scan_type", (uid,))
    by_type = cur.fetchall()

    cur.execute("SELECT * FROM scans WHERE user_id=%s ORDER BY timestamp DESC LIMIT 5", (uid,))
    recent = cur.fetchall()

    cur.execute("SELECT COUNT(*) as c FROM scans WHERE user_id=%s AND DATE(timestamp)=CURDATE()", (uid,))
    today_count = cur.fetchone()['c']

    cur.execute(
        "SELECT DATE(timestamp) as day, COUNT(*) as c FROM scans "
        "WHERE user_id=%s AND timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY) "
        "GROUP BY DATE(timestamp) ORDER BY day",
        (uid,)
    )
    weekly = cur.fetchall()
    cur.close()
    return total, scam_count, safe_count, by_type, recent, today_count, weekly

# ── Public Routes ──────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        cur = mysql.connection.cursor()
        cur.execute("SELECT id FROM users WHERE email=%s OR username=%s", (email, username))
        if cur.fetchone():
            flash('Username or email already exists.', 'danger')
            cur.close()
            return redirect(url_for('register'))
        cur.execute(
            "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
            (username, email, generate_password_hash(password))
        )
        mysql.connection.commit()
        cur.close()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip()
        password = request.form['password']
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cur.fetchone()
        cur.close()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
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
    total, scam_count, safe_count, by_type, recent, today_count, weekly = get_dashboard_stats(uid)
    return render_template('dashboard.html',
                           total=total, scam_count=scam_count, safe_count=safe_count,
                           by_type=by_type, recent=recent,
                           today_count=today_count, weekly=weekly)

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

@app.route('/report-fraud')
@login_required
def report_fraud():
    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT fr.*, u.username FROM fraud_reports fr "
        "JOIN users u ON fr.user_id=u.id "
        "ORDER BY fr.timestamp DESC LIMIT 50"
    )
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

# ── Scan API Endpoints ─────────────────────────────────────────────────────────
@app.route('/api/scan/job', methods=['POST'])
@login_required
def api_scan_job():
    data = request.get_json()
    res = ai_engine.detect_fake_job(
        data.get('title', ''), data.get('company', ''),
        data.get('salary', ''), data.get('description', '')
    )
    input_text = f"Job: {data.get('title')} at {data.get('company')}"
    save_scan(session['user_id'], 'Fake Job', input_text, res['result'], res['trust_score'], res['explanation'])
    return jsonify(res)

@app.route('/api/scan/message', methods=['POST'])
@login_required
def api_scan_message():
    data = request.get_json()
    res = ai_engine.detect_scam_message(data.get('message', ''))
    save_scan(session['user_id'], 'Scam Message', data.get('message', '')[:200],
              res['result'], res['trust_score'], res['explanation'])
    return jsonify(res)

@app.route('/api/scan/verify', methods=['POST'])
@login_required
def api_verify():
    data = request.get_json(force=True) or {}
    query = data.get('query', '').strip()
    res = verifier.verify_platform(query)
    save_scan(session['user_id'], 'RBI/SEBI Check', query,
              res['result'], res['trust_score'], res['explanation'])
    return jsonify(res)

@app.route('/api/scan/loan', methods=['POST'])
@login_required
def api_scan_loan():
    data = request.get_json()
    res = ai_engine.detect_loan_app(
        data.get('app_name', ''), data.get('permissions', ''), data.get('interest_rate', 0)
    )
    save_scan(session['user_id'], 'Loan App', data.get('app_name', ''),
              res['result'], res['trust_score'], res['explanation'])
    return jsonify(res)

@app.route('/api/scan/website', methods=['POST'])
@login_required
def api_scan_website():
    data = request.get_json()
    url = data.get('url', '')
    res = ai_engine.scan_website(url)
    save_scan(session['user_id'], 'Website Scan', url, res['result'], res['trust_score'], res['explanation'])
    return jsonify(res)

# ── Chatbot API ────────────────────────────────────────────────────────────────
@app.route('/api/chatbot', methods=['POST'])
@login_required
def api_chatbot():
    try:
        data = request.get_json(force=True) or {}
        user_msg = data.get('message', '').strip()
        if not user_msg:
            return jsonify({"response": "Please type a message."})

        bot_response = ai_engine.get_chatbot_response(user_msg)

        # Log to DB — silently skip if table doesn't exist yet
        try:
            cur = mysql.connection.cursor()
            cur.execute(
                "INSERT INTO chatbot_logs (user_id, user_message, bot_response) VALUES (%s, %s, %s)",
                (session['user_id'], user_msg[:500], bot_response[:2000])
            )
            mysql.connection.commit()
            cur.close()
        except Exception:
            pass

        return jsonify({"response": bot_response})
    except Exception as e:
        return jsonify({"response": "Sorry, I encountered an error. Please try again."}), 200

# ── Fraud Report API ───────────────────────────────────────────────────────────
@app.route('/api/report', methods=['POST'])
@login_required
def api_report():
    data = request.get_json()
    report_type = data.get('report_type', 'other')
    target = data.get('target', '').strip()
    description = data.get('description', '').strip()

    if not target or not description:
        return jsonify({"error": "Target and description are required."}), 400

    cur = mysql.connection.cursor()
    cur.execute(
        "INSERT INTO fraud_reports (user_id, report_type, target, description) VALUES (%s, %s, %s, %s)",
        (session['user_id'], report_type, target[:500], description[:2000])
    )
    mysql.connection.commit()
    cur.close()

    return jsonify({"success": True, "message": "Report submitted successfully. Thank you for helping the community!"})

# ── Analytics API ──────────────────────────────────────────────────────────────
@app.route('/api/analytics')
@login_required
def api_analytics():
    uid = session['user_id']
    total, scam_count, safe_count, by_type, recent, today_count, weekly = get_dashboard_stats(uid)
    return jsonify({
        "total": total,
        "scam_count": scam_count,
        "safe_count": safe_count,
        "today_count": today_count,
        "by_type": by_type,
        "weekly": [{"day": str(r['day']), "c": r['c']} for r in weekly]
    })

if __name__ == '__main__':
    app.run(debug=os.environ.get('FLASK_DEBUG', 'False').lower() == 'true')
