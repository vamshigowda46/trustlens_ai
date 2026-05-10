# TrustLens AI – Setup Guide

## Folder Structure

```
trustlens_ai/
├── app.py                  # Flask application & all routes
├── ai_engine.py            # NLP models, TF-IDF, fraud detection logic
├── requirements.txt        # Python dependencies
├── schema.sql              # MySQL database schema + seed data
├── static/
│   ├── css/
│   │   └── style.css       # Full dark cybersecurity theme
│   └── js/
│       └── main.js         # AJAX, trust score animation, result rendering
└── templates/
    ├── base.html           # Base layout (Bootstrap, Chart.js imports)
    ├── sidebar.html        # Reusable sidebar navigation
    ├── result_panel.html   # Reusable scan result panel
    ├── index.html          # Landing page
    ├── login.html          # Login page
    ├── register.html       # Register page
    ├── dashboard.html      # Analytics dashboard with Chart.js
    ├── fake_job.html       # Fake job detector
    ├── scam_message.html   # Scam message detector
    ├── rbi_sebi.html       # RBI/SEBI verification
    ├── loan_app.html       # Loan app detector
    ├── website_scanner.html# Website/phishing scanner
    └── history.html        # Scan history with filters
```

---

## Step 1 – Install Python Requirements

```bash
cd trustlens_ai
pip install -r requirements.txt
```

---

## Step 2 – MySQL Database Setup

1. Open MySQL Workbench or run MySQL in terminal
2. Run the schema file:

```bash
mysql -u root -p < schema.sql
```

Or paste the contents of `schema.sql` into MySQL Workbench and execute.

3. Update your MySQL password in `app.py` (line 14):

```python
app.config['MYSQL_PASSWORD'] = 'your_mysql_password'
```

---

## Step 3 – Run the Flask Server

```bash
python app.py
```

Open your browser at: **http://localhost:5000**

---

## Step 4 – Test All Modules

### Register & Login
- Go to http://localhost:5000/register
- Create an account, then login

### Fake Job Detector
- Go to /fake-job
- Click "⚠ Fake Job Sample" → Analyze → Should return FAKE with low trust score
- Click "✓ Real Job Sample" → Should return SAFE with high trust score

### Scam Message Detector
- Go to /scam-message
- Click "⚠ Lottery Scam Sample" → Should return SCAM
- Click "✓ Safe Message Sample" → Should return SAFE

### RBI/SEBI Verification
- Go to /rbi-sebi
- Click "Zerodha" chip → Should return VERIFIED (SEBI)
- Type "QuickLoan123" → Should return NOT FOUND

### Loan App Detector
- Go to /loan-app
- Click "⚠ Scam App Sample" → Should return FRAUDULENT
- Click "✓ Legit App Sample" → Should return SAFE

### Website Scanner
- Go to /website-scanner
- Click the dangerous URL sample → Should return DANGEROUS
- Click the safe URL sample → Should return SAFE

### Dashboard & History
- Go to /dashboard → Charts update automatically after scans
- Go to /history → All scans listed with filters

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `ModuleNotFoundError` | Run `pip install -r requirements.txt` |
| MySQL connection error | Check password in `app.py` line 14 |
| `trustlens_ai` DB not found | Run `schema.sql` in MySQL |
| Port 5000 in use | Run `python app.py` with `app.run(port=5001)` |
