-- TrustLens AI – Full Database Schema
CREATE DATABASE IF NOT EXISTS trustlens_ai;
USE trustlens_ai;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(80) NOT NULL UNIQUE,
    email VARCHAR(120) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    scan_type VARCHAR(50) NOT NULL,
    input_text TEXT NOT NULL,
    result VARCHAR(50) NOT NULL,
    trust_score INT NOT NULL,
    explanation TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS verified_companies (
    id INT AUTO_INCREMENT PRIMARY KEY,
    company_name VARCHAR(100) NOT NULL,
    app_name VARCHAR(100),
    website VARCHAR(200),
    type ENUM('bank','broker','payment','insurance','nbfc') NOT NULL,
    regulator ENUM('RBI','SEBI','IRDAI','Both') NOT NULL,
    registration_status ENUM('verified','suspended','blacklisted') DEFAULT 'verified'
);

CREATE TABLE IF NOT EXISTS fraud_reports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    report_type ENUM('website','job','app','message','other') NOT NULL,
    target VARCHAR(500) NOT NULL,
    description TEXT NOT NULL,
    evidence TEXT,
    status ENUM('pending','reviewed','confirmed','dismissed') DEFAULT 'pending',
    votes INT DEFAULT 0,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS chatbot_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    user_message TEXT NOT NULL,
    bot_response TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT IGNORE INTO verified_companies (company_name, app_name, website, type, regulator) VALUES
('State Bank of India', 'YONO SBI', 'sbi.co.in', 'bank', 'RBI'),
('HDFC Bank', 'HDFC Bank MobileBanking', 'hdfcbank.com', 'bank', 'RBI'),
('ICICI Bank', 'iMobile Pay', 'icicibank.com', 'bank', 'RBI'),
('Axis Bank', 'Axis Mobile', 'axisbank.com', 'bank', 'RBI'),
('Kotak Mahindra Bank', 'Kotak Mobile Banking', 'kotak.com', 'bank', 'RBI'),
('Paytm Payments Bank', 'Paytm', 'paytm.com', 'payment', 'RBI'),
('PhonePe', 'PhonePe', 'phonepe.com', 'payment', 'RBI'),
('Google Pay', 'GPay', 'pay.google.com', 'payment', 'RBI'),
('Zerodha', 'Kite', 'zerodha.com', 'broker', 'SEBI'),
('Groww', 'Groww', 'groww.in', 'broker', 'SEBI'),
('Upstox', 'Upstox', 'upstox.com', 'broker', 'SEBI'),
('Angel One', 'Angel One', 'angelone.in', 'broker', 'SEBI'),
('5paisa', '5paisa', '5paisa.com', 'broker', 'SEBI'),
('HDFC Securities', 'HDFC Securities', 'hdfcsec.com', 'broker', 'Both'),
('ICICI Direct', 'ICICIdirect', 'icicidirect.com', 'broker', 'Both'),
('Bajaj Finance', 'Bajaj Finserv', 'bajajfinserv.in', 'nbfc', 'RBI'),
('Tata Capital', 'Tata Capital', 'tatacapital.com', 'nbfc', 'RBI'),
('Muthoot Finance', 'iMuthoot', 'muthootfinance.com', 'nbfc', 'RBI');
