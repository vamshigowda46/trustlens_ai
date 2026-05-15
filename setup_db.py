import MySQLdb
import sys

try:
    conn = MySQLdb.connect(
        host='viaduct.proxy.rlwy.net',
        port=19006,
        user='root',
        passwd='DaYkyHBBuRdsiayEgVzWICiszPsgZsvI',
        db='railway'
    )
    conn.autocommit(True)
    cur = conn.cursor()

    cur.execute('SELECT DATABASE()')
    sys.stdout.write('Connected to DB: ' + str(cur.fetchone()) + '\n')
    sys.stdout.flush()

    statements = [
        """CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(80) NOT NULL UNIQUE,
            email VARCHAR(120) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""",
        """CREATE TABLE IF NOT EXISTS scans (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            scan_type VARCHAR(50) NOT NULL,
            input_text TEXT NOT NULL,
            result VARCHAR(50) NOT NULL,
            trust_score INT NOT NULL,
            explanation TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )""",
        """CREATE TABLE IF NOT EXISTS verified_companies (
            id INT AUTO_INCREMENT PRIMARY KEY,
            company_name VARCHAR(100) NOT NULL,
            app_name VARCHAR(100),
            website VARCHAR(200),
            type ENUM('bank','broker','payment','insurance','nbfc') NOT NULL,
            regulator ENUM('RBI','SEBI','IRDAI','Both') NOT NULL,
            registration_status ENUM('verified','suspended','blacklisted') DEFAULT 'verified'
        )""",
        """CREATE TABLE IF NOT EXISTS fraud_reports (
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
        )""",
        """CREATE TABLE IF NOT EXISTS chatbot_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT,
            user_message TEXT NOT NULL,
            bot_response TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""",
        """CREATE TABLE IF NOT EXISTS chat_conversations (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            title VARCHAR(200) NOT NULL DEFAULT 'New chat',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            KEY idx_chat_user_updated (user_id, updated_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
        """CREATE TABLE IF NOT EXISTS chat_messages (
            id INT AUTO_INCREMENT PRIMARY KEY,
            conversation_id INT NOT NULL,
            role ENUM('user','assistant','system') NOT NULL,
            content MEDIUMTEXT NOT NULL,
            meta TEXT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            KEY idx_chat_msg_conv (conversation_id, id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    ]

    for sql in statements:
        cur.execute(sql)
        sys.stdout.write('OK: ' + sql.strip().split('\n')[0] + '\n')
        sys.stdout.flush()

    cur.execute('SHOW TABLES')
    sys.stdout.write('Final tables: ' + str([r[0] for r in cur.fetchall()]) + '\n')
    sys.stdout.flush()
    conn.close()

except Exception as e:
    sys.stderr.write('ERROR: ' + str(e) + '\n')
    sys.stderr.flush()
