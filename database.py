import sqlite3
import os
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "instance", "app.db")


def get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS checks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        company_name TEXT,
        company_url TEXT,
        contact_email TEXT,
        job_text TEXT NOT NULL,
        salary_text TEXT,
        ml_probability REAL,
        rule_score REAL,
        company_confidence REAL,
        final_score REAL,
        risk_level TEXT,
        flags_json TEXT,
        notes_json TEXT,
        recs_json TEXT,
        threat_vectors_json TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS favorites (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        check_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(user_id, check_id),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (check_id) REFERENCES checks(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS feedback (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        check_id INTEGER,
        rating INTEGER NOT NULL,
        comment TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
        FOREIGN KEY (check_id) REFERENCES checks(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        key_value TEXT UNIQUE NOT NULL,
        name TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS community_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        company_name TEXT NOT NULL,
        scam_type TEXT NOT NULL,
        contact_info TEXT,
        description TEXT NOT NULL,
        upvotes INTEGER NOT NULL DEFAULT 1,
        status TEXT DEFAULT 'Under Review',
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    );
    CREATE TABLE IF NOT EXISTS community_upvotes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        report_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(user_id, report_id),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (report_id) REFERENCES community_reports(id) ON DELETE CASCADE
    );
    """)
    
    # Gracefully ensure threat_vectors_json column exists if database was already created
    try:
        cur = conn.execute("PRAGMA table_info(checks)")
        cols = [r["name"] for r in cur.fetchall()]
        if "threat_vectors_json" not in cols:
            conn.execute("ALTER TABLE checks ADD COLUMN threat_vectors_json TEXT")
            conn.commit()
    except Exception:
        pass

    # Populate seed community reports if empty
    try:
        cur = conn.execute("SELECT COUNT(*) as c FROM community_reports")
        if cur.fetchone()["c"] == 0:
            sample_reports = [
                ("Apex Global Tech Careers", "Advance Fee / Security Deposit", "hr@apex-tech-careers.xyz / WhatsApp: +91-9876543210", "Posed as a remote data entry firm and demanded Rs 2,500 for training software before releasing the offer letter.", 14, "Verified Scam", now_iso()),
                ("Vertex Soft Info Solutions", "Identity Phishing / Bank Details", "recruiter@vertex-india.site / Telegram: @vertex_hr", "Sent fake offer letter requesting bank statement with balance and Aadhaar OTP verification.", 9, "Verified Scam", now_iso()),
                ("FastTrack Placement Corp", "Guaranteed Placement Scam", "contact@fasttrack-hire.work", "Guaranteed 100% placement with Microsoft/Google for Rs 15,000 upfront consultation charge.", 19, "Verified Scam", now_iso()),
            ]
            conn.executemany("""
                INSERT INTO community_reports(company_name, scam_type, contact_info, description, upvotes, status, created_at)
                VALUES(?,?,?,?,?,?,?)
            """, sample_reports)
            conn.commit()
    except Exception:
        pass

    conn.commit()
    conn.close()


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
