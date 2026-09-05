import sqlite3

DB_NAME = "scans.db"


def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            status TEXT NOT NULL,
            score INTEGER NOT NULL,
            ml_probability REAL,
            vt_malicious INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


def save_scan(
    url,
    status,
    score,
    ml_probability,
    vt_malicious
):
    conn = get_connection()

    conn.execute("""
        INSERT INTO scans (
            url,
            status,
            score,
            ml_probability,
            vt_malicious
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        url,
        status,
        score,
        ml_probability,
        vt_malicious
    ))

    conn.commit()
    conn.close()


def get_recent_scans(limit=20):
    conn = get_connection()

    rows = conn.execute("""
        SELECT *
        FROM scans
        ORDER BY id DESC
        LIMIT ?
    """, (limit,)).fetchall()

    conn.close()

    return rows


def get_stats():
    conn = get_connection()

    total = conn.execute(
        "SELECT COUNT(*) FROM scans"
    ).fetchone()[0]

    safe = conn.execute("""
        SELECT COUNT(*)
        FROM scans
        WHERE status IN ('Likely Safe', 'Low Risk')
    """).fetchone()[0]

    suspicious = conn.execute("""
        SELECT COUNT(*)
        FROM scans
        WHERE status = 'Suspicious'
    """).fetchone()[0]

    phishing = conn.execute("""
        SELECT COUNT(*)
        FROM scans
        WHERE status = 'Likely Phishing'
    """).fetchone()[0]

    conn.close()

    return {
        "total": total,
        "safe": safe,
        "suspicious": suspicious,
        "phishing": phishing
    }