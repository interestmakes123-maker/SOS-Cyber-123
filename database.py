import sqlite3

DATABASE = "scamshield.db"


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS scam_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scam_type TEXT NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Add AI analysis columns to existing reports
    ai_risk_level = "ALTER TABLE scam_reports ADD COLUMN ai_risk_level TEXT"
    ai_probability = "ALTER TABLE scam_reports ADD COLUMN ai_probability TEXT"
    ai_scam_type = "ALTER TABLE scam_reports ADD COLUMN ai_scam_type TEXT"
    ai_warning_signs = "ALTER TABLE scam_reports ADD COLUMN ai_warning_signs TEXT"
    ai_recommended_action = "ALTER TABLE scam_reports ADD COLUMN ai_recommended_action TEXT"

    for query in [
        ai_risk_level,
        ai_probability,
        ai_scam_type,
        ai_warning_signs,
        ai_recommended_action
    ]:
        try:
            conn.execute(query)
        except sqlite3.OperationalError:
            pass
    conn.execute("""
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id INTEGER,
            scammer_phone TEXT,
            transaction_id TEXT,
            amount_lost REAL,
            incident_details TEXT,
            file_name TEXT,
            file_path TEXT,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    try:
      conn.execute(
        "ALTER TABLE evidence ADD COLUMN report_id INTEGER"
    )
    except sqlite3.OperationalError:
      pass
    conn.execute("""
    CREATE TABLE IF NOT EXISTS incident_timeline (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id INTEGER,
    evidence_id INTEGER,
    event TEXT NOT NULL,
    event_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (report_id) REFERENCES scam_reports(id),
    FOREIGN KEY (evidence_id) REFERENCES evidence(id)

    )
""")
    try:
     conn.execute(
        "ALTER TABLE incident_timeline ADD COLUMN report_id INTEGER"
    )
    except sqlite3.OperationalError:
     pass
    conn.commit()
    conn.close()