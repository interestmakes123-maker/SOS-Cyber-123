from flask import Flask, request, render_template
import os
from werkzeug.utils import secure_filename
from database import init_db, get_db_connection
from analyzer import analyze_message

app = Flask(__name__)

# Initialize database
init_db()


@app.route("/")
def home():
    return render_template("index.html")
@app.route("/analyzer")
def analyzer():
    return render_template("analyzer.html")
@app.route("/timeline")
def timeline():
    return render_template("timeline.html")
@app.route("/evidence")
def evidence():
    return render_template("evidence.html")
@app.route("/report")
def report_page():
    return render_template("report.html")


@app.route("/api/test")
def test():
    return {
        "message": "Backend and database are connected successfully!"
    }


# API to submit a scam report
@app.route("/api/report", methods=["POST"])
def report_scam():

    data = request.get_json()

    scam_type = data.get("scam_type")
    description = data.get("description")

    if not scam_type:
        return {
            "error": "Scam type is required"
        }, 400

    conn = get_db_connection()

    cursor = conn.execute(
        """
        INSERT INTO scam_reports
        (scam_type, description)
        VALUES (?, ?)
        """,
        (scam_type, description)
    )

    report_id = cursor.lastrowid

    # Create timeline event for the scam report
    conn.execute(
        """
        INSERT INTO incident_timeline
        (report_id, event)
        VALUES (?, ?)
        """,
        (
            report_id,
            "Scam reported"
        )
    )

    conn.commit()
    conn.close()

    return {
        "message": "Scam report submitted successfully!",
        "report_id": report_id
    }

# Emergency Action Plan API
@app.route("/api/emergency/<scam_type>")
def emergency_plan(scam_type):

    plans = {
        "Phishing Scam": [
            "Do not click any suspicious links.",
            "Change your account password.",
            "Enable two-factor authentication.",
            "Report the suspicious message."
        ],

        "Money Transfer Scam": [
            "Contact your bank immediately.",
            "Report the fraudulent transaction.",
            "Block the affected bank account or UPI ID.",
            "Do not share your UPI PIN with anyone."
        ],

        "OTP Scam": [
            "Do not share OTPs with anyone.",
            "Contact your bank immediately if money was lost.",
            "Change your banking password.",
            "Report the incident."
        ],

        "Online Shopping Scam": [
            "Do not make any further payments.",
            "Contact your bank or payment provider.",
            "Save screenshots and payment details.",
            "Report the fraudulent seller."
        ],

        "Job Scam": [
            "Do not pay any further fees.",
            "Save the job advertisement and messages.",
            "Do not share sensitive personal information.",
            "Report the fraudulent job offer."
        ],

        "Fake Call Scam": [
            "Do not share OTPs, PINs, or passwords.",
            "End the suspicious call.",
            "Contact your bank if financial information was shared.",
            "Report the scam."
        ]
    }
    risk_levels = {
    "Phishing Scam": "HIGH",
    "Money Transfer Scam": "HIGH",
    "OTP Scam": "HIGH",
    "Online Shopping Scam": "MEDIUM",
    "Job Scam": "MEDIUM",
    "Fake Call Scam": "MEDIUM"
}
    risk_level = risk_levels.get(scam_type, "LOW")

    plan = plans.get(scam_type)

    if not plan:
     return {
           "error": "Scam type not found"
    }, 404
    return {
    "scam_type": scam_type,
    "risk_level": risk_level,
    "action_plan": plan
}
@app.route("/api/analyze", methods=["POST"])
def analyze_scam():

    data = request.get_json()

    message = data.get("message")
    report_id = data.get("report_id")

    if not message:
        return {
            "error": "Message is required"
        }, 400

    result = analyze_message(message)
    # Save AI analysis result to the report
    if report_id:

        conn = get_db_connection()

        conn.execute(
            """
            UPDATE scam_reports
            SET
                ai_risk_level = ?,
                ai_probability = ?,
                ai_scam_type = ?,
                ai_warning_signs = ?,
                ai_recommended_action = ?
            WHERE id = ?
            """,
            (
                result.get("risk_level"),
                result.get("scam_probability"),
                result.get("scam_type"),
                ", ".join(result.get("warning_signs", [])),
                result.get("recommended_action"),
                report_id
            )
        )

        conn.commit()
        conn.close()

    # Record AI analysis in incident timeline
    if report_id:

        conn = get_db_connection()

        conn.execute(
            """
            INSERT INTO incident_timeline
            (report_id, event)
            VALUES (?, ?)
            """,
            (
                report_id,
                "AI analysis completed"
            )
        )

        conn.commit()
        conn.close()

    return result

@app.route("/api/emergency-response/<int:report_id>", methods=["POST"])
def emergency_response(report_id):

    conn = get_db_connection()

    report = conn.execute(
        "SELECT id FROM scam_reports WHERE id = ?",
        (report_id,)
    ).fetchone()

    if not report:
        conn.close()
        return {
            "error": "Report not found"
        }, 404

    conn.execute(
        """
        INSERT INTO incident_timeline
        (report_id, event)
        VALUES (?, ?)
        """,
        (
            report_id,
            "Emergency response initiated"
        )
    )

    conn.commit()
    conn.close()

    return {
        "message": "Emergency response recorded successfully!"
    }
# Evidence upload API
@app.route("/api/evidence", methods=["POST"])
def upload_evidence():

    file = request.files.get("file")
    if file and file.content_length and file.content_length > 10 * 1024 * 1024:
     return {
        "error": "File size must be less than 10 MB"
    }, 400

    if not file:
        return {
            "error": "Evidence file is required"
        }, 400

    report_id = request.form.get("report_id")

    if not report_id:
      return {
        "error": "Report ID is required"
    }, 400

    try:
      report_id = int(report_id)
    except ValueError:
     return {
        "error": "Invalid report ID"
    }, 400
    conn = get_db_connection()

    report = conn.execute(
    "SELECT id FROM scam_reports WHERE id = ?",
    (report_id,)
).fetchone()

    conn.close()

    if not report:
      return {
        "error": "Report not found"
    }, 404 
    scammer_phone = request.form.get("scammer_phone", "").strip()
    transaction_id = request.form.get("transaction_id", "").strip()
    amount_lost = request.form.get("amount_lost", "").strip()

    if amount_lost:
      try:
        amount_lost = float(amount_lost)
      except ValueError:
        return {
            "error": "Amount lost must be a valid number"
        }, 400
    else:
       amount_lost = None
    incident_details = request.form.get("incident_details", "").strip()

    filename = secure_filename(file.filename)

    if not filename:
        return {
            "error": "Invalid file name"
        }, 400

    allowed_extensions = {
        "png",
        "jpg",
        "jpeg",
        "pdf",
        "txt",
        "doc",
        "docx"
    }

    extension = filename.rsplit(".", 1)[-1].lower()

    if extension not in allowed_extensions:
        return {
            "error": "Unsupported file type"
        }, 400

    import uuid

    unique_filename = (
        uuid.uuid4().hex + "_" + filename
    )

    upload_folder = "uploads"

    os.makedirs(upload_folder, exist_ok=True)

    file_path = os.path.join(
        upload_folder,
        unique_filename
    )

    file.save(file_path)

    conn = get_db_connection()

    cursor = conn.execute(
        """
        INSERT INTO evidence
        (
            report_id,
            scammer_phone,
            transaction_id,
            amount_lost,
            incident_details,
            file_name,
            file_path
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            report_id,
            scammer_phone,
            transaction_id,
            amount_lost,
            incident_details,
            filename,
            file_path
        )
    )

    evidence_id = cursor.lastrowid

    conn.execute(
        """
        INSERT INTO incident_timeline
        (
            report_id,
            evidence_id,
            event
        )
        VALUES (?, ?, ?)
        """,
        (
            report_id,
            evidence_id,
            "Evidence uploaded"
        )
    )

    conn.commit()
    conn.close()

    return {
        "message": "Evidence uploaded successfully!",
        "evidence_id": evidence_id,
        "file_name": filename,
        "timeline_url": (
            "/timeline?report_id="
            + str(report_id)
        )
    }
@app.route("/api/timeline/<int:report_id>")
def get_timeline(report_id):

    conn = get_db_connection()

    report = conn.execute(
    """
    SELECT
        id,
        scam_type,
        description,
        created_at,
        ai_risk_level,
        ai_probability,
        ai_scam_type,
        ai_warning_signs,
        ai_recommended_action
    FROM scam_reports
    WHERE id = ?
    """,
    (report_id,)
).fetchone()
    evidence = conn.execute(
        """
        SELECT
            id,
            scammer_phone,
            transaction_id,
            amount_lost,
            incident_details,
            file_name,
            uploaded_at
        FROM evidence
        WHERE report_id = ?
        ORDER BY uploaded_at ASC
        """,
        (report_id,)
    ).fetchall()

    timeline = conn.execute(
        """
        SELECT event, event_time
        FROM incident_timeline
        WHERE report_id = ?
        ORDER BY event_time ASC
        """,
        (report_id,)
    ).fetchall()

    conn.close()

    return {
        "report": dict(report) if report else None,
        "evidence": [dict(item) for item in evidence],
        "timeline": [dict(item) for item in timeline]
    }
@app.route('/skills')
def skills():
    return render_template('skill_assessment.html')
@app.route('/skill-result')
def skill_result():
    return render_template('skill_result.html')
@app.route('/learning')
def learning():
    return render_template('learning.html')
@app.route('/profile')
def profile():
    return render_template('profile.html')
@app.route('/msme')
def msme():
    return render_template('msme.html')

if __name__ == "__main__":
    app.run(debug=True)
