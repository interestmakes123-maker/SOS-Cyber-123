# ScamShield

ScamShield is a Flask-based cyber safety application for reporting scam incidents, analyzing suspicious messages, storing evidence, and tracking an incident timeline. It is designed as a first-response helper for phishing, OTP, money transfer, online shopping, job, and fake call scams.

## Features

- Scam type selection and report creation
- Rule-based suspicious message analyzer
- Emergency action plans by scam type
- Evidence upload vault for screenshots, documents, and notes
- Incident timeline for reports, analysis, emergency response, and evidence uploads
- Learning, profile, MSME, and skill assessment pages
- SQLite storage with automatic table creation

## Tech Stack

- Python
- Flask
- SQLite
- HTML, CSS, and JavaScript

## Project Structure

```text
ScamShield/
|-- app.py                  # Flask application and routes
|-- analyzer.py             # Rule-based scam message analyzer
|-- database.py             # SQLite connection and schema setup
|-- scamshield.db           # Local SQLite database
|-- templates/              # Flask HTML templates
|-- uploads/                # Uploaded evidence files
`-- README.md
```

## Setup

1. Create and activate a virtual environment:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

2. Install dependencies:

```powershell
pip install flask werkzeug
```

3. Run the application:

```powershell
python app.py
```

4. Open the app in your browser:

```text
http://127.0.0.1:5000
```

## Pages

- `/` - Home page
- `/analyzer` - AI scam message analyzer
- `/evidence` - Evidence upload vault
- `/timeline` - Incident timeline
- `/report` - Report page
- `/skills` - Skill assessment
- `/skill-result` - Skill assessment result
- `/learning` - Learning resources
- `/profile` - User profile
- `/msme` - MSME page

## API Endpoints

### Test Backend

```http
GET /api/test
```

Checks whether the backend is running.

### Create Scam Report

```http
POST /api/report
Content-Type: application/json
```

Example body:

```json
{
  "scam_type": "Phishing Scam",
  "description": "Suspicious account verification message"
}
```

### Get Emergency Plan

```http
GET /api/emergency/<scam_type>
```

Returns the risk level and recommended emergency action plan for a scam type.

### Analyze Message

```http
POST /api/analyze
Content-Type: application/json
```

Example body:

```json
{
  "message": "Your account will be blocked. Verify your password using this link immediately.",
  "report_id": 1
}
```

Returns:

- Risk level
- Scam probability score
- Detected scam type
- Warning signs
- Recommended action

### Record Emergency Response

```http
POST /api/emergency-response/<report_id>
```

Adds an emergency response event to the incident timeline.

### Upload Evidence

```http
POST /api/evidence
Content-Type: multipart/form-data
```

Supported file types:

- PNG
- JPG / JPEG
- PDF
- TXT
- DOC / DOCX

The uploaded file must be associated with a valid `report_id`.

### Get Timeline

```http
GET /api/timeline/<report_id>
```

Returns the report details, uploaded evidence records, and timeline events.

## Database

The application uses `scamshield.db`, a local SQLite database. Tables are created automatically when the app starts:

- `scam_reports`
- `evidence`
- `incident_timeline`

## Notes

- Uploaded files are stored in the `uploads/` directory.
- The scam analyzer is rule-based and uses keyword and pattern matching from `analyzer.py`.
- This project is intended to support awareness and early response. Users should still report cybercrime through official authorities when needed.
