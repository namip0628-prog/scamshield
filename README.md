# ScamShield India

A community-driven UPI/SMS scam-checking web app. Users can assess a suspicious
message or identifier, submit a community report, and browse aggregate trends.
Reports enter the indicator database only after moderator verification.

## What it does

- Analyzes up to 2,000 characters using a local TF-IDF/logistic-regression
  starter model, explicit warning rules, and verified community indicators.
- Returns a 0–100 risk score, a Safe/Suspicious/Scam label, and human-readable
  reasons. The score is a screening signal, not a calibrated probability.
- Recognizes bare domains as links, includes testable example messages, and
  offers official cyber-fraud response guidance for high-risk results.
- Lets users submit a flagged message to the moderator queue directly from its
  analysis result.
- Accepts reports for SMS messages, URLs, Indian phone numbers, and UPI IDs.
- Provides moderator review and a dashboard of verified report categories.
- Uses SQLite for local development and PostgreSQL when `DATABASE_URL` is set.

**Important:** The included training examples are a small illustrative starter
sample, not a representative or independently validated dataset. Treat results
as informational—not proof that a message is safe or fraudulent. Verify
payments and account messages with your bank or provider through its official
app or contact details. Never share an OTP, UPI PIN, password, or card details.

## Run locally

Python 3.10 or newer is recommended.

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:FLASK_APP = "wsgi:app"
flask init-db
flask run
```

Open <http://127.0.0.1:5000>. The local SQLite database is created at
`instance/scamshield.sqlite`.

Configure moderation in a separate PowerShell session before launching:

```powershell
$env:MODERATOR_TOKEN = "use-a-long-random-secret"
$env:SECRET_KEY = "use-another-long-random-secret"
flask run
```

Moderator sign-in is at `/moderator/login`. Keep the moderator token private;
do not commit it to source control.

## PostgreSQL and deployment

Set `DATABASE_URL` to the PostgreSQL connection string. Render's older
`postgres://` URL form is normalized automatically to use psycopg 3. Set both
`SECRET_KEY` and `MODERATOR_TOKEN` as private deployment environment variables.
Set `FLASK_ENV=production` so session cookies use HTTPS and the app refuses to
start without a secret key.

Install with `pip install -r requirements.txt`, initialize tables once with
`flask --app wsgi:app init-db`, then start with `gunicorn wsgi:app`. The included
`Procfile` configures the Gunicorn start command.

For a Render web service, use the repository root as the root directory, set the
build command to `pip install -r requirements.txt`, and the start command to
`gunicorn wsgi:app`. Initialize the PostgreSQL schema with
`flask --app wsgi:app init-db` after the database and environment variables are
available and before accepting traffic.

## Tests

```powershell
python -m pytest
```

Tests use an in-memory SQLite database and do not modify the local database.
