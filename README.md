# ScamShield India

A community-driven UPI/SMS scam-checking web app. Users can assess a suspicious
message or identifier, submit a community report, and browse aggregate trends.
Reports enter the indicator database only after moderator verification.

## What it does

- Analyzes up to 2,000 characters with explicit warning rules and
  moderator-verified community indicators. A trained text classifier can be
  added as a supplementary signal after it passes the documented validation.
- Returns a 0–100 heuristic risk score, a Scam/Suspicious/No clear warning signs
  label, and human-readable reasons. The score is not a calibrated probability.
- Can combine the rules with a locally trained text classifier when a validated
  model artifact is provided. Without one, the app clearly uses rules only.
- Recognizes bare domains as links, includes testable example messages, and
  offers official cyber-fraud response guidance for high-risk results.
- Lets users submit a flagged message to the moderator queue directly from its
  analysis result.
- Accepts reports for SMS messages, URLs, Indian phone numbers, and UPI IDs.
- Provides moderator review and a dashboard of verified report categories.
- Supports email/password and optional Google sign-in. Signed-in users can see
  the reports they submitted from any device; message checks are not saved.
- Shows report status, moderator notes, duplicate-report warnings, and verified
  report trends for selected time ranges.
- Offers English and Hindi scam checks, with explicit limitations and privacy
  details on the transparency page.
- Uses SQLite for local development and PostgreSQL when `DATABASE_URL` is set.

**Important:** Heuristic checks and community reports are informational—not proof
that a message is safe or fraudulent. A message with no detected warning signs
can still be a scam. Verify payments and account messages with your bank or
provider through its official app or contact details. Never share an OTP, UPI
PIN, password, or card details.

## Run locally

Python 3.10 or newer is recommended.

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:FLASK_APP = "wsgi:app"
flask run
```

Open <http://127.0.0.1:5000>. The local SQLite database is created at
`instance/scamshield.sqlite`; missing tables are created automatically when
the app starts.

Configure moderation in a separate PowerShell session before launching:

```powershell
$env:MODERATOR_TOKEN = "use-a-long-random-secret"
$env:SECRET_KEY = "use-another-long-random-secret"
flask run
```

Moderator sign-in is at `/moderator/login`. Keep the moderator token private;
do not commit it to source control.

## Account sign-in

Email/password accounts are available at `/account/register` and
`/account/login`. Users sign in separately on each device; submitted reports
are associated with their account and visible on `/account/reports`. Checks are
not stored. Passwords are stored as salted hashes. Google accounts use Google
sign-in.

Email verification and password recovery require an SMTP service. Configure
`MAIL_SERVER`, `MAIL_PORT` (default `587`), `MAIL_USERNAME`,
`MAIL_PASSWORD`, `MAIL_USE_TLS` (`true` by default), and
`MAIL_DEFAULT_SENDER` as private environment variables. Set `PUBLIC_BASE_URL`
to the canonical HTTPS origin of the deployed app (for example,
`https://scamshield.example`) so account links use the expected host. Without
these settings, email/password accounts remain usable without email
verification and reset links cannot be delivered. Do not use a public or
untrusted SMTP relay.

To enable Google sign-in, create a Google OAuth client and set
`GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`. Add your deployment's
`https://<your-host>/account/google/callback` URL as an authorized redirect URI.
The Google button is hidden until both environment variables are set.

## PostgreSQL and Render deployment

For shared, persistent data across deployed instances, attach a managed
PostgreSQL database and set `DATABASE_URL` to its connection string. Render's
older `postgres://` URL form is normalized automatically to use psycopg 3.
SQLite is intended for local development; its filesystem is not a shared
database for multiple deployed instances.

Set `SECRET_KEY`, `MODERATOR_TOKEN`, `DATABASE_URL`, and `FLASK_ENV=production`
as private deployment environment variables. Production mode requires a
`SECRET_KEY` and enables secure session cookies. Configure Google OAuth
variables as well if Google sign-in is desired.

In Render, use the repository root as the root directory, set the build command
to `pip install -r requirements.txt`, and the start command to `gunicorn wsgi:app`.
The app's requests read and write through the shared database, so report
submissions and moderator decisions are visible on the next page load across
instances and devices. No browser refresh-free/WebSocket updates are used.

The app creates missing tables at startup and applies additive columns needed
by current releases. When deploying to a fresh Render service, link the
PostgreSQL database so its `DATABASE_URL` is available to the web service. The
`flask --app wsgi:app init-db` command remains available for manual
initialization.

## Tests

```powershell
python -m pytest
```

Tests use an in-memory SQLite database and do not modify the local database.

## Optional supervised text model

The private training CSV is not committed to the repository. A trained model
artifact may be committed for deployment, but it contains learned features from
the training data and should only be shared when you are authorized to use that
data. If no model artifact is present, ScamShield uses its rules and
moderator-verified indicators only. Do not use unreviewed user submissions as
scam labels. Obtain consent, redact personal information, and have moderators
verify labels.

Prepare a private UTF-8 CSV with these columns:

```csv
text,label,campaign_id
```

`label` must be `scam` or `legitimate`; `campaign_id` groups messages from the
same scam campaign or legitimate source so related messages do not appear in
both training and holdout data. The training script requires at least 50
distinct examples and 5 campaign groups for each label. It prints
campaign-separated holdout metrics and saves a model only when scam precision
is at least 0.70 and recall at least 0.60. These thresholds are a starting
quality gate, not proof the model is safe for production.

From the repository root, install the declared dependencies and train:

```powershell
python -m pip install -r requirements.txt
python scripts/train_model.py --input data/scam_training.csv
```

The validated artifact is written to
`model_artifacts/scamshield_text_classifier.joblib`. Deploy that artifact with
the application code; never commit the private CSV. Set `SCAMSHIELD_MODEL_PATH`
in Render only if the artifact is stored at a different path. The model can
only raise a result to Suspicious; it cannot mark a message as definitively
fraudulent or lower the existing rule-based score. Model files must come from a
trusted source because loading a joblib file can execute code.
