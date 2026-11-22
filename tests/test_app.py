from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, inspect, text

from scamshield import create_app
from scamshield.extensions import db
from scamshield.models import Indicator, ScamReport, User


@pytest.fixture
def app():
    app = create_app(
        {
            "TESTING": True,
            "WTF_CSRF_ENABLED": False,
            "SECRET_KEY": "test-key",
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "MODERATOR_TOKEN": "test-moderator-token",
        }
    )
    with app.app_context():
        db.create_all()
    yield app
    with app.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def test_home_page_renders(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"Check for scams" in response.data


def test_analyzer_rejects_empty_or_oversized_text(client):
    assert client.post("/", data={"text": " "}).status_code == 200
    response = client.post("/", data={"text": "x" * 2001})
    assert b"2,000 characters" in response.data


def test_analyzer_returns_reasons_for_scam_message(client):
    response = client.post(
        "/",
        data={"text": "URGENT: Your bank account will be blocked today. Share your OTP now."},
    )
    assert response.status_code == 200
    assert b"Scam" in response.data
    assert b"Never share these with anyone" in response.data


def test_analyzer_flags_secret_requests_but_not_safety_advice(client):
    warning = client.post(
        "/",
        data={"text": "Send your one-time password to the agent to reverse the payment."},
    )
    assert b"asks for a secret" in warning.data
    assert b"Suspicious" in warning.data

    advice = client.post(
        "/",
        data={"text": "Never share your OTP or UPI PIN with anyone."},
    )
    assert b"No clear warning signs" in advice.data
    assert b"asks for a secret" not in advice.data


def test_analyzer_does_not_flag_benign_urgency_alone(client):
    response = client.post("/", data={"text": "Your appointment is today at 10 am."})
    assert b"No clear warning signs" in response.data
    assert b"pressure you to act" not in response.data


def test_bare_url_gets_link_warning_and_report_match(app, client):
    with app.app_context():
        db.session.add(Indicator(kind="url", value="scam.example/path"))
        db.session.commit()
    response = client.post("/", data={"text": "Please visit scam.example/path"})
    assert response.status_code == 200
    assert b"community-verified report" in response.data
    assert b"Send this message for review" in response.data


def test_standalone_url_is_reported_as_url(client, app):
    response = client.post("/", data={"text": "scam.example/path"})
    assert b'name="kind" value="url"' in response.data
    client.post(
        "/report",
        data={
            "kind": "url",
            "value": "scam.example/path",
            "category": "other",
            "details": "",
        },
    )
    with app.app_context():
        assert ScamReport.query.one().kind == "url"


def test_analysis_result_can_be_submitted_for_moderation(client, app):
    response = client.post(
        "/",
        data={"text": "Your bank account will be blocked today. Share your OTP."},
    )
    assert b"Send this message for review" in response.data
    response = client.post(
        "/report",
        data={
            "kind": "sms",
            "value": "Your bank account will be blocked today. Share your OTP.",
            "category": "other",
            "details": "",
        },
    )
    assert response.status_code == 302
    with app.app_context():
        report = ScamReport.query.one()
        assert report.status == "pending"
        assert report.kind == "sms"

def test_pending_report_does_not_affect_analysis(client, app):
    client.post(
        "/report",
        data={
            "kind": "upi_id",
            "value": "fraud@upi",
            "category": "upi_collect",
            "details": "",
        },
    )
    response = client.post("/", data={"text": "fraud@upi"})
    assert b"matches a community-verified report" not in response.data
    with app.app_context():
        assert ScamReport.query.count() == 1
        assert Indicator.query.count() == 0


def test_verified_report_matches_upi_case_insensitively(client, app):
    client.post(
        "/report",
        data={
            "kind": "upi_id",
            "value": "Fraud@UPI",
            "category": "upi_collect",
            "details": "",
        },
    )
    assert client.post(
        "/moderator/login", data={"token": "test-moderator-token"}
    ).status_code == 302
    with app.app_context():
        report = ScamReport.query.one()
        report_id = report.id
    assert client.post(f"/moderator/reports/{report_id}/verify").status_code == 302

    response = client.post("/", data={"text": "fraud@upi"})
    assert b"community-verified report" in response.data
    assert b">100<" in response.data


def test_moderator_routes_require_login_and_csrf_protection(client):
    assert client.get("/moderator").status_code == 403
    assert client.post("/moderator/reports/1/verify").status_code == 403


def test_dashboard_counts_only_verified_reports(client, app):
    with app.app_context():
        db.session.add_all(
            [
                ScamReport(kind="sms", value="pending", category="fake_kyc"),
                ScamReport(
                    kind="sms",
                    value="verified",
                    category="fake_kyc",
                    status="verified",
                ),
            ]
        )
        db.session.commit()
    response = client.get("/dashboard")
    assert b"1" in response.data
    assert b"Fake KYC" in response.data


def test_email_account_can_sign_in_from_another_client_and_see_own_reports(app):
    first_client = app.test_client()
    registration = first_client.post(
        "/account/register",
        data={
            "email": "Person@example.com",
            "password": "a-long-test-password",
            "confirmation": "a-long-test-password",
        },
    )
    assert registration.status_code == 302
    with app.app_context():
        user = User.query.one()
        assert user.email == "person@example.com"
        assert user.password_hash != "a-long-test-password"
        assert user.check_password("a-long-test-password")

    report_response = first_client.post(
        "/report",
        data={
            "kind": "upi_id",
            "value": "review-this@upi",
            "category": "upi_collect",
            "details": "",
        },
    )
    assert report_response.status_code == 302
    assert b"review-this@upi" in first_client.get("/account/reports").data

    second_client = app.test_client()
    login_response = second_client.post(
        "/account/login",
        query_string={"next": "https://example.com"},
        data={"email": "PERSON@example.com", "password": "a-long-test-password"},
    )
    assert login_response.status_code == 302
    assert login_response.headers["Location"].endswith("/account/reports")
    assert b"review-this@upi" in second_client.get("/account/reports").data


def test_account_report_history_is_private_and_login_is_required(client, app):
    assert client.get("/account/reports").status_code == 302
    client.post(
        "/account/register",
        data={
            "email": "first@example.com",
            "password": "a-long-test-password",
            "confirmation": "a-long-test-password",
        },
    )
    client.post(
        "/report",
        data={
            "kind": "phone",
            "value": "9876543210",
            "category": "other",
            "details": "",
        },
    )

    other_client = app.test_client()
    other_client.post(
        "/account/register",
        data={
            "email": "second@example.com",
            "password": "another-long-password",
            "confirmation": "another-long-password",
        },
    )
    assert b"9876543210" not in other_client.get("/account/reports").data


def test_google_sign_in_requires_oauth_configuration(client):
    assert client.get("/account/google").status_code == 503


def test_google_sign_in_does_not_link_an_existing_password_account(
    app, client, monkeypatch
):
    client.post(
        "/account/register",
        data={
            "email": "person@example.com",
            "password": "a-long-test-password",
            "confirmation": "a-long-test-password",
        },
    )

    class GoogleClient:
        def authorize_access_token(self):
            return {"access_token": "test-token"}

        def parse_id_token(self, _token, nonce):
            assert nonce == "test-nonce"
            return {
                "email": "person@example.com",
                "email_verified": True,
                "sub": "google-user-id",
                "name": "Test User",
            }

    monkeypatch.setattr(
        "scamshield.routes.oauth.create_client",
        lambda _name: GoogleClient(),
    )
    with client.session_transaction() as user_session:
        user_session["google_oauth_nonce"] = "test-nonce"
    response = client.get("/account/google/callback")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/account/login")
    with app.app_context():
        user = User.query.one()
        assert user.google_sub is None


def test_google_sign_in_creates_an_account_for_a_verified_email(
    app, client, monkeypatch
):
    class GoogleClient:
        def authorize_access_token(self):
            return {"access_token": "test-token"}

        def parse_id_token(self, _token, nonce):
            assert nonce == "verified-nonce"
            return {
                "email": "google@example.com",
                "email_verified": True,
                "sub": "verified-google-user",
                "name": "Google User",
            }

    monkeypatch.setattr(
        "scamshield.routes.oauth.create_client",
        lambda _name: GoogleClient(),
    )
    with client.session_transaction() as user_session:
        user_session["google_oauth_nonce"] = "verified-nonce"
    response = client.get("/account/google/callback")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/account/reports")
    with app.app_context():
        user = User.query.one()
        assert user.email == "google@example.com"
        assert user.google_sub == "verified-google-user"
        assert user.password_hash is None


def test_registration_rejects_short_passwords(client):
    response = client.post(
        "/account/register",
        data={
            "email": "person@example.com",
            "password": "short",
            "confirmation": "short",
        },
    )
    assert b"12 and 128 characters" in response.data


def test_production_requires_a_shared_database(monkeypatch):
    monkeypatch.setenv("FLASK_ENV", "production")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(RuntimeError, match="DATABASE_URL"):
        create_app({"SECRET_KEY": "test-key"})


def test_hindi_check_returns_translated_reasons(client):
    response = client.post(
        "/",
        data={"text": "तुरंत अपना OTP भेजें", "language": "hi"},
    )
    assert response.status_code == 200
    assert "गोपनीय जानकारी मांगता है".encode() in response.data
    assert "धोखाधड़ी के संकेत".encode() in response.data
    advice = client.post(
        "/",
        data={"text": "अपना OTP किसी को न बताएं", "language": "hi"},
    )
    assert "स्पष्ट चेतावनी नहीं".encode() in advice.data
    assert "गोपनीय जानकारी मांगता है".encode() not in advice.data


def test_about_page_explains_score_and_report_privacy(client):
    response = client.get("/about")
    assert response.status_code == 200
    assert b"not a probability" in response.data
    assert b"Reports you submit are stored" in response.data


def test_duplicate_report_is_flagged_but_still_recorded(client, app):
    data = {
        "kind": "upi_id",
        "value": "Fraud@UPI",
        "category": "upi_collect",
        "details": "",
    }
    client.post("/report", data=data)
    response = client.post(
        "/report",
        data={**data, "value": "fraud@upi"},
        follow_redirects=True,
    )
    assert b"A similar report is already awaiting review" in response.data
    with app.app_context():
        assert ScamReport.query.count() == 2


def test_dashboard_period_filter_excludes_older_verified_reports(client, app):
    with app.app_context():
        db.session.add_all(
            [
                ScamReport(
                    kind="sms",
                    value="recent",
                    category="upi_collect",
                    status="verified",
                    created_at=datetime.now(timezone.utc),
                    reviewed_at=datetime.now(timezone.utc),
                ),
                ScamReport(
                    kind="sms",
                    value="older",
                    category="fake_kyc",
                    status="verified",
                    created_at=datetime.now(timezone.utc) - timedelta(days=20),
                    reviewed_at=datetime.now(timezone.utc) - timedelta(days=20),
                ),
            ]
        )
        db.session.commit()
    response = client.get("/dashboard?period=7")
    assert b"UPI collect request" in response.data
    assert b"Fake KYC" not in response.data
    assert b"Last 7 days" in response.data


def test_moderator_note_is_saved_with_review_status(client, app):
    with app.app_context():
        report = ScamReport(kind="sms", value="example", category="other")
        db.session.add(report)
        db.session.commit()
        report_id = report.id
    client.post("/moderator/login", data={"token": "test-moderator-token"})
    response = client.post(
        f"/moderator/reports/{report_id}/reject",
        data={"review_note": "Insufficient evidence"},
    )
    assert response.status_code == 302
    with app.app_context():
        report = db.session.get(ScamReport, report_id)
        assert report.status == "rejected"
        assert report.review_note == "Insufficient evidence"
        assert report.reviewed_at is not None


def test_account_verification_and_password_reset_tokens(app, client):
    from scamshield.routes import _account_token

    with app.app_context():
        user = User(email="recover@example.com", email_verified=False)
        user.set_password("old-password-123")
        db.session.add(user)
        db.session.commit()
        user_id = user.id
        verify_token = _account_token(user, "verify")
        reset_token = _account_token(user, "reset")

    verify_page = client.get(f"/account/verify/{verify_token}")
    assert verify_page.status_code == 200
    with app.app_context():
        assert db.session.get(User, user_id).email_verified is False
    assert client.post(f"/account/verify/{verify_token}").status_code == 302
    assert client.get(f"/account/reset/{reset_token}").status_code == 200
    reset_response = client.post(
        f"/account/reset/{reset_token}",
        data={
            "password": "new-password-123",
            "confirmation": "new-password-123",
        },
    )
    assert reset_response.status_code == 302
    with app.app_context():
        user = db.session.get(User, user_id)
        assert user.email_verified is True
        assert user.check_password("new-password-123")


def test_registration_uses_canonical_host_for_verification_email(
    app, client, monkeypatch
):
    sent = {}

    def capture_email(recipient, subject, purpose, action_url):
        sent.update(
            recipient=recipient,
            subject=subject,
            purpose=purpose,
            action_url=action_url,
        )
        return True

    app.config.update(
        MAIL_SERVER="smtp.example.test",
        MAIL_DEFAULT_SENDER="no-reply@example.test",
        PUBLIC_BASE_URL="https://scamshield.example",
    )
    monkeypatch.setattr("scamshield.routes._send_account_email", capture_email)
    response = client.post(
        "/account/register",
        data={
            "email": "new@example.com",
            "password": "a-long-test-password",
            "confirmation": "a-long-test-password",
        },
    )
    assert response.status_code == 302
    assert sent["recipient"] == "new@example.com"
    assert sent["action_url"].startswith("https://scamshield.example/account/verify/")
    with app.app_context():
        assert User.query.one().email_verified is False


def test_startup_adds_new_columns_without_losing_existing_accounts(tmp_path):
    database_path = tmp_path / "existing.sqlite"
    engine = create_engine(f"sqlite:///{database_path.as_posix()}")
    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE user (id INTEGER PRIMARY KEY, email VARCHAR(254) NOT NULL, "
                "password_hash VARCHAR(255), google_sub VARCHAR(255), "
                "display_name VARCHAR(120) NOT NULL DEFAULT '', created_at DATETIME NOT NULL)"
            )
        )
        connection.execute(
            text(
                "CREATE TABLE scam_report (id INTEGER PRIMARY KEY, kind VARCHAR(20) NOT NULL, "
                "value VARCHAR(2000) NOT NULL, category VARCHAR(60) NOT NULL, "
                "details VARCHAR(500) NOT NULL DEFAULT '', status VARCHAR(20) NOT NULL, "
                "created_at DATETIME NOT NULL)"
            )
        )
        connection.execute(
            text(
                "INSERT INTO user (id, email, created_at) "
                "VALUES (1, 'existing@example.com', '2026-01-01 00:00:00')"
            )
        )
    engine.dispose()

    migrated_app = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-key",
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{database_path.as_posix()}",
        }
    )
    with migrated_app.app_context():
        existing_user = User.query.one()
        assert existing_user.email == "existing@example.com"
        assert existing_user.email_verified is True
        report_columns = {
            column["name"] for column in inspect(db.engine).get_columns("scam_report")
        }
        assert {"review_note", "reviewed_at"} <= report_columns
