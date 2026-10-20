import pytest

from scamshield import create_app
from scamshield.extensions import db
from scamshield.models import Indicator, ScamReport


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
