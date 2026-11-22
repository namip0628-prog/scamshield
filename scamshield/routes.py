import hmac
import re
import secrets
import smtplib
from email.message import EmailMessage
from collections import Counter
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from authlib.integrations.base_client.errors import OAuthError
from flask_login import current_user, login_required, login_user, logout_user
from joserfc.errors import JoseError
from sqlalchemy import func
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from .analysis import analyze_text, normalize_value
from .extensions import db, oauth
from .models import Indicator, ScamReport, User, user_scam_reports

main = Blueprint("main", __name__)
_REPORT_KINDS = {"sms", "url", "phone", "upi_id"}
_REPORT_CATEGORIES = {
    "fake_kyc": "Fake KYC",
    "upi_collect": "UPI collect request",
    "bill_threat": "Bill-disconnection threat",
    "fake_refund": "Fake refund or reward",
    "other": "Other",
}
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@main.route("/", methods=["GET", "POST"])
def index():
    result = None
    text = ""
    language = "en"
    if request.method == "POST":
        text = request.form.get("text", "").strip()
        language = request.form.get("language", "en")
        if language not in {"en", "hi"}:
            language = "en"
        if not text:
            flash("Paste a message or enter a suspicious link, phone number, or UPI ID.", "error")
        elif len(text) > 2000:
            flash("Please keep the text to 2,000 characters or fewer.", "error")
        else:
            result = analyze_text(text, language=language)
    return render_template("index.html", result=result, text=text, language=language)


@main.route("/report", methods=["GET", "POST"])
def report():
    if request.method == "POST":
        kind = request.form.get("kind", "")
        value = request.form.get("value", "").strip()
        category = request.form.get("category", "")
        details = request.form.get("details", "").strip()
        errors = []
        if kind not in _REPORT_KINDS:
            errors.append("Choose a supported report type.")
        if not value or len(value) > 2000:
            errors.append("Enter a value between 1 and 2,000 characters.")
        if category not in _REPORT_CATEGORIES:
            errors.append("Choose a scam category.")
        if len(details) > 500:
            errors.append("Keep additional details to 500 characters or fewer.")
        if errors:
            for error in errors:
                flash(error, "error")
            return render_template("report.html", categories=_REPORT_CATEGORIES)

        normalized_value = normalize_value(kind, value)
        recent_reports = (
            ScamReport.query.filter(
                ScamReport.kind == kind,
                ScamReport.status.in_(("pending", "verified")),
            )
            .order_by(ScamReport.created_at.desc())
            .limit(200)
            .all()
        )
        if any(normalize_value(kind, item.value) == normalized_value for item in recent_reports):
            flash(
                "A similar report is already awaiting review or has been verified. "
                "You can still submit your report with additional context.",
                "warning",
            )

        db.session.add(
            ScamReport(
                kind=kind,
                value=value,
                category=category,
                details=details,
                reporters=[current_user] if current_user.is_authenticated else [],
            )
        )
        db.session.commit()
        flash("Thank you. Your report was submitted for moderator review.", "success")
        return redirect(url_for("main.report"))
    return render_template(
        "report.html",
        categories=_REPORT_CATEGORIES,
        selected_kind="",
        value="",
    )


@main.route("/dashboard")
def dashboard():
    period = request.args.get("period", "all")
    if period not in {"7", "30", "90", "all"}:
        period = "all"
    report_query = ScamReport.query.filter_by(status="verified")
    if period != "all":
        cutoff = datetime.now(timezone.utc) - timedelta(days=int(period))
        report_query = report_query.filter(
            ScamReport.created_at >= cutoff
        )
    verified_reports = (
        report_query
        .with_entities(ScamReport.category, func.count(ScamReport.id))
        .group_by(ScamReport.category)
        .all()
    )
    category_counts = Counter(
        {_REPORT_CATEGORIES.get(category, "Other"): count for category, count in verified_reports}
    )
    return render_template(
        "dashboard.html",
        categories=list(category_counts.keys()),
        counts=list(category_counts.values()),
        total=sum(category_counts.values()),
        indicators=Indicator.query.count(),
        period=period,
        updated_at=(
            db.session.query(func.max(ScamReport.reviewed_at))
            .filter_by(status="verified")
            .scalar()
        ),
    )


@main.route("/about")
def about():
    return render_template("about.html")


@main.route("/account/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main.my_reports"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().casefold()
        password = request.form.get("password", "")
        confirmation = request.form.get("confirmation", "")
        if not _EMAIL_RE.fullmatch(email) or len(email) > 254:
            flash("Enter a valid email address.", "error")
        elif len(password) < 12 or len(password) > 128:
            flash("Use a password between 12 and 128 characters.", "error")
        elif password != confirmation:
            flash("The passwords do not match.", "error")
        elif User.query.filter_by(email=email).first():
            flash("An account already exists for that email address.", "error")
        else:
            user = User(email=email)
            user.set_password(password)
            user.email_verified = not _mail_is_configured()
            db.session.add(user)
            db.session.commit()
            login_user(user)
            if _mail_is_configured():
                sent = _send_account_email(
                    user.email,
                    "Verify your ScamShield email",
                    "verify",
                    _account_action_url(
                        "main.verify_email",
                        token=_account_token(user, "verify"),
                    ),
                )
                if sent:
                    flash("Your account is ready. Check your email to verify the address.", "success")
                else:
                    flash("Your account was created, but the verification email could not be sent.", "error")
            else:
                flash("Your account is ready.", "success")
            return redirect(url_for("main.my_reports"))
    return render_template(
        "account.html",
        mode="register",
        google_sign_in_enabled=bool(
            current_app.config.get("GOOGLE_CLIENT_ID")
            and current_app.config.get("GOOGLE_CLIENT_SECRET")
        ),
    )


@main.route("/account/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.my_reports"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().casefold()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            if not user.email_verified:
                flash("You are signed in, but your email address is not verified yet.", "warning")
            else:
                flash("You are signed in.", "success")
            return redirect(_safe_next_url(request.args.get("next")) or url_for("main.my_reports"))
        flash("The email or password was not accepted.", "error")
    return render_template(
        "account.html",
        mode="login",
        google_sign_in_enabled=bool(
            current_app.config.get("GOOGLE_CLIENT_ID")
            and current_app.config.get("GOOGLE_CLIENT_SECRET")
        ),
    )


@main.route("/account/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().casefold()
        user = User.query.filter_by(email=email).first()
        if user and user.password_hash and _mail_is_configured():
            token = _account_token(user, "reset")
            _send_account_email(
                user.email,
                "Reset your ScamShield password",
                "reset",
                _account_action_url("main.reset_password", token=token),
            )
        flash(
            "If an account exists for that address and email delivery is configured, "
            "a password-reset link will be sent.",
            "success",
        )
        return redirect(url_for("main.forgot_password"))
    return render_template("forgot_password.html")


@main.route("/account/verify/<token>", methods=["GET", "POST"])
def verify_email(token):
    user = _load_account_token(token, "verify", max_age=86400)
    if user is None:
        flash("That verification link is invalid or has expired.", "error")
        return redirect(url_for("main.login"))
    if request.method == "GET":
        return render_template("verify_email.html")
    user.email_verified = True
    db.session.commit()
    flash("Your email address has been verified.", "success")
    return redirect(url_for("main.login"))


@main.route("/account/reset/<token>", methods=["GET", "POST"])
def reset_password(token):
    user = _load_account_token(token, "reset", max_age=3600)
    if user is None or not user.password_hash:
        flash("That password-reset link is invalid or has expired.", "error")
        return redirect(url_for("main.forgot_password"))
    if request.method == "POST":
        password = request.form.get("password", "")
        confirmation = request.form.get("confirmation", "")
        if len(password) < 12 or len(password) > 128:
            flash("Use a password between 12 and 128 characters.", "error")
        elif password != confirmation:
            flash("The passwords do not match.", "error")
        else:
            user.set_password(password)
            db.session.commit()
            flash("Your password has been updated. Please sign in.", "success")
            return redirect(url_for("main.login"))
    return render_template("reset_password.html")


@main.route("/account/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("You have been signed out.", "success")
    return redirect(url_for("main.index"))


@main.route("/account/resend-verification", methods=["POST"])
@login_required
def resend_verification():
    if current_user.email_verified:
        flash("Your email address is already verified.", "success")
    elif not _mail_is_configured():
        flash("Email verification is unavailable because email delivery is not configured.", "error")
    else:
        sent = _send_account_email(
            current_user.email,
            "Verify your ScamShield email",
            "verify",
            _account_action_url(
                "main.verify_email",
                token=_account_token(current_user, "verify"),
            ),
        )
        flash(
            "A verification link was sent." if sent else "The verification email could not be sent.",
            "success" if sent else "error",
        )
    return redirect(url_for("main.my_reports"))


@main.route("/account/google")
def google_login():
    client = oauth.create_client("google")
    if client is None:
        abort(503, description="Google sign-in is not configured.")
    nonce = secrets.token_urlsafe(32)
    session["google_oauth_nonce"] = nonce
    return client.authorize_redirect(
        url_for("main.google_callback", _external=True),
        nonce=nonce,
    )


@main.route("/account/google/callback")
def google_callback():
    client = oauth.create_client("google")
    if client is None:
        abort(503, description="Google sign-in is not configured.")
    try:
        token = client.authorize_access_token()
    except OAuthError:
        flash("Google sign-in could not be completed. Please try again.", "error")
        return redirect(url_for("main.login"))

    nonce = session.pop("google_oauth_nonce", None)
    if nonce is None:
        flash("Google sign-in could not be verified. Please try again.", "error")
        return redirect(url_for("main.login"))
    try:
        claims = client.parse_id_token(token, nonce=nonce)
    except JoseError:
        flash("Google sign-in could not be verified. Please try again.", "error")
        return redirect(url_for("main.login"))
    if claims is None:
        flash("Google did not provide a valid sign-in token.", "error")
        return redirect(url_for("main.login"))
    email = claims.get("email")
    google_sub = claims.get("sub")
    if (
        not claims.get("email_verified")
        or not isinstance(email, str)
        or not isinstance(google_sub, str)
        or not google_sub
    ):
        flash("Google did not provide a verified email address.", "error")
        return redirect(url_for("main.login"))
    email = email.strip().casefold()
    if not _EMAIL_RE.fullmatch(email) or len(email) > 254:
        flash("Google did not provide a verified email address.", "error")
        return redirect(url_for("main.login"))

    user = User.query.filter_by(google_sub=google_sub).first()
    if user is None:
        user = User.query.filter_by(email=email).first()
        if user and user.google_sub and user.google_sub != google_sub:
            flash("This email is already linked to another Google account.", "error")
            return redirect(url_for("main.login"))
        if user and user.password_hash:
            flash(
                "An account already uses this email. Sign in with email and password instead.",
                "error",
            )
            return redirect(url_for("main.login"))
        if user is None:
            user = User(email=email, google_sub=google_sub)
            user.email_verified = True
            db.session.add(user)
        else:
            user.google_sub = google_sub
            user.email_verified = True
        display_name = claims.get("name", "")
        user.display_name = display_name[:120] if isinstance(display_name, str) else ""
        db.session.commit()

    login_user(user)
    flash("You are signed in with Google.", "success")
    return redirect(url_for("main.my_reports"))


@main.route("/account/reports")
@login_required
def my_reports():
    reports = (
        ScamReport.query.join(user_scam_reports)
        .filter(user_scam_reports.c.user_id == current_user.id)
        .order_by(ScamReport.created_at.desc())
        .limit(100)
        .all()
    )
    return render_template("my_reports.html", reports=reports, categories=_REPORT_CATEGORIES)


@main.route("/moderator/login", methods=["GET", "POST"])
def moderator_login():
    token = current_app.config.get("MODERATOR_TOKEN")
    if not token:
        abort(503, description="Moderator access is not configured.")
    if request.method == "POST":
        supplied = request.form.get("token", "")
        if hmac.compare_digest(supplied, token):
            session["is_moderator"] = True
            return redirect(url_for("main.moderator"))
        flash("The moderator token was not accepted.", "error")
    return render_template("moderator_login.html")


@main.route("/moderator/logout", methods=["POST"])
def moderator_logout():
    session.pop("is_moderator", None)
    flash("You have been logged out.", "success")
    return redirect(url_for("main.index"))


@main.route("/moderator")
def moderator():
    _require_moderator()
    reports = ScamReport.query.order_by(ScamReport.created_at.desc()).limit(100).all()
    return render_template("moderator.html", reports=reports, categories=_REPORT_CATEGORIES)


@main.route("/moderator/reports/<int:report_id>/<action>", methods=["POST"])
def moderate_report(report_id, action):
    _require_moderator()
    if action not in {"verify", "reject"}:
        abort(404)
    report = db.get_or_404(ScamReport, report_id)
    if report.status != "pending":
        flash("This report has already been reviewed.", "error")
        return redirect(url_for("main.moderator"))
    review_note = request.form.get("review_note", "").strip()
    if len(review_note) > 500:
        flash("Keep the moderator note to 500 characters or fewer.", "error")
        return redirect(url_for("main.moderator"))

    if action == "verify":
        indicator_value = normalize_value(report.kind, report.value)
        indicator = Indicator.query.filter_by(
            kind=report.kind,
            value=indicator_value,
        ).first()
        if indicator:
            indicator.report_count += 1
        else:
            db.session.add(
                Indicator(
                    kind=report.kind,
                    value=indicator_value,
                )
            )
        report.status = "verified"
    else:
        report.status = "rejected"
    report.reviewed_at = datetime.now(timezone.utc)
    report.review_note = review_note
    db.session.commit()
    flash(f"Report {report.status}.", "success")
    return redirect(url_for("main.moderator"))


def _require_moderator():
    if not session.get("is_moderator"):
        abort(403)


def _safe_next_url(target):
    if not target:
        return None
    parsed = urlsplit(target)
    if (
        parsed.scheme
        or parsed.netloc
        or not parsed.path.startswith("/")
        or parsed.path.startswith(("//", "/\\"))
    ):
        return None
    return target


def _mail_is_configured():
    return bool(
        current_app.config.get("MAIL_SERVER")
        and current_app.config.get("MAIL_DEFAULT_SENDER")
        and current_app.config.get("PUBLIC_BASE_URL")
    )


def _account_serializer():
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"])


def _account_action_url(endpoint, **values):
    base_url = current_app.config.get("PUBLIC_BASE_URL")
    if base_url:
        return f"{base_url.rstrip('/')}{url_for(endpoint, **values)}"
    return url_for(endpoint, _external=True, **values)


def _account_token(user, purpose):
    return _account_serializer().dumps(
        {"user_id": user.id, "purpose": purpose},
        salt="scamshield-account-action",
    )


def _load_account_token(token, purpose, max_age):
    try:
        payload = _account_serializer().loads(
            token,
            salt="scamshield-account-action",
            max_age=max_age,
        )
    except (BadSignature, SignatureExpired):
        return None
    if payload.get("purpose") != purpose:
        return None
    return db.session.get(User, payload.get("user_id"))


def _send_account_email(recipient, subject, purpose, action_url):
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = current_app.config["MAIL_DEFAULT_SENDER"]
    message["To"] = recipient
    message.set_content(
        f"Use this link to {purpose} your ScamShield account:\n\n"
        f"{action_url}\n\n"
        "If you did not request this, you can ignore this email."
    )
    try:
        with smtplib.SMTP(
            current_app.config["MAIL_SERVER"],
            current_app.config["MAIL_PORT"],
            timeout=10,
        ) as server:
            if current_app.config["MAIL_USE_TLS"]:
                server.starttls()
            username = current_app.config.get("MAIL_USERNAME")
            if username:
                server.login(username, current_app.config.get("MAIL_PASSWORD") or "")
            server.send_message(message)
    except (OSError, smtplib.SMTPException):
        current_app.logger.exception("Could not send account email to %s", recipient)
        return False
    return True
