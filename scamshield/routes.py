import hmac
from collections import Counter

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
from sqlalchemy import func

from .analysis import analyze_text, normalize_value
from .extensions import db
from .models import Indicator, ScamReport

main = Blueprint("main", __name__)
_REPORT_KINDS = {"sms", "url", "phone", "upi_id"}
_REPORT_CATEGORIES = {
    "fake_kyc": "Fake KYC",
    "upi_collect": "UPI collect request",
    "bill_threat": "Bill-disconnection threat",
    "fake_refund": "Fake refund or reward",
    "other": "Other",
}


@main.route("/", methods=["GET", "POST"])
def index():
    result = None
    text = ""
    if request.method == "POST":
        text = request.form.get("text", "").strip()
        if not text:
            flash("Paste a message or enter a suspicious link, phone number, or UPI ID.", "error")
        elif len(text) > 2000:
            flash("Please keep the text to 2,000 characters or fewer.", "error")
        else:
            result = analyze_text(text)
    return render_template("index.html", result=result, text=text)


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

        db.session.add(
            ScamReport(
                kind=kind,
                value=value,
                category=category,
                details=details,
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
    verified_reports = (
        ScamReport.query.filter_by(status="verified")
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
    )


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
    db.session.commit()
    flash(f"Report {report.status}.", "success")
    return redirect(url_for("main.moderator"))


def _require_moderator():
    if not session.get("is_moderator"):
        abort(403)
