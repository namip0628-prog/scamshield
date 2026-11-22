from datetime import datetime, timezone

from sqlalchemy import UniqueConstraint
from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db


def utc_now():
    return datetime.now(timezone.utc)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(254), nullable=False, unique=True, index=True)
    password_hash = db.Column(db.String(255))
    google_sub = db.Column(db.String(255), unique=True, index=True)
    display_name = db.Column(db.String(120), nullable=False, default="")
    email_verified = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now)
    reports = db.relationship(
        "ScamReport",
        secondary="user_scam_reports",
        back_populates="reporters",
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return bool(self.password_hash) and check_password_hash(
            self.password_hash, password
        )


user_scam_reports = db.Table(
    "user_scam_reports",
    db.Column("user_id", db.Integer, db.ForeignKey("user.id"), primary_key=True),
    db.Column(
        "report_id",
        db.Integer,
        db.ForeignKey("scam_report.id"),
        primary_key=True,
    ),
)


class Indicator(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    kind = db.Column(db.String(20), nullable=False, index=True)
    value = db.Column(db.String(2000), nullable=False, index=True)
    report_count = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now)
    __table_args__ = (UniqueConstraint("kind", "value", name="uq_indicator_kind_value"),)


class ScamReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    kind = db.Column(db.String(20), nullable=False)
    value = db.Column(db.String(2000), nullable=False)
    category = db.Column(db.String(60), nullable=False)
    details = db.Column(db.String(500), nullable=False, default="")
    status = db.Column(db.String(20), nullable=False, default="pending", index=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now)
    reviewed_at = db.Column(db.DateTime(timezone=True))
    review_note = db.Column(db.String(500), nullable=False, default="")
    reporters = db.relationship(
        "User",
        secondary=user_scam_reports,
        back_populates="reports",
    )
