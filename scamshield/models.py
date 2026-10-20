from datetime import datetime, timezone

from sqlalchemy import UniqueConstraint

from .extensions import db


def utc_now():
    return datetime.now(timezone.utc)


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
