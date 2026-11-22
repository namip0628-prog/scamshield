import os
from pathlib import Path

import click
from flask import Flask
from sqlalchemy import DateTime, inspect, text

from .extensions import csrf, db, login_manager, oauth


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    database_url = os.environ.get("DATABASE_URL")
    if database_url:
        if database_url.startswith("postgres://"):
            database_url = database_url.replace(
                "postgres://", "postgresql+psycopg://", 1
            )
        elif database_url.startswith("postgresql://"):
            database_url = database_url.replace(
                "postgresql://", "postgresql+psycopg://", 1
            )
    configured_database_url = database_url or (test_config or {}).get(
        "SQLALCHEMY_DATABASE_URI"
    )
    if os.environ.get("FLASK_ENV") == "production" and not configured_database_url:
        raise RuntimeError(
            "Set DATABASE_URL to a shared PostgreSQL database in production."
        )
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY"),
        SQLALCHEMY_DATABASE_URI=database_url,
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        MODERATOR_TOKEN=os.environ.get("MODERATOR_TOKEN"),
        GOOGLE_CLIENT_ID=os.environ.get("GOOGLE_CLIENT_ID"),
        GOOGLE_CLIENT_SECRET=os.environ.get("GOOGLE_CLIENT_SECRET"),
        MAIL_SERVER=os.environ.get("MAIL_SERVER"),
        MAIL_PORT=int(os.environ.get("MAIL_PORT", "587")),
        MAIL_USERNAME=os.environ.get("MAIL_USERNAME"),
        MAIL_PASSWORD=os.environ.get("MAIL_PASSWORD"),
        MAIL_USE_TLS=os.environ.get("MAIL_USE_TLS", "true").casefold() == "true",
        MAIL_DEFAULT_SENDER=os.environ.get("MAIL_DEFAULT_SENDER"),
        PUBLIC_BASE_URL=os.environ.get("PUBLIC_BASE_URL"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production",
    )

    if not app.config["SQLALCHEMY_DATABASE_URI"]:
        database_path = Path(app.instance_path) / "scamshield.sqlite"
        app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{database_path.as_posix()}"

    if test_config:
        app.config.update(test_config)
    if not app.config.get("SECRET_KEY"):
        if os.environ.get("FLASK_ENV") == "production":
            raise RuntimeError("Set SECRET_KEY to a private random value in production.")
        app.config["SECRET_KEY"] = "local-development-key-change-before-deployment"

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "main.login"
    oauth.init_app(app)
    if app.config["GOOGLE_CLIENT_ID"] and app.config["GOOGLE_CLIENT_SECRET"]:
        oauth.register(
            name="google",
            client_id=app.config["GOOGLE_CLIENT_ID"],
            client_secret=app.config["GOOGLE_CLIENT_SECRET"],
            server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile"},
        )

    from . import models  # noqa: F401
    from .models import User
    from .routes import main

    @login_manager.user_loader
    def load_user(user_id):
        try:
            return db.session.get(User, int(user_id))
        except (TypeError, ValueError):
            return None

    app.register_blueprint(main)

    with app.app_context():
        db.create_all()
        _add_missing_columns()

    @app.cli.command("init-db")
    def init_db():
        """Create the database tables."""
        with app.app_context():
            db.create_all()
        click.echo("Database tables created.")

    return app


def _add_missing_columns():
    additions = {
        "user": {
            "email_verified": "BOOLEAN NOT NULL DEFAULT TRUE",
        },
        "scam_report": {
            "reviewed_at": str(DateTime(timezone=True).compile(dialect=db.engine.dialect)),
            "review_note": "VARCHAR(500) NOT NULL DEFAULT ''",
        },
    }
    inspector = inspect(db.engine)
    for table, columns in additions.items():
        existing = {column["name"] for column in inspector.get_columns(table)}
        for column, definition in columns.items():
            if column not in existing:
                db.session.execute(
                    text(f'ALTER TABLE "{table}" ADD COLUMN "{column}" {definition}')
                )
    db.session.commit()
