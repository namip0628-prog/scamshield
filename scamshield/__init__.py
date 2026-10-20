import os
from pathlib import Path

import click
from flask import Flask

from .extensions import csrf, db


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
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY"),
        SQLALCHEMY_DATABASE_URI=database_url,
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        MODERATOR_TOKEN=os.environ.get("MODERATOR_TOKEN"),
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

    from . import models  # noqa: F401
    from .routes import main

    app.register_blueprint(main)

    @app.cli.command("init-db")
    def init_db():
        """Create the database tables."""
        with app.app_context():
            db.create_all()
        click.echo("Database tables created.")

    return app
