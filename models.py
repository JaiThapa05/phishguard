from datetime import datetime, timezone

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)


db = SQLAlchemy()


class User(UserMixin, db.Model):

    __tablename__ = "users"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    name = db.Column(
        db.String(100),
        nullable=False
    )

    email = db.Column(
        db.String(255),
        unique=True,
        nullable=False,
        index=True
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

    scans = db.relationship(
        "Scan",
        backref="user",
        lazy=True,
        cascade="all, delete-orphan"
    )


    def set_password(self, password):

        self.password_hash = (
            generate_password_hash(
                password
            )
        )


    def check_password(self, password):

        return check_password_hash(
            self.password_hash,
            password
        )


class Scan(db.Model):

    __tablename__ = "scans"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "users.id"
        ),
        nullable=False,
        index=True
    )

    url = db.Column(
        db.Text,
        nullable=False
    )

    status = db.Column(
        db.String(50),
        nullable=False
    )

    score = db.Column(
        db.Integer,
        nullable=False
    )

    ml_probability = db.Column(
        db.Float,
        nullable=True
    )

    rule_score = db.Column(
        db.Integer,
        default=0
    )

    domain_score = db.Column(
        db.Integer,
        default=0
    )

    registered_domain = db.Column(
        db.String(255),
        nullable=True
    )

    domain_age_days = db.Column(
        db.Integer,
        nullable=True
    )

    domain_created = db.Column(
        db.String(50),
        nullable=True
    )

    vt_malicious = db.Column(
        db.Integer,
        default=0
    )

    vt_suspicious = db.Column(
        db.Integer,
        default=0
    )

    vt_harmless = db.Column(
        db.Integer,
        default=0
    )

    vt_undetected = db.Column(
        db.Integer,
        default=0
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )