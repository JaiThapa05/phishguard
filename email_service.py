import os
import html

import resend

from dotenv import load_dotenv

from flask import url_for

from itsdangerous import (
    URLSafeTimedSerializer,
    BadSignature,
    SignatureExpired
)


load_dotenv()


RESEND_API_KEY = os.getenv(
    "RESEND_API_KEY"
)

SECRET_KEY = os.getenv(
    "SECRET_KEY"
)


if RESEND_API_KEY:
    resend.api_key = RESEND_API_KEY


def get_serializer():

    if not SECRET_KEY:

        raise RuntimeError(
            "SECRET_KEY is not configured"
        )

    return URLSafeTimedSerializer(
        SECRET_KEY
    )


def create_verification_token(email):

    serializer = get_serializer()

    return serializer.dumps(
        email,
        salt="email-verification"
    )


def verify_token(
    token,
    max_age=1800
):

    serializer = get_serializer()

    try:

        return serializer.loads(
            token,
            salt="email-verification",
            max_age=max_age
        )

    except (
        SignatureExpired,
        BadSignature
    ):

        return None


def send_verification_email(
    email,
    name
):

    if not RESEND_API_KEY:

        raise RuntimeError(
            "RESEND_API_KEY is not configured"
        )


    token = create_verification_token(
        email
    )


    verification_url = url_for(
        "verify_email",
        token=token,
        _external=True
    )


    safe_name = html.escape(
        str(name)
    )

    safe_url = html.escape(
        verification_url,
        quote=True
    )


    params = {

        "from":
        "PhishGuard <verify@YOUR_DOMAIN>",
        "to":
            [email],

        "subject":
            "Verify your PhishGuard account",

        "html":
            f"""
            <div style="
                max-width:600px;
                margin:auto;
                padding:35px;
                font-family:Arial,sans-serif;
            ">

                <h2>
                    Verify your PhishGuard account
                </h2>

                <p>
                    Hi {safe_name},
                </p>

                <p>
                    Click below to verify your email address.
                </p>

                <p style="margin:30px 0;">

                    <a
                        href="{safe_url}"
                        style="
                            display:inline-block;
                            padding:13px 20px;
                            background:#526fff;
                            color:#ffffff;
                            text-decoration:none;
                            border-radius:8px;
                        "
                    >
                        Verify Email
                    </a>

                </p>

                <p>
                    This verification link expires
                    in 30 minutes.
                </p>

                <p style="
                    color:#777;
                    font-size:12px;
                ">
                    If you did not create a PhishGuard
                    account, ignore this email.
                </p>

            </div>
            """
    }


    response = resend.Emails.send(
        params
    )

    print(
        "Verification email sent:",
        response
    )

    return response