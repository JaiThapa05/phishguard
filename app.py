import os
from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify
from detector import analyze_url
from virustotal import check_virustotal
from database import init_db, save_scan, get_recent_scans, get_stats
from risk_engine import calculate_final_risk
from domain_reputation import check_domain_age
from url_validator import validate_url
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_migrate import Migrate
from authlib.integrations.flask_client import OAuth
from email_service import (
    send_verification_email,
    verify_token
)
from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    redirect,
    url_for,
    flash,
    abort
)

from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user
)
from flask_login import current_user
from models import db, User, Scan
app = Flask(__name__)

oauth = OAuth(app)

google = oauth.register(
    name="google",

    client_id=os.getenv(
        "GOOGLE_CLIENT_ID"
    ),

    client_secret=os.getenv(
        "GOOGLE_CLIENT_SECRET"
    ),

    server_metadata_url=(
        "https://accounts.google.com/"
        ".well-known/openid-configuration"
    ),

    client_kwargs={
        "scope": "openid email profile"
    }
)

@app.route("/login/google")
def google_login():

    redirect_uri = url_for(
        "google_callback",
        _external=True
    )

    return google.authorize_redirect(
        redirect_uri
    )


@app.route("/auth/google/callback")
def google_callback():

    try:

        token = google.authorize_access_token()

        user_info = token.get(
            "userinfo"
        )

        if not user_info:

            user_info = google.userinfo()


        email = (
            user_info.get(
                "email",
                ""
            )
            .strip()
            .lower()
        )


        google_id = str(
            user_info.get(
                "sub",
                ""
            )
        )


        name = (
            user_info.get("name")
            or email.split("@")[0]
        )


        verified = user_info.get(
            "email_verified",
            False
        )


        if not verified:

            flash(
                "Google could not verify this email.",
                "error"
            )

            return redirect(
                url_for("login")
            )


        # If you specifically want Gmail only
        if not email.endswith("@gmail.com"):

            flash(
                "Please use a Gmail account.",
                "error"
            )

            return redirect(
                url_for("login")
            )


        if not google_id:

            flash(
                "Google authentication failed.",
                "error"
            )

            return redirect(
                url_for("login")
            )


        # First search by Google ID

        user = User.query.filter_by(
            google_id=google_id
        ).first()


        # Existing account?
        if user is None:

            user = User.query.filter_by(
                email=email
            ).first()


            if user:

                user.google_id = google_id
                user.is_verified = True


            else:

                import secrets

                user = User(
                    name=name,
                    email=email,
                    google_id=google_id,
                    is_verified=True
                )

                # Existing DB currently requires
                # password_hash, so give OAuth
                # account an unusable random password.

                user.set_password(
                    secrets.token_urlsafe(48)
                )

                db.session.add(
                    user
                )


            db.session.commit()


        login_user(
            user,
            remember=True
        )


        return redirect(
            url_for("dashboard")
        )


    except Exception as e:

        print(
            "Google OAuth error:",
            e
        )

        flash(
            "Google sign-in failed. Please try again.",
            "error"
        )

        return redirect(
            url_for("login")
        )


@app.route("/report/<int:scan_id>")
@login_required
def report(scan_id):

    scan = db.session.get(
        Scan,
        scan_id
    )

    if scan is None:
        abort(404)

    # User can access only their own report
    if scan.user_id != current_user.id:
        abort(403)

    return render_template(
        "report.html",
        scan=scan
    )
app.config["SECRET_KEY"] = os.getenv(
    "SECRET_KEY",
    "development-only-secret"
)


database_url = os.getenv(
    "DATABASE_URL"
)


if database_url:

    # Some platforms may provide postgres://
    # SQLAlchemy expects postgresql://
    if database_url.startswith(
        "postgres://"
    ):

        database_url = (
            database_url.replace(
                "postgres://",
                "postgresql://",
                1
            )
        )

    app.config[
        "SQLALCHEMY_DATABASE_URI"
    ] = database_url

else:

    app.config[
        "SQLALCHEMY_DATABASE_URI"
    ] = "sqlite:///phishguard.db"


app.config[
    "SQLALCHEMY_TRACK_MODIFICATIONS"
] = False


db.init_app(app)

migrate = Migrate(app, db)


login_manager = LoginManager()

login_manager.init_app(app)

login_manager.login_view = "login"

login_manager.login_message = (
    "Please sign in to access this page."
)

login_manager.login_message_category = "info"


@login_manager.user_loader
def load_user(user_id):

    return db.session.get(
        User,
        int(user_id)
    )

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if current_user.is_authenticated:

        return redirect(
            url_for("dashboard")
        )


    if request.method == "POST":

        name = (
            request.form
            .get("name", "")
            .strip()
        )

        email = (
            request.form
            .get("email", "")
            .strip()
            .lower()
        )

        password = request.form.get(
            "password",
            ""
        )

        confirm = request.form.get(
            "confirm_password",
            ""
        )


        if not name or not email:

            flash(
                "Please complete all fields.",
                "error"
            )

            return render_template(
                "register.html"
            )


        if len(password) < 8:

            flash(
                "Password must contain at least 8 characters.",
                "error"
            )

            return render_template(
                "register.html"
            )


        if password != confirm:

            flash(
                "Passwords do not match.",
                "error"
            )

            return render_template(
                "register.html"
            )


        existing = User.query.filter_by(
            email=email
        ).first()


        if existing:

            flash(
                "An account with this email already exists.",
                "error"
            )

            return render_template(
                "register.html"
            )


        user = User(
            name=name,
            email=email,

            # Temporary until public email
            # verification is configured.
            is_verified=True
        )


        user.set_password(
            password
        )


        try:

            db.session.add(user)

            db.session.commit()


        except Exception as e:

            db.session.rollback()

            print(
                "Registration error:",
                e
            )

            flash(
                "Unable to create account.",
                "error"
            )

            return render_template(
                "register.html"
            )


        login_user(
            user,
            remember=True
        )


        return redirect(
            url_for("dashboard")
        )


    return render_template(
        "register.html"
    )

    # ==========================================
    # POST - CREATE ACCOUNT
    # ==========================================

    if request.method == "POST":

        name = (
            request.form
            .get("name", "")
            .strip()
        )

        email = (
            request.form
            .get("email", "")
            .strip()
            .lower()
        )

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )


        # --------------------------------------
        # REQUIRED FIELDS
        # --------------------------------------

        if (
            not name
            or not email
            or not password
            or not confirm_password
        ):

            flash(
                "Please fill in all fields.",
                "error"
            )

            return render_template(
                "register.html"
            )


        # --------------------------------------
        # NAME VALIDATION
        # --------------------------------------

        if len(name) > 100:

            flash(
                "Name is too long.",
                "error"
            )

            return render_template(
                "register.html"
            )


        # --------------------------------------
        # EMAIL BASIC VALIDATION
        # --------------------------------------

        if (
            "@" not in email
            or "." not in email.split("@")[-1]
        ):

            flash(
                "Please enter a valid email address.",
                "error"
            )

            return render_template(
                "register.html"
            )


        # --------------------------------------
        # PASSWORD VALIDATION
        # --------------------------------------

        if len(password) < 8:

            flash(
                "Password must be at least 8 characters.",
                "error"
            )

            return render_template(
                "register.html"
            )


        if password != confirm_password:

            flash(
                "Passwords do not match.",
                "error"
            )

            return render_template(
                "register.html"
            )


        # --------------------------------------
        # EXISTING ACCOUNT
        # --------------------------------------

        existing_user = (
            User.query
            .filter_by(
                email=email
            )
            .first()
        )


        if existing_user:

            flash(
                "An account with this email already exists.",
                "error"
            )

            return render_template(
                "register.html"
            )


        # ======================================
        # CREATE USER
        # ======================================

        user = User(
            name=name,
            email=email,
            is_verified=False
        )


        user.set_password(
            password
        )


        try:

            db.session.add(
                user
            )

            db.session.commit()


        except Exception as e:

            db.session.rollback()

            print(
                "User registration database error:",
                e
            )

            flash(
                "Unable to create account. "
                "Please try again.",
                "error"
            )

            return render_template(
                "register.html"
            )


        # ======================================
        # SEND VERIFICATION EMAIL
        # ======================================

        try:

            send_verification_email(
                user.email,
                user.name
            )


        except Exception as e:

            print(
                "Verification email error:",
                e
            )

            flash(
                "Your account was created, but the "
                "verification email could not be sent.",
                "error"
            )

            return redirect(
                url_for("login")
            )


        # ======================================
        # SUCCESS
        # ======================================

        flash(
            "Account created successfully. "
            "Check your email and verify your "
            "account before signing in.",
            "success"
        )


        return redirect(
            url_for("login")
        )


    # ==========================================
    # GET - DISPLAY REGISTER PAGE
    # ==========================================

    return render_template(
        "register.html"
    )
@app.route("/logout")
@login_required
def logout():

    logout_user()

    return redirect(
        url_for("home")
    )

with app.app_context():

    db.create_all()

    print(
        "Authentication database initialized!"
    )

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["100 per hour"],
    storage_uri="memory://"
)
init_db()
@app.route("/login", methods=["GET", "POST"])
def login():

    if current_user.is_authenticated:
        return redirect(
            url_for("home")
        )

    if request.method == "POST":

        email = (
            request.form
            .get("email", "")
            .strip()
            .lower()
        )

        password = request.form.get(
            "password",
            ""
        )

        if not email or not password:

            flash(
                "Please enter your email and password.",
                "error"
            )

            return render_template(
                "login.html"
            )

        user = (
            User.query
            .filter_by(email=email)
            .first()
        )

        if (
            user is None
            or not user.check_password(password)
        ):

            flash(
                "Invalid email or password.",
                "error"
            )

            return render_template(
                "login.html"
            )
        if not user.is_verified:

            flash("Please verify your email before signing in.",
                 "error")
            
            return render_template(
                "login.html"
    )
        

        login_user(
            user,
            remember=True
        )

        return redirect(
            url_for("home")
        )

    return render_template(
        "login.html"
    )
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/dashboard")
@login_required
def dashboard():

    scans = (
        Scan.query
        .filter_by(
            user_id=current_user.id
        )
        .order_by(
            Scan.created_at.desc()
        )
        .limit(50)
        .all()
    )


    total = (
        Scan.query
        .filter_by(
            user_id=current_user.id
        )
        .count()
    )


    safe = (
        Scan.query
        .filter_by(
            user_id=current_user.id,
            status="Low Risk"
        )
        .count()
    )


    suspicious = (
        Scan.query
        .filter_by(
            user_id=current_user.id,
            status="Suspicious"
        )
        .count()
    )


    phishing = (
        Scan.query
        .filter_by(
            user_id=current_user.id,
            status="Likely Phishing"
        )
        .count()
    )


    stats = {
        "total": total,
        "safe": safe,
        "suspicious": suspicious,
        "phishing": phishing
    }


    return render_template(
        "dashboard.html",
        scans=scans,
        stats=stats
    )

@app.route("/check", methods=["POST"])
@limiter.limit("15 per minute")
def check():
    data = request.get_json()
    raw_url = data.get(
    "url",
    "")
    valid, url, error = validate_url(
        raw_url)
    if not valid:
        return jsonify({
        "error": error
    }), 400

    result = analyze_url(url)

    vt_result = check_virustotal(url)

    result["virustotal"] = vt_result

    domain_name = result.get("domain", "")
    domain_reputation = check_domain_age(
    domain_name
    )

    result["domain_reputation"] = domain_reputation

    domain_age = domain_reputation.get(
        "age_days")

    

    final_score, reputation_reasons = calculate_final_risk(
    ml_probability=result["ml_probability"],
    rule_score=result["rule_score"],
    domain_score=result.get("domain_score", 0),
    virustotal=vt_result,
    domain_age=domain_age
    )

    result["score"] = final_score

    for reason in reputation_reasons:
        if reason not in result["reasons"]:
            result["reasons"].append(reason)
        if final_score >= 60:
            result["status"] = "Likely Phishing"
        elif final_score >= 30:
            result["status"] = "Suspicious"
        else:
            result["status"] = "Low Risk"

    vt_malicious = 0

    if vt_result.get("found"):
        vt_malicious = vt_result.get("malicious", 0)
        save_scan(
        url=result["url"],
        status=result["status"],
        score=result["score"],
        ml_probability=result["ml_probability"],
        vt_malicious=vt_malicious
    )
    if current_user.is_authenticated:
        user_scan = Scan(

        user_id=current_user.id,

        url=result["url"],

        status=result["status"],

        score=result["score"],

        ml_probability=
            result["ml_probability"],

        rule_score=
            result["rule_score"],

        domain_score=
            result.get(
                "domain_score",
                0
            ),

        registered_domain=
            result.get(
                "domain",
                ""
            ),

        domain_age_days=
            domain_reputation.get(
                "age_days"
            ),

        domain_created=
            domain_reputation.get(
                "created"
            ),

        vt_malicious=
            vt_result.get(
                "malicious",
                0
            ),

        vt_suspicious=
            vt_result.get(
                "suspicious",
                0
            ),

        vt_harmless=
            vt_result.get(
                "harmless",
                0
            ),

        vt_undetected=
            vt_result.get(
                "undetected",
                0
            )
    )
        db.session.add(user_scan)
        db.session.commit()
        result["scan_id"] = user_scan.id
    else:
        result["scan_id"] = None    

@app.route(
    "/verify-email/<token>"
)
def verify_email(token):

    email = verify_token(
        token
    )


    if not email:

        flash(
            "Verification link is invalid or has expired.",
            "error"
        )

        return redirect(
            url_for("login")
        )


    user = (
        User.query
        .filter_by(
            email=email
        )
        .first()
    )


    if not user:

        flash(
            "Account not found.",
            "error"
        )

        return redirect(
            url_for("register")
        )


    if user.is_verified:

        flash(
            "Your email is already verified.",
            "info"
        )

        return redirect(
            url_for("login")
        )


    user.is_verified = True

    db.session.commit()


    flash(
        "Email verified successfully. "
        "You can now sign in.",
        "success"
    )


    return redirect(
        url_for("login")
    )
    # ==========================================
# SAVE SCAN FOR LOGGED-IN USER
# ==========================================

    if current_user.is_authenticated:
        try:
        
            user_scan = Scan(

            user_id=current_user.id,

            url=result["url"],

            status=result["status"],

            score=result["score"],

            ml_probability=result.get(
                "ml_probability"
                ),
                rule_score=result.get(
                "rule_score",
                0),
                domain_score=result.get(
                "domain_score",
                0),
                registered_domain=result.get(
                "domain",
                ""),
                domain_age_days=(domain_reputation.get(
                    "age_days")
                    if domain_reputation
                    else None
                    ),
                    domain_created=(domain_reputation.get(
                    "created")
                    if domain_reputation
                    else None),
                    vt_malicious=vt_result.get(
                "malicious",
                0),
                vt_suspicious=vt_result.get(
                "suspicious",
                0),
                vt_harmless=vt_result.get(
                "harmless",
                0),
                vt_undetected=vt_result.get(
                "undetected",
                0) 
            )
            db.session.add(user_scan)
            db.session.commit()
            result["scan_id"] = (
            user_scan.id
            )
        except Exception as e:
            db.session.rollback()
            print(
            "Scan save error:",
            e
        )
        result["scan_id"] = None


    else:
        result["scan_id"] = None


        return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True)