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
from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    redirect,
    url_for,
    flash
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
            url_for("home")
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

        password = (
            request.form
            .get("password", "")
        )

        confirm_password = (
            request.form
            .get("confirm_password", "")
        )


        if not name or not email or not password:

            flash(
                "Please fill in all fields.",
                "error"
            )

            return render_template(
                "register.html"
            )


        if len(name) > 100:

            flash(
                "Name is too long.",
                "error"
            )

            return render_template(
                "register.html"
            )


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


        user = User(
            name=name,
            email=email
        )

        user.set_password(
            password
        )


        db.session.add(
            user
        )

        db.session.commit()


        login_user(
            user
        )


        return redirect(
            url_for("home")
        )


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