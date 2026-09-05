from flask import Flask, render_template, request, jsonify
from detector import analyze_url
from virustotal import check_virustotal
from database import init_db, save_scan, get_recent_scans, get_stats
from risk_engine import calculate_final_risk
from domain_reputation import check_domain_age
from url_validator import validate_url
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
app = Flask(__name__)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["100 per hour"],
    storage_uri="memory://"
)
init_db()
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/dashboard")
def dashboard():

    scans = get_recent_scans(20)
    stats = get_stats()

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

    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True)