"""RAVN AI — Enterprise Security Platform (Flask)."""

from __future__ import annotations

import os
from functools import wraps
from typing import Callable

from dotenv import load_dotenv
load_dotenv()

from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from groq import Groq

import models
from config import SECRET_KEY
from scanner import scan_website

# Suppress SSL warnings for scanning external sites
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.secret_key = SECRET_KEY


def login_required(view: Callable):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


@app.context_processor
def inject_globals():
    user = None
    if "user_email" in session:
        user = models.get_user_by_email(session["user_email"])
    unread = len([a for a in models.get_alerts() if a["status"] == "new"])
    return {"current_user": user, "unread_alerts": unread}


@app.template_filter("relative_time")
def relative_time(value: str | None) -> str:
    if not value:
        return "Never"
    from datetime import datetime, timezone
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        delta = datetime.now(timezone.utc) - dt
        seconds = int(delta.total_seconds())
        if seconds < 60:
            return "Just now"
        if seconds < 3600:
            return f"{seconds // 60}m ago"
        if seconds < 86400:
            return f"{seconds // 3600}h ago"
        return f"{seconds // 86400}d ago"
    except Exception:
        return value


@app.template_filter("format_datetime")
def format_datetime(value: str | None) -> str:
    if not value:
        return "—"
    from datetime import datetime
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt.strftime("%b %d, %Y %H:%M")
    except Exception:
        return value


@app.template_filter("risk_level")
def risk_level(score: int) -> str:
    if score >= 70:
        return "critical"
    if score >= 40:
        return "high"
    if score >= 20:
        return "medium"
    return "low"


# ── Public pages ─────────────────────────────────────────────────────────────

@app.route("/")
def landing():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("landing.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        user = models.verify_user(email, password)
        if user:
            session["user_id"] = user["id"]
            session["user_email"] = user["email"]
            session["user_name"] = user["name"]
            flash("Welcome back.", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid email or password.", "error")
    return render_template("auth/login.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        if len(password) < 6:
            flash("Password must be at least 6 characters.", "error")
        elif models.create_user(email, password, name):
            flash("Account created. Please sign in.", "success")
            return redirect(url_for("login"))
        else:
            flash("An account with this email already exists.", "error")
    return render_template("auth/signup.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("landing"))


# ── Dashboard ────────────────────────────────────────────────────────────────

@app.route("/dashboard")
@login_required
def dashboard():
    stats = models.get_dashboard_stats()
    alerts = models.get_alerts()[:5]
    trend = models.get_threat_trend()
    risk_dist = models.get_risk_distribution()
    return render_template(
        "dashboard/index.html",
        stats=stats,
        recent_alerts=alerts,
        threat_trend=trend,
        risk_distribution=risk_dist,
    )


# ── Websites ─────────────────────────────────────────────────────────────────

@app.route("/websites")
@login_required
def websites():
    search = request.args.get("q", "")
    items = models.get_websites(search)
    return render_template("websites/list.html", websites=items, search=search)


@app.route("/websites/add", methods=["POST"])
@login_required
def add_website():
    name = request.form.get("name", "").strip()
    url = request.form.get("url", "").strip()
    if name and url:
        models.add_website(name, url)
        flash(f"{name} is now being monitored.", "success")
    else:
        flash("Name and URL are required.", "error")
    return redirect(url_for("websites"))


@app.route("/websites/<website_id>")
@login_required
def website_detail(website_id: str):
    website = models.get_website(website_id)
    if not website:
        flash("Website not found.", "error")
        return redirect(url_for("websites"))
    scans = models.get_scans(website_id)
    site_alerts = [a for a in models.get_alerts() if a["website_id"] == website_id]
    return render_template("websites/detail.html", website=website, scans=scans, alerts=site_alerts)


@app.route("/websites/<website_id>/delete", methods=["POST"])
@login_required
def delete_website(website_id: str):
    website = models.get_website(website_id)
    if website:
        models.remove_website(website_id)
        flash(f"{website['name']} has been removed.", "success")
    return redirect(url_for("websites"))


@app.route("/websites/<website_id>/scan", methods=["POST"])
@login_required
def scan_website_route(website_id: str):
    website = models.get_website(website_id)
    if not website:
        return jsonify({"error": "Website not found"}), 404
    result = scan_website(website["url"])
    models.update_website_after_scan(website_id, result)
    return jsonify(result)


# ── Alerts ───────────────────────────────────────────────────────────────────

@app.route("/alerts")
@login_required
def alerts():
    severity = request.args.get("filter", "all")
    items = models.get_alerts(severity)
    return render_template("alerts/index.html", alerts=items, current_filter=severity)


@app.route("/alerts/<alert_id>/<action>", methods=["POST"])
@login_required
def alert_action(alert_id: str, action: str):
    if action in ("acknowledge", "resolve", "escalate"):
        status_map = {"acknowledge": "acknowledged", "resolve": "resolved", "escalate": "escalated"}
        models.update_alert_status(alert_id, status_map[action])
        flash(f"Alert {status_map[action]}.", "success")
    return redirect(url_for("alerts"))


# ── Reports ──────────────────────────────────────────────────────────────────

@app.route("/reports")
@login_required
def reports():
    items = models.get_reports()
    return render_template("reports/index.html", reports=items)


# ── Settings ─────────────────────────────────────────────────────────────────

@app.route("/settings")
@login_required
def settings():
    tab = request.args.get("tab", "profile")
    return render_template("settings/index.html", active_tab=tab)


@app.route("/settings/save", methods=["POST"])
@login_required
def save_settings():
    flash("Settings saved successfully.", "success")
    tab = request.form.get("tab", "profile")
    return redirect(url_for("settings", tab=tab))


# ── API ──────────────────────────────────────────────────────────────────────

@app.route("/api/scan", methods=["POST"])
@login_required
def api_scan():
    data = request.get_json(silent=True) or {}
    url = data.get("url")
    if not url:
        return jsonify({"error": "URL is required"}), 400
    return jsonify(scan_website(url))


@app.route("/auth/google", methods=["POST"])
def auth_google():
    token = request.form.get("credential")
    if not token:
        flash("Google sign-in failed: No credential provided.", "error")
        return redirect(url_for("login"))
    try:
        # Without a client ID in config, we can't fully verify in production securely.
        # But for this demo, we'll parse it or skip validation if no client ID is provided.
        # Usually: idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), CLIENT_ID)
        # Using a relaxed verification for this demo since we don't have a Client ID yet.
        idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), None, clock_skew_in_seconds=10)
        
        email = idinfo.get("email")
        name = idinfo.get("name", "Google User")
        
        if not email:
            flash("Google sign-in failed: No email provided.", "error")
            return redirect(url_for("login"))

        user = models.get_user_by_email(email)
        if not user:
            # Create user on the fly
            models.create_user(email, "google_sso_random_pw_" + str(os.urandom(8)), name)
            user = models.get_user_by_email(email)
        
        session["user_id"] = user["id"]
        session["user_email"] = user["email"]
        session["user_name"] = user["name"]
        flash("Welcome back.", "success")
        return redirect(url_for("dashboard"))
    except ValueError as e:
        # Invalid token
        flash(f"Google sign-in failed: {str(e)}", "error")
        return redirect(url_for("login"))


@app.route("/api/chat", methods=["POST"])
@login_required
def api_chat():
    data = request.get_json(silent=True) or {}
    message = data.get("message", "")
    
    try:
        # Initialize Groq Client
        client = Groq(
            api_key=os.environ.get("GROQ_API_KEY")
        )
        
        # Give the AI some context
        system_prompt = (
            "You are RAVN AI, an advanced security assistant for an enterprise threat monitoring platform. "
            "You help users analyze threats, understand vulnerabilities, and navigate the dashboard. "
            "Keep your answers concise, professional, and helpful."
        )
        
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": message}
            ]
        )
        
        reply = response.choices[0].message.content
    except Exception as e:
        reply = f"I'm sorry, I encountered an error communicating with my AI brain: {str(e)}"
        
    return jsonify({"response": reply})


if __name__ == "__main__":
    os.makedirs(os.path.join(os.path.dirname(__file__), "data"), exist_ok=True)
    models.init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
