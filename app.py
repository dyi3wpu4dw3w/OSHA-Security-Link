import hmac
import os
from datetime import datetime, timezone
from functools import wraps
from secrets import token_urlsafe
from threading import Lock

from flask import (
    Flask, abort, jsonify, redirect, render_template, request,
    session, url_for
)

secret_key = os.environ.get("YOSHA_SECRET_KEY")
if not secret_key:
    raise RuntimeError("YOSHA_SECRET_KEY must be configured before startup.")

app = Flask(__name__)
app.secret_key = secret_key
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1") == "1",
    MAX_CONTENT_LENGTH=1024 * 1024,
)

links = {}
sessions = {}
lock = Lock()


def csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = token_urlsafe(32)
        session["_csrf_token"] = token
    return token


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": csrf_token}


@app.before_request
def protect_post_requests():
    if request.method == "POST":
        submitted = request.form.get("csrf_token", "")
        expected = session.get("_csrf_token", "")
        if not expected or not submitted or not hmac.compare_digest(
            submitted, expected
        ):
            abort(400, "طلب غير صالح أو انتهت صلاحيته. حدّث الصفحة وحاول مجدداً.")


def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault(
        "Permissions-Policy",
        "camera=(self), microphone=(), geolocation=()"
    )
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; "
        "form-action 'self'"
    )
    return response


@app.get("/healthz")
def healthz():
    return jsonify({"status": "ok"}), 200


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        password = request.form.get("password", "")
        configured_password = os.environ.get("YOSHA_ADMIN_PASSWORD", "")

        if configured_password and hmac.compare_digest(
            password, configured_password
        ):
            session.clear()
            session["admin_logged_in"] = True
            csrf_token()
            return redirect(url_for("home"))

        return render_template(
            "login.html", error="بيانات الدخول غير صحيحة أو لم يتم إعداد كلمة المرور."
        ), 401

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@admin_required
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@admin_required
def home():
    with lock:
        total = len(links)
        visits = sum(item["visits"] for item in links.values())
        current_links = dict(links)

    return render_template(
        "dashboard.html",
        total=total,
        visits=visits,
        links=current_links
    )


@app.route("/create", methods=["POST"])
@admin_required
def create_link():
    title = request.form.get("title", "").strip()
    if not title or len(title) > 80:
        abort(400, "عنوان غير صالح")

    token = token_urlsafe(16)
    with lock:
        links[token] = {
            "title": title,
            "visits": 0,
            "created": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        }

    return render_template(
        "created.html",
        url=request.url_root.rstrip("/") + url_for("test_page", token=token)
    )


@app.route("/test/<token>")
def test_page(token):
    with lock:
        item = links.get(token)
        if item is None:
            abort(404)
        item["visits"] += 1
        title = item["title"]

    return render_template("test.html", title=title)


@app.route("/camera")
def camera_page():
    return render_template("camera.html")


@app.route("/camera/<invite_token>")
def camera_invite(invite_token):
    with lock:
        valid = any(
            item["invite_token"] == invite_token
            and item["status"] == "awaiting_camera"
            for item in sessions.values()
        )
    if not valid:
        abort(404)
    return render_template("camera.html")


@app.route("/live-dashboard")
@admin_required
def live_dashboard():
    with lock:
        current_sessions = dict(sessions)
    return render_template("live_dashboard.html", sessions=current_sessions)


@app.route("/session/create", methods=["POST"])
@admin_required
def create_session():
    session_id = token_urlsafe(16)
    invite_token = token_urlsafe(32)

    with lock:
        sessions[session_id] = {
            "status": "awaiting_camera",
            "created": datetime.now(timezone.utc).isoformat(),
            "duration_limit_hours": None,
            "invite_token": invite_token
        }

    invite_url = url_for(
        "camera_invite", invite_token=invite_token, _external=True
    )
    return jsonify({
        "message": "تم إنشاء جلسة الدعوة",
        "session_id": session_id,
        "invite_url": invite_url,
        "status": "awaiting_camera"
    })


@app.route("/session/<session_id>/stop", methods=["POST"])
@admin_required
def stop_session(session_id):
    with lock:
        current = sessions.get(session_id)
        if current is None:
            abort(404)
        current["status"] = "stopped"
    return jsonify({"message": "تم إنهاء الجلسة"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
