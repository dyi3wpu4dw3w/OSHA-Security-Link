import os  
from functools import wraps
from flask import Flask, render_template, request, abort, redirect, url_for, session
from secrets import token_urlsafe
from datetime import datetime, timezone
from threading import Lock

app = Flask(__name__)
app.secret_key = os.environ["YOSHA_SECRET_KEY"]

links = {}
sessions = {}
lock = Lock()
def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper


@app.route("/login", methods=["GET", "POST"])
def login():
    import hmac

    if request.method == "POST":
        password = request.form.get("password", "")

        if hmac.compare_digest(
            password,
            os.environ.get("YOSHA_ADMIN_PASSWORD", "")
        ):
            session["admin_logged_in"] = True
            return redirect(url_for("home"))

        return render_template("login.html", error="كلمة المرور غير صحيحة")

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))
@app.route("/")
@admin_required
def home():
    with lock:
        total = len(links)
        visits = sum(item["visits"] for item in links.values())

    return render_template(
        "dashboard.html",
        total=total,
        visits=visits,
        links=links
    )


@app.route("/create", methods=["POST"])
def create_link():
    title = request.form.get("title", "").strip()

    if not title or len(title) > 80:
        abort(400, "عنوان غير صالح")

    token = token_urlsafe(16)

    with lock:
        links[token] = {
            "title": title,
            "visits": 0,
            "created": datetime.now(timezone.utc).strftime(
                "%Y-%m-%d %H:%M UTC"
            )
        }

    return render_template(
        "created.html",
        url=request.url_root.rstrip("/") + "/test/" + token
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

    return render_template(
        "live_dashboard.html",
        sessions=current_sessions
    )


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
        "camera_invite",
        invite_token=invite_token,
        _external=True
    )

    return {
        "message": "تم إنشاء جلسة الدعوة",
        "session_id": session_id,
        "invite_url": invite_url,
        "status": "awaiting_camera"
    }

@app.route("/session/<session_id>/stop", methods=["POST"])
@admin_required
def stop_session(session_id):
    with lock:
        session = sessions.get(session_id)

        if session is None:
            abort(404)

        session["status"] = "stopped"

    return {"message": "تم إنهاء الجلسة"}


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )

