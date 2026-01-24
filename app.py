# ===============================
# app.py — 676Trades Backend
# ===============================

import os, secrets
from datetime import datetime, timedelta, timezone

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import stripe

# -------------------------
# App / Config
# -------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev")

FRONTEND_ORIGINS = ["https://676trades.org", "https://www.676trades.org"]

CORS(app, resources={r"/*": {"origins": FRONTEND_ORIGINS}},
     allow_headers=["Content-Type", "X-API-Key", "X-Admin-Token"])

limiter = Limiter(get_remote_address, app=app, default_limits=["100/minute"])

# -------------------------
# Database
# -------------------------
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///db.sqlite3")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# -------------------------
# Mail (Gmail SMTP)
# -------------------------
app.config.update(
    MAIL_SERVER=os.getenv("MAIL_SERVER"),
    MAIL_PORT=int(os.getenv("MAIL_PORT", "587")),
    MAIL_USE_TLS=os.getenv("MAIL_USE_TLS", "true").lower() == "true",
    MAIL_USERNAME=os.getenv("MAIL_USERNAME"),
    MAIL_PASSWORD=os.getenv("MAIL_PASSWORD"),
    MAIL_DEFAULT_SENDER=os.getenv("MAIL_DEFAULT_SENDER"),
)
mail = Mail(app)

# -------------------------
# Stripe
# -------------------------
stripe.api_key = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_PRICE_ID = os.getenv("STRIPE_PRICE_ID", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
APP_BASE_URL = os.getenv("APP_BASE_URL", "https://676trades.org")
TRIAL_DAYS = 5

ADMIN_TOKEN = os.getenv("ADMIN_TOKEN")

# -------------------------
# Models
# -------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    api_key = db.Column(db.String(64), unique=True, nullable=False)
    enabled = db.Column(db.Boolean, default=False)

    pairs = db.Column(db.String(255), default="XAUUSD")
    lot_size = db.Column(db.Float, default=0.01)

    sl_mode = db.Column(db.String(20), default="dynamic")
    tp_mode = db.Column(db.String(20), default="rr")

    min_pips = db.Column(db.Integer, default=50)
    sl_buffer_pips = db.Column(db.Integer, default=5)
    rr = db.Column(db.Float, default=1.0)
    pattern_tp_mult = db.Column(db.Float, default=1.5)
    fixed_sl_pips = db.Column(db.Integer, default=50)
    fixed_tp_pips = db.Column(db.Integer, default=50)

    plan = db.Column(db.String(20), default="free")
    subscription_status = db.Column(db.String(30), default="none")
    trial_ends_at = db.Column(db.DateTime)

    stripe_customer_id = db.Column(db.String(80))
    stripe_subscription_id = db.Column(db.String(80))

    reset_token = db.Column(db.String(64))
    reset_token_expires = db.Column(db.DateTime)

    last_seen_at = db.Column(db.DateTime)
    last_seen_ip = db.Column(db.String(64))

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_login_at = db.Column(db.DateTime)

class Trade(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    symbol = db.Column(db.String(20))
    side = db.Column(db.String(10))
    volume = db.Column(db.Float)
    entry = db.Column(db.Float)
    sl = db.Column(db.Float)
    tp = db.Column(db.Float)
    profit = db.Column(db.Float)
    opened_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

# -------------------------
# Helpers
# -------------------------
def json_error(msg, code=400):
    return jsonify({"ok": False, "error": msg}), code

def require_api_key():
    key = request.headers.get("X-API-Key", "")
    user = User.query.filter_by(api_key=key).first()
    if not user:
        return None, json_error("Invalid API key", 401)
    return user, None

def require_admin():
    if request.headers.get("X-Admin-Token") != ADMIN_TOKEN:
        return json_error("Admin unauthorized", 401)
    return None

# -------------------------
# Auth Routes
# -------------------------
@app.post("/auth/register")
def register():
    d = request.json or {}
    email = d.get("email","").lower()
    pw = d.get("password","")

    if not email or not pw:
        return json_error("Missing email or password")

    user = User(
        email=email,
        password_hash=generate_password_hash(pw),
        api_key=secrets.token_hex(24),
        trial_ends_at=datetime.now(timezone.utc) + timedelta(days=TRIAL_DAYS)
    )

    try:
        db.session.add(user)
        db.session.commit()
    except IntegrityError:
        return json_error("Email already registered", 409)

    return jsonify({"ok": True, "api_key": user.api_key})

@app.post("/auth/login")
def login():
    d = request.json or {}
    user = User.query.filter_by(email=d.get("email","").lower()).first()
    if not user or not check_password_hash(user.password_hash, d.get("password","")):
        return json_error("Invalid login", 401)

    user.last_login_at = datetime.now(timezone.utc)
    db.session.commit()
    return jsonify({"ok": True, "api_key": user.api_key})

# -------------------------
# Password Reset (EMAIL)
# -------------------------
@app.post("/auth/forgot-password")
def forgot_password():
    email = (request.json or {}).get("email","").lower()
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"ok": True})

    token = secrets.token_urlsafe(32)
    user.reset_token = token
    user.reset_token_expires = datetime.now(timezone.utc) + timedelta(minutes=30)
    db.session.commit()

    reset_url = f"{APP_BASE_URL}/reset-password.html?token={token}"

    msg = Message("Reset your 676Trades password",
        recipients=[user.email],
        body=f"Reset your password:\n\n{reset_url}\n\nLink expires in 30 minutes."
    )
    mail.send(msg)
    return jsonify({"ok": True})

@app.post("/auth/reset-password")
def reset_password():
    d = request.json or {}
    user = User.query.filter_by(reset_token=d.get("token")).first()

    if not user or user.reset_token_expires < datetime.now(timezone.utc):
        return json_error("Invalid or expired token", 400)

    user.password_hash = generate_password_hash(d.get("password"))
    user.reset_token = None
    user.reset_token_expires = None
    db.session.commit()
    return jsonify({"ok": True})

# -------------------------
# EA Status
# -------------------------
@app.get("/api/v1/status")
def status():
    user, err = require_api_key()
    if err: return err

    user.last_seen_at = datetime.now(timezone.utc)
    user.last_seen_ip = request.remote_addr
    db.session.commit()

    return jsonify({
        "ok": True,
        "enabled": user.enabled,
        "pairs": user.pairs,
        "lot_size": user.lot_size,
        "sl_mode": user.sl_mode,
        "tp_mode": user.tp_mode,
        "min_pips": user.min_pips,
        "sl_buffer_pips": user.sl_buffer_pips,
        "rr": user.rr,
        "pattern_tp_mult": user.pattern_tp_mult,
        "fixed_sl_pips": user.fixed_sl_pips,
        "fixed_tp_pips": user.fixed_tp_pips,
        "ea_connected": True,
        "last_seen_at": user.last_seen_at.isoformat()
    })

# -------------------------
# Admin Endpoints
# -------------------------
@app.get("/admin/users")
def admin_users():
    if require_admin(): return require_admin()
    users = User.query.order_by(User.id.desc()).all()

    return jsonify({
        "items": [{
            "id": u.id,
            "email": u.email,
            "plan": u.plan,
            "subscription_status": u.subscription_status,
            "enabled": u.enabled,
            "pairs": u.pairs,
            "online": bool(u.last_seen_at and datetime.now(timezone.utc) - u.last_seen_at < timedelta(minutes=5)),
            "last_seen_at": u.last_seen_at.isoformat() if u.last_seen_at else None
        } for u in users]
    })

@app.post("/admin/user/<int:uid>/override")
def admin_override(uid):
    if require_admin(): return require_admin()
    u = User.query.get_or_404(uid)
    d = request.json or {}

    for k in ["pairs","lot_size","min_pips","rr","enabled"]:
        if k in d: setattr(u, k, d[k])

    db.session.commit()
    return jsonify({"ok": True})

@app.post("/admin/user/<int:uid>/rotate-key")
def admin_rotate(uid):
    if require_admin(): return require_admin()
    u = User.query.get_or_404(uid)
    u.api_key = secrets.token_hex(24)
    db.session.commit()
    return jsonify({"ok": True})

@app.post("/admin/user/<int:uid>/set-plan")
def admin_plan(uid):
    if require_admin(): return require_admin()
    u = User.query.get_or_404(uid)
    d = request.json or {}
    u.plan = d.get("plan","free")
    u.subscription_status = d.get("subscription_status","none")
    db.session.commit()
    return jsonify({"ok": True})

# -------------------------
# Init
# -------------------------
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run()
