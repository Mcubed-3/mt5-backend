# app.py
import os
import secrets
import hashlib
from datetime import datetime, timezone, timedelta

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_mail import Mail, Message

from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError
from sqlalchemy import text

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import stripe


# ============================================================
# App / Config
# ============================================================
app = Flask(__name__)

# ---- Security secret (used for Flask-Mail + misc) ----
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", secrets.token_hex(16))

# ---- CORS ----
FRONTEND_ORIGINS = ["https://676trades.org", "https://www.676trades.org"]
CORS(
    app,
    resources={r"/*": {"origins": FRONTEND_ORIGINS}},
    allow_headers=["Content-Type", "X-API-Key", "X-Admin-Token"],
    methods=["GET", "POST", "OPTIONS"],
)

# ---- Rate limiting ----
limiter = Limiter(get_remote_address, app=app, default_limits=["60 per minute"])

# ---- Database ----
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///db.sqlite3")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# ---- Mail (Password reset) ----
# Works with Gmail SMTP *if you use an App Password* (recommended).
app.config["MAIL_SERVER"] = os.getenv("MAIL_SERVER", "").strip()
app.config["MAIL_PORT"] = int(os.getenv("MAIL_PORT", "587"))
app.config["MAIL_USE_TLS"] = os.getenv("MAIL_USE_TLS", "true").lower() == "true"
app.config["MAIL_USE_SSL"] = os.getenv("MAIL_USE_SSL", "false").lower() == "true"
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME", "").strip()
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD", "").strip()
app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_DEFAULT_SENDER", app.config["MAIL_USERNAME"]).strip()

mail = Mail(app)

# ---- Stripe ----
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "").strip()
STRIPE_PRICE_ID = os.getenv("STRIPE_PRICE_ID", "").strip()  # must be price_...
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "").strip()
APP_BASE_URL = os.getenv("APP_BASE_URL", "https://676trades.org").strip()  # frontend base url
TRIAL_DAYS = int(os.getenv("TRIAL_DAYS", "5"))

if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

# ---- Admin ----
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "").strip()
ADMIN_ALLOWED_IPS = os.getenv("ADMIN_ALLOWED_IPS", "").strip()  # comma-separated public IPs
ADMIN_ENABLED = bool(ADMIN_TOKEN)

# Heartbeat window (minutes) for "connected"
HEARTBEAT_WINDOW_MIN = int(os.getenv("HEARTBEAT_WINDOW_MIN", "5"))


# ============================================================
# Models
# ============================================================
class User(db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)

    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)

    api_key = db.Column(db.String(64), unique=True, nullable=False, index=True)

    enabled = db.Column(db.Boolean, default=False, nullable=False)

    # Multi symbols CSV (and backward compatible single symbol)
    pair = db.Column(db.String(20), default="XAUUSD", nullable=False)
    pairs = db.Column(db.String(255), default="XAUUSD", nullable=False)

    lot_size = db.Column(db.Float, default=0.01, nullable=False)

    # SL/TP settings
    sl_mode = db.Column(db.String(20), default="dynamic", nullable=False)
    tp_mode = db.Column(db.String(20), default="rr", nullable=False)

    min_pips = db.Column(db.Integer, default=50, nullable=False)
    sl_buffer_pips = db.Column(db.Integer, default=5, nullable=False)

    rr = db.Column(db.Float, default=1.0, nullable=False)
    pattern_tp_mult = db.Column(db.Float, default=1.5, nullable=False)

    fixed_sl_pips = db.Column(db.Integer, default=50, nullable=False)
    fixed_tp_pips = db.Column(db.Integer, default=50, nullable=False)

    # Profile
    display_name = db.Column(db.String(80), nullable=True)

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    last_login_at = db.Column(db.DateTime, nullable=True)
    last_settings_at = db.Column(db.DateTime, nullable=True)

    # Password reset
    reset_token = db.Column(db.String(120), nullable=True, index=True)
    reset_token_expires_at = db.Column(db.DateTime, nullable=True)

    # Billing
    plan = db.Column(db.String(20), default="free", nullable=False)  # free / pro
    subscription_status = db.Column(db.String(30), default="none", nullable=False)  # none/active/past_due/canceled
    trial_ends_at = db.Column(db.DateTime, nullable=True)

    stripe_customer_id = db.Column(db.String(80), nullable=True, index=True)
    stripe_subscription_id = db.Column(db.String(80), nullable=True, index=True)

    # Heartbeat / MT5 presence
    last_seen_at = db.Column(db.DateTime, nullable=True)
    last_seen_symbol = db.Column(db.String(20), nullable=True)
    last_seen_tf = db.Column(db.String(20), nullable=True)
    last_seen_ip = db.Column(db.String(64), nullable=True)


class Trade(db.Model):
    __tablename__ = "trade"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), index=True, nullable=False)
    user = db.relationship("User", backref="trades")

    symbol = db.Column(db.String(20), nullable=False)
    side = db.Column(db.String(10), nullable=False)

    volume = db.Column(db.Float, nullable=False)
    entry = db.Column(db.Float, nullable=True)
    sl = db.Column(db.Float, nullable=True)
    tp = db.Column(db.Float, nullable=True)

    deal_id = db.Column(db.String(64), nullable=True, index=True)
    profit = db.Column(db.Float, nullable=True)

    opened_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)


class AuditLog(db.Model):
    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True)
    at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    actor = db.Column(db.String(40), default="admin", nullable=False)  # "admin" for now
    action = db.Column(db.String(80), nullable=False)

    target_user_id = db.Column(db.Integer, nullable=True, index=True)
    target_email = db.Column(db.String(255), nullable=True)

    ip = db.Column(db.String(64), nullable=True)
    meta = db.Column(db.String(2000), nullable=True)


# ============================================================
# Helpers
# ============================================================
def json_error(message: str, code: int = 400):
    return jsonify({"ok": False, "error": message}), code


def safe_float(v, default=None):
    try:
        return float(v)
    except Exception:
        return default


def safe_int(v, default=None):
    try:
        return int(v)
    except Exception:
        return default


def now_utc():
    return datetime.now(timezone.utc)


def normalize_dt(dt):
    if not dt:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def normalize_pairs(value: str) -> str:
    parts = [p.strip().upper() for p in (value or "").split(",")]
    parts = [p for p in parts if p]
    for p in parts:
        if len(p) < 3 or len(p) > 12:
            raise ValueError("pair looks invalid")
    seen = set()
    out = []
    for p in parts:
        if p not in seen:
            seen.add(p)
            out.append(p)
    if not out:
        raise ValueError("pairs cannot be empty")
    return ",".join(out)


def first_pair(pairs_csv: str) -> str:
    try:
        return (pairs_csv or "XAUUSD").split(",")[0].strip().upper() or "XAUUSD"
    except Exception:
        return "XAUUSD"


def require_api_key():
    api_key = request.headers.get("X-API-Key", "").strip()
    if not api_key:
        return None, json_error("Missing X-API-Key header", 401)

    user = User.query.filter_by(api_key=api_key).first()
    if not user:
        return None, json_error("Invalid API key", 401)

    return user, None


def trial_active(user: User) -> bool:
    if not user.trial_ends_at:
        return False
    t = normalize_dt(user.trial_ends_at)
    return now_utc() < t


def is_paid_active(user: User) -> bool:
    return user.subscription_status == "active"


def ensure_can_trade(user: User):
    # allow if paid active OR trial still active
    if is_paid_active(user) or trial_active(user):
        return None

    # force disabled for unpaid
    if user.enabled:
        user.enabled = False
        db.session.commit()

    return json_error("Payment required. Please start your free trial / subscribe.", 402)


def heartbeat_connected(user: User) -> bool:
    if not user.last_seen_at:
        return False
    t = normalize_dt(user.last_seen_at)
    return now_utc() - t <= timedelta(minutes=HEARTBEAT_WINDOW_MIN)


def client_ip():
    """
    Render / proxies often set X-Forwarded-For: "client, proxy1, proxy2"
    We want the first.
    """
    xff = (request.headers.get("X-Forwarded-For") or "").strip()
    if xff:
        return xff.split(",")[0].strip()
    return (request.remote_addr or "").strip()


def admin_ip_required():
    if not ADMIN_ALLOWED_IPS:
        # If you didn't set ADMIN_ALLOWED_IPS, we don't block by IP
        return None

    allowed = [x.strip() for x in ADMIN_ALLOWED_IPS.split(",") if x.strip()]
    if not allowed:
        return None

    ip = client_ip()
    if ip not in allowed:
        return json_error("Forbidden (IP not allowed).", 403)
    return None


def require_admin():
    if not ADMIN_ENABLED:
        return json_error("Admin is not configured on server.", 500)

    # Require token
    token = request.headers.get("X-Admin-Token", "").strip()
    if not token or token != ADMIN_TOKEN:
        return json_error("Forbidden (bad admin token).", 403)

    # Require allowed IP (if configured)
    ip_err = admin_ip_required()
    if ip_err:
        return ip_err

    return None


def audit(action: str, target_user: User | None = None, meta: str | None = None):
    try:
        ip = client_ip()
        row = AuditLog(
            action=action,
            target_user_id=(target_user.id if target_user else None),
            target_email=(target_user.email if target_user else None),
            ip=ip,
            meta=(meta[:2000] if meta else None),
        )
        db.session.add(row)
        db.session.commit()
    except Exception:
        # never break production flow for audit log
        db.session.rollback()


def send_reset_email(to_email: str, reset_url: str):
    # If mail isn't configured, we fail clearly.
    if not app.config["MAIL_SERVER"] or not app.config["MAIL_USERNAME"] or not app.config["MAIL_PASSWORD"]:
        raise RuntimeError("Mail not configured on server.")

    subject = "Reset your 676Trades password"
    body = (
        "You requested a password reset.\n\n"
        f"Reset link:\n{reset_url}\n\n"
        "If you didn’t request this, you can ignore this email.\n"
    )
    msg = Message(subject=subject, recipients=[to_email], body=body)
    mail.send(msg)


# ============================================================
# Auto-migration (Postgres-safe)
# ============================================================
def ensure_schema():
    uri = app.config["SQLALCHEMY_DATABASE_URI"]
    is_postgres = uri.startswith("postgresql")
    if not is_postgres:
        db.create_all()
        return

    with db.engine.begin() as conn:
        conn.execute(text("""CREATE TABLE IF NOT EXISTS "user" (id SERIAL PRIMARY KEY)"""))

        cols = {
            r[0] for r in conn.execute(text("""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_schema='public' AND table_name='user'
            """)).fetchall()
        }

        def add_col(sql): conn.execute(text(sql))

        # base
        if "email" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN email VARCHAR(255)')
            add_col('CREATE UNIQUE INDEX IF NOT EXISTS ix_user_email ON "user"(email)')
        if "password_hash" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN password_hash VARCHAR(255)')
        if "api_key" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN api_key VARCHAR(64)')
            add_col('CREATE UNIQUE INDEX IF NOT EXISTS ix_user_api_key ON "user"(api_key)')
        if "enabled" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN enabled BOOLEAN NOT NULL DEFAULT FALSE')

        if "pair" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN pair VARCHAR(20) NOT NULL DEFAULT \'XAUUSD\'')
        if "pairs" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN pairs VARCHAR(255) NOT NULL DEFAULT \'XAUUSD\'')
        if "lot_size" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN lot_size DOUBLE PRECISION NOT NULL DEFAULT 0.01')

        if "display_name" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN display_name VARCHAR(80) NULL')

        if "created_at" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()')
        if "last_login_at" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN last_login_at TIMESTAMPTZ NULL')
        if "last_settings_at" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN last_settings_at TIMESTAMPTZ NULL')

        # sl/tp
        if "sl_mode" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN sl_mode VARCHAR(20) NOT NULL DEFAULT \'dynamic\'')
        if "tp_mode" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN tp_mode VARCHAR(20) NOT NULL DEFAULT \'rr\'')
        if "min_pips" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN min_pips INTEGER NOT NULL DEFAULT 50')
        if "sl_buffer_pips" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN sl_buffer_pips INTEGER NOT NULL DEFAULT 5')
        if "rr" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN rr DOUBLE PRECISION NOT NULL DEFAULT 1.0')
        if "pattern_tp_mult" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN pattern_tp_mult DOUBLE PRECISION NOT NULL DEFAULT 1.5')
        if "fixed_sl_pips" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN fixed_sl_pips INTEGER NOT NULL DEFAULT 50')
        if "fixed_tp_pips" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN fixed_tp_pips INTEGER NOT NULL DEFAULT 50')

        # password reset fields
        if "reset_token" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN reset_token VARCHAR(120) NULL')
            add_col('CREATE INDEX IF NOT EXISTS ix_user_reset_token ON "user"(reset_token)')
        if "reset_token_expires_at" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN reset_token_expires_at TIMESTAMPTZ NULL')

        # billing
        if "plan" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN plan VARCHAR(20) NOT NULL DEFAULT \'free\'')
        if "subscription_status" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN subscription_status VARCHAR(30) NOT NULL DEFAULT \'none\'')
        if "trial_ends_at" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN trial_ends_at TIMESTAMPTZ NULL')
        if "stripe_customer_id" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN stripe_customer_id VARCHAR(80) NULL')
            add_col('CREATE INDEX IF NOT EXISTS ix_user_stripe_customer_id ON "user"(stripe_customer_id)')
        if "stripe_subscription_id" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN stripe_subscription_id VARCHAR(80) NULL')
            add_col('CREATE INDEX IF NOT EXISTS ix_user_stripe_subscription_id ON "user"(stripe_subscription_id)')

        # heartbeat
        if "last_seen_at" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN last_seen_at TIMESTAMPTZ NULL')
        if "last_seen_symbol" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN last_seen_symbol VARCHAR(20) NULL')
        if "last_seen_tf" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN last_seen_tf VARCHAR(20) NULL')
        if "last_seen_ip" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN last_seen_ip VARCHAR(64) NULL')

        # trade table
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS trade (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES "user"(id),
                symbol VARCHAR(20) NOT NULL,
                side VARCHAR(10) NOT NULL,
                volume DOUBLE PRECISION NOT NULL,
                entry DOUBLE PRECISION NULL,
                sl DOUBLE PRECISION NULL,
                tp DOUBLE PRECISION NULL,
                deal_id VARCHAR(64) NULL,
                profit DOUBLE PRECISION NULL,
                opened_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """))
        conn.execute(text('CREATE INDEX IF NOT EXISTS ix_trade_user_id ON trade(user_id)'))
        conn.execute(text('CREATE INDEX IF NOT EXISTS ix_trade_deal_id ON trade(deal_id)'))

        # audit_log table
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id SERIAL PRIMARY KEY,
                at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                actor VARCHAR(40) NOT NULL DEFAULT 'admin',
                action VARCHAR(80) NOT NULL,
                target_user_id INTEGER NULL,
                target_email VARCHAR(255) NULL,
                ip VARCHAR(64) NULL,
                meta VARCHAR(2000) NULL
            )
        """))
        conn.execute(text('CREATE INDEX IF NOT EXISTS ix_audit_target_user_id ON audit_log(target_user_id)'))
        conn.execute(text('CREATE INDEX IF NOT EXISTS ix_audit_at ON audit_log(at)'))


# ============================================================
# Routes: Health
# ============================================================
@app.get("/")
def root():
    return jsonify({"ok": True, "service": "mt5-control-backend", "version": "v1"})


@app.get("/health")
def health():
    return jsonify({"ok": True})


# ============================================================
# Routes: Auth
# ============================================================
@app.post("/auth/register")
@limiter.limit("10 per hour")
def register():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = (data.get("password") or "").strip()

    if not email or not password:
        return json_error("Email and password required", 400)

    api_key = secrets.token_hex(24)

    user = User(
        email=email,
        password_hash=generate_password_hash(password),
        api_key=api_key,
        enabled=False,
        pair="XAUUSD",
        pairs="XAUUSD",
        lot_size=0.01,
        plan="free",
        subscription_status="none",
    )

    try:
        db.session.add(user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return json_error("Email already registered", 409)

    return jsonify({"ok": True, "message": "Registered", "api_key": api_key})


@app.post("/auth/login")
@limiter.limit("30 per hour")
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = (data.get("password") or "").strip()

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        return json_error("Invalid email or password", 401)

    user.last_login_at = now_utc()
    db.session.commit()

    return jsonify({"ok": True, "api_key": user.api_key})


@app.post("/auth/rotate-key")
@limiter.limit("10 per hour")
def rotate_key():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = (data.get("password") or "").strip()

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        return json_error("Invalid email or password", 401)

    user.api_key = secrets.token_hex(24)
    user.enabled = False  # safety
    db.session.commit()

    return jsonify({"ok": True, "api_key": user.api_key})


# ---- Password reset (Phase 1 Step 2) ----
@app.post("/auth/forgot-password")
@limiter.limit("10 per hour")
def forgot_password():
    """
    Takes { email }
    Always returns ok=true (to prevent email enumeration), but logs real errors server-side.
    """
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()

    # Always respond ok to avoid leaking whether an email exists
    if not email:
        return jsonify({"ok": True})

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"ok": True})

    # create token
    token = secrets.token_urlsafe(32)
    user.reset_token = token
    user.reset_token_expires_at = now_utc() + timedelta(minutes=30)
    db.session.commit()

    # link to frontend reset page (you can create reset-password.html later)
    reset_url = f"{APP_BASE_URL}/reset-password.html?token={token}"

    try:
        send_reset_email(user.email, reset_url)
    except Exception as e:
        # keep response ok, but make it visible in Render logs
        print("MAIL ERROR:", str(e))

    return jsonify({"ok": True})


@app.post("/auth/reset-password")
@limiter.limit("10 per hour")
def reset_password():
    """
    Takes { token, new_password }
    """
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    new_password = (data.get("new_password") or "").strip()

    if not token or not new_password:
        return json_error("token and new_password required", 400)

    user = User.query.filter_by(reset_token=token).first()
    if not user:
        return json_error("Invalid or expired token", 400)

    exp = normalize_dt(user.reset_token_expires_at)
    if not exp or now_utc() > exp:
        return json_error("Invalid or expired token", 400)

    user.password_hash = generate_password_hash(new_password)
    user.reset_token = None
    user.reset_token_expires_at = None

    # security: rotate api key so old key can't be used if compromised
    user.api_key = secrets.token_hex(24)
    user.enabled = False

    db.session.commit()

    return jsonify({"ok": True, "message": "Password reset. Please login again."})


# ============================================================
# Routes: Account (for account2.html)
# ============================================================
@app.get("/account/me")
@limiter.limit("60 per minute")
def account_me():
    user, err = require_api_key()
    if err:
        return err

    return jsonify({
        "ok": True,
        "id": user.id,
        "email": user.email,
        "display_name": user.display_name,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
        "plan": user.plan,
        "subscription_status": user.subscription_status,
        "trial_ends_at": user.trial_ends_at.isoformat() if user.trial_ends_at else None,
    })


@app.post("/account/profile")
@limiter.limit("60 per minute")
def account_profile():
    user, err = require_api_key()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    display_name = (data.get("display_name") or "").strip()

    if display_name and len(display_name) > 80:
        return json_error("display_name too long", 400)

    user.display_name = display_name or None
    db.session.commit()
    return jsonify({"ok": True})


# ============================================================
# Routes: Control (EA + Dashboard)
# ============================================================
@app.get("/api/v1/status")
@limiter.limit("120 per minute")
def status():
    user, err = require_api_key()
    if err:
        return err

    pairs_csv = (user.pairs or user.pair or "XAUUSD").strip() or "XAUUSD"

    return jsonify({
        "ok": True,
        "enabled": bool(user.enabled),

        "pair": first_pair(pairs_csv),
        "pairs": pairs_csv,

        "lot_size": float(user.lot_size),

        "sl_mode": user.sl_mode,
        "tp_mode": user.tp_mode,
        "min_pips": int(user.min_pips),
        "sl_buffer_pips": int(user.sl_buffer_pips),
        "rr": float(user.rr),
        "pattern_tp_mult": float(user.pattern_tp_mult),
        "fixed_sl_pips": int(user.fixed_sl_pips),
        "fixed_tp_pips": int(user.fixed_tp_pips),

        # billing snapshot
        "plan": user.plan,
        "subscription_status": user.subscription_status,
        "trial_ends_at": user.trial_ends_at.isoformat() if user.trial_ends_at else None,

        # heartbeat snapshot
        "ea_connected": heartbeat_connected(user),
        "last_seen_at": user.last_seen_at.isoformat() if user.last_seen_at else None,
        "last_seen_symbol": user.last_seen_symbol,
        "last_seen_tf": user.last_seen_tf,
    })


@app.post("/api/v1/toggle")
@limiter.limit("60 per minute")
def toggle():
    user, err = require_api_key()
    if err:
        return err

    pay_err = ensure_can_trade(user)
    if pay_err:
        return pay_err

    data = request.get_json(silent=True) or {}
    enabled = data.get("enabled", None)

    if enabled is not None:
        user.enabled = bool(enabled)
    else:
        user.enabled = not user.enabled

    db.session.commit()
    return jsonify({"ok": True, "enabled": bool(user.enabled)})


@app.post("/api/v1/settings")
@limiter.limit("60 per minute")
def settings():
    user, err = require_api_key()
    if err:
        return err

    pay_err = ensure_can_trade(user)
    if pay_err:
        return pay_err

    data = request.get_json(silent=True) or {}

    # accept "pairs" OR "pair"
    if "pairs" in data:
        try:
            user.pairs = normalize_pairs(str(data["pairs"]))
            user.pair = first_pair(user.pairs)
        except ValueError as e:
            return json_error(str(e), 400)

    if "pair" in data and "pairs" not in data:
        try:
            single = normalize_pairs(str(data["pair"]))
            user.pairs = single
            user.pair = first_pair(single)
        except ValueError as e:
            return json_error(str(e), 400)

    if "lot_size" in data:
        lot = safe_float(data["lot_size"])
        if lot is None:
            return json_error("lot_size must be a number", 400)
        if lot <= 0 or lot > 100:
            return json_error("lot_size out of range", 400)
        user.lot_size = lot

    if "sl_mode" in data:
        sl_mode = str(data["sl_mode"]).strip().lower()
        if sl_mode not in ("dynamic", "fixed"):
            return json_error("sl_mode must be dynamic or fixed", 400)
        user.sl_mode = sl_mode

    if "tp_mode" in data:
        tp_mode = str(data["tp_mode"]).strip().lower()
        if tp_mode not in ("rr", "pattern_mult", "fixed"):
            return json_error("tp_mode must be rr, pattern_mult, or fixed", 400)
        user.tp_mode = tp_mode

    if "min_pips" in data:
        v = safe_int(data["min_pips"])
        if v is None or v < 1 or v > 5000:
            return json_error("min_pips out of range", 400)
        user.min_pips = v

    if "sl_buffer_pips" in data:
        v = safe_int(data["sl_buffer_pips"])
        if v is None or v < 0 or v > 500:
            return json_error("sl_buffer_pips out of range", 400)
        user.sl_buffer_pips = v

    if "rr" in data:
        v = safe_float(data["rr"])
        if v is None or v < 0.1 or v > 20:
            return json_error("rr out of range", 400)
        user.rr = v

    if "pattern_tp_mult" in data:
        v = safe_float(data["pattern_tp_mult"])
        if v is None or v < 0.1 or v > 20:
            return json_error("pattern_tp_mult out of range", 400)
        user.pattern_tp_mult = v

    if "fixed_sl_pips" in data:
        v = safe_int(data["fixed_sl_pips"])
        if v is None or v < 1 or v > 5000:
            return json_error("fixed_sl_pips out of range", 400)
        user.fixed_sl_pips = v

    if "fixed_tp_pips" in data:
        v = safe_int(data["fixed_tp_pips"])
        if v is None or v < 1 or v > 5000:
            return json_error("fixed_tp_pips out of range", 400)
        user.fixed_tp_pips = v

    user.last_settings_at = now_utc()
    db.session.commit()
    return status()


# ---- Heartbeat endpoint (EA calls this) ----
@app.post("/api/v1/heartbeat")
@limiter.limit("240 per minute")
def heartbeat():
    user, err = require_api_key()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    symbol = (data.get("symbol") or "").strip().upper()
    tf = (data.get("timeframe") or "").strip().upper()

    # store
    user.last_seen_at = now_utc()
    user.last_seen_symbol = symbol[:20] if symbol else None
    user.last_seen_tf = tf[:20] if tf else None
    user.last_seen_ip = client_ip()[:64] if client_ip() else None
    db.session.commit()

    return jsonify({"ok": True})


# ============================================================
# Billing routes (frontend uses X-API-Key)
# ============================================================
@app.get("/billing/status")
@limiter.limit("60 per minute")
def billing_status():
    user, err = require_api_key()
    if err:
        return err

    return jsonify({
        "ok": True,
        "plan": user.plan,
        "subscription_status": user.subscription_status,
        "trial_ends_at": user.trial_ends_at.isoformat() if user.trial_ends_at else None,
        "trial_active": trial_active(user),
    })


@app.post("/billing/create-checkout-session")
@limiter.limit("20 per hour")
def create_checkout_session():
    user, err = require_api_key()
    if err:
        return err

    if not STRIPE_SECRET_KEY or not STRIPE_PRICE_ID:
        return json_error("Stripe not configured on server.", 500)

    # Ensure a Stripe customer exists
    if not user.stripe_customer_id:
        cust = stripe.Customer.create(email=user.email, metadata={"user_id": str(user.id)})
        user.stripe_customer_id = cust["id"]
        db.session.commit()

    success_url = f"{APP_BASE_URL}/billing.html?success=1"
    cancel_url = f"{APP_BASE_URL}/billing.html?canceled=1"

    session = stripe.checkout.Session.create(
        mode="subscription",
        customer=user.stripe_customer_id,
        line_items=[{"price": STRIPE_PRICE_ID, "quantity": 1}],
        success_url=success_url,
        cancel_url=cancel_url,
        subscription_data={"trial_period_days": TRIAL_DAYS},
        metadata={"user_id": str(user.id)},
    )

    # store trial end locally (helps UI; Stripe is source of truth)
    if not user.trial_ends_at:
        user.trial_ends_at = now_utc() + timedelta(days=TRIAL_DAYS)
        db.session.commit()

    return jsonify({"ok": True, "url": session.url})


@app.post("/billing/create-portal-session")
@limiter.limit("30 per hour")
def create_portal_session():
    user, err = require_api_key()
    if err:
        return err

    if not STRIPE_SECRET_KEY:
        return json_error("Stripe not configured on server.", 500)

    if not user.stripe_customer_id:
        return json_error("No Stripe customer found for this user.", 400)

    return_url = f"{APP_BASE_URL}/billing.html"

    portal = stripe.billing_portal.Session.create(
        customer=user.stripe_customer_id,
        return_url=return_url,
    )
    return jsonify({"ok": True, "url": portal.url})


# ============================================================
# Stripe webhook
# ============================================================
@app.post("/stripe/webhook")
def stripe_webhook():
    if not STRIPE_WEBHOOK_SECRET:
        return json_error("Webhook not configured.", 500)

    payload = request.data
    sig_header = request.headers.get("Stripe-Signature", "")

    try:
        event = stripe.Webhook.construct_event(
            payload=payload, sig_header=sig_header, secret=STRIPE_WEBHOOK_SECRET
        )
    except Exception:
        return json_error("Invalid webhook signature.", 400)

    etype = event["type"]
    obj = event["data"]["object"]

    def get_user_by_customer(customer_id: str):
        if not customer_id:
            return None
        return User.query.filter_by(stripe_customer_id=customer_id).first()

    if etype in ("checkout.session.completed",):
        customer_id = obj.get("customer")
        subscription_id = obj.get("subscription")
        user = get_user_by_customer(customer_id)
        if user:
            user.stripe_subscription_id = subscription_id
            user.plan = "pro"
            user.subscription_status = "active"
            db.session.commit()

    if etype in ("customer.subscription.updated", "customer.subscription.created", "customer.subscription.deleted"):
        customer_id = obj.get("customer")
        subscription_id = obj.get("id")
        status_s = obj.get("status")  # active, trialing, past_due, canceled, unpaid...

        user = get_user_by_customer(customer_id)
        if user:
            user.stripe_subscription_id = subscription_id

            if status_s in ("active", "trialing"):
                user.subscription_status = "active"
                user.plan = "pro"
            elif status_s in ("past_due", "unpaid"):
                user.subscription_status = "past_due"
                user.plan = "free"
                user.enabled = False
            else:
                user.subscription_status = "canceled"
                user.plan = "free"
                user.enabled = False

            db.session.commit()

    return jsonify({"ok": True})


# ============================================================
# Trades routes
# ============================================================
@app.post("/api/v1/trades")
@limiter.limit("120 per minute")
def post_trade():
    user, err = require_api_key()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    symbol = (data.get("symbol") or "").strip().upper()
    side = (data.get("side") or "").strip().upper()

    if not symbol or side not in ("BUY", "SELL"):
        return json_error("symbol and side (BUY/SELL) required", 400)

    t = Trade(
        user_id=user.id,
        symbol=symbol,
        side=side,
        volume=safe_float(data.get("volume"), 0.0) or 0.0,
        entry=safe_float(data.get("entry")),
        sl=safe_float(data.get("sl")),
        tp=safe_float(data.get("tp")),
        deal_id=str(data.get("deal_id") or "")[:64] or None,
        profit=safe_float(data.get("profit")),
    )
    db.session.add(t)
    db.session.commit()

    return jsonify({"ok": True, "id": t.id})


@app.get("/api/v1/trades")
@limiter.limit("60 per minute")
def get_trades():
    user, err = require_api_key()
    if err:
        return err

    limit = safe_int(request.args.get("limit", 50), 50)
    limit = max(1, min(limit, 200))

    rows = (
        Trade.query
        .filter_by(user_id=user.id)
        .order_by(Trade.id.desc())
        .limit(limit)
        .all()
    )

    return jsonify({
        "ok": True,
        "items": [
            {
                "id": r.id,
                "symbol": r.symbol,
                "side": r.side,
                "volume": r.volume,
                "entry": r.entry,
                "sl": r.sl,
                "tp": r.tp,
                "deal_id": r.deal_id,
                "profit": r.profit,
                "opened_at": r.opened_at.isoformat(),
            }
            for r in rows
        ]
    })


# ============================================================
# Admin endpoints (locked by token + optional IP allowlist)
# ============================================================
@app.get("/admin/users")
@limiter.limit("60 per minute")
def admin_users():
    err = require_admin()
    if err:
        return err

    q = (request.args.get("q") or "").strip().lower()

    qry = User.query
    if q:
        qry = qry.filter(User.email.ilike(f"%{q}%"))

    users = qry.order_by(User.id.desc()).limit(200).all()

    items = []
    for u in users:
        items.append({
            "id": u.id,
            "email": u.email,
            "plan": u.plan,
            "subscription_status": u.subscription_status,
            "pairs": u.pairs,
            "lot_size": u.lot_size,
            "enabled": bool(u.enabled),
            "last_seen_at": u.last_seen_at.isoformat() if u.last_seen_at else None,
            "online": heartbeat_connected(u),
        })

    return jsonify({"ok": True, "items": items})


@app.get("/admin/user/<int:user_id>/activity")
@limiter.limit("60 per minute")
def admin_user_activity(user_id: int):
    err = require_admin()
    if err:
        return err

    u = User.query.get(user_id)
    if not u:
        return json_error("User not found", 404)

    trades = (
        Trade.query
        .filter_by(user_id=u.id)
        .order_by(Trade.id.desc())
        .limit(50)
        .all()
    )

    return jsonify({
        "ok": True,
        "user": {
            "id": u.id,
            "email": u.email,
            "plan": u.plan,
            "subscription_status": u.subscription_status,
            "trial_ends_at": u.trial_ends_at.isoformat() if u.trial_ends_at else None,
            "enabled": bool(u.enabled),
            "pairs": u.pairs,
            "lot_size": u.lot_size,
            "created_at": u.created_at.isoformat() if u.created_at else None,
            "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
            "last_settings_at": u.last_settings_at.isoformat() if u.last_settings_at else None,
            "last_seen_at": u.last_seen_at.isoformat() if u.last_seen_at else None,
            "last_seen_symbol": u.last_seen_symbol,
            "last_seen_tf": u.last_seen_tf,
            "last_seen_ip": u.last_seen_ip,
        },
        "trades": [
            {
                "id": t.id,
                "symbol": t.symbol,
                "side": t.side,
                "volume": t.volume,
                "entry": t.entry,
                "sl": t.sl,
                "tp": t.tp,
                "profit": t.profit,
                "opened_at": t.opened_at.isoformat(),
            } for t in trades
        ]
    })


@app.post("/admin/user/<int:user_id>/force-toggle")
@limiter.limit("60 per minute")
def admin_force_toggle(user_id: int):
    err = require_admin()
    if err:
        return err

    u = User.query.get(user_id)
    if not u:
        return json_error("User not found", 404)

    data = request.get_json(silent=True) or {}
    enabled = data.get("enabled", None)
    if enabled is None:
        return json_error("enabled required (true/false)", 400)

    u.enabled = bool(enabled)
    db.session.commit()

    audit("force_toggle", u, meta=f"enabled={u.enabled}")
    return jsonify({"ok": True, "enabled": bool(u.enabled)})


@app.post("/admin/user/<int:user_id>/rotate-key")
@limiter.limit("30 per minute")
def admin_rotate_user_key(user_id: int):
    err = require_admin()
    if err:
        return err

    u = User.query.get(user_id)
    if not u:
        return json_error("User not found", 404)

    u.api_key = secrets.token_hex(24)
    u.enabled = False
    db.session.commit()

    audit("rotate_user_key", u)
    return jsonify({"ok": True})


@app.post("/admin/user/<int:user_id>/set-plan")
@limiter.limit("60 per minute")
def admin_set_plan(user_id: int):
    err = require_admin()
    if err:
        return err

    u = User.query.get(user_id)
    if not u:
        return json_error("User not found", 404)

    data = request.get_json(silent=True) or {}
    plan = (data.get("plan") or "").strip().lower()
    sub = (data.get("subscription_status") or "").strip().lower()

    if plan not in ("free", "pro"):
        return json_error("plan must be free or pro", 400)
    if sub not in ("none", "active", "past_due", "canceled"):
        return json_error("subscription_status must be none/active/past_due/canceled", 400)

    u.plan = plan
    u.subscription_status = sub
    if sub != "active" and not trial_active(u):
        u.enabled = False

    db.session.commit()
    audit("set_plan", u, meta=f"plan={plan} sub={sub}")
    return jsonify({"ok": True})


@app.post("/admin/user/<int:user_id>/set-settings")
@limiter.limit("60 per minute")
def admin_set_settings(user_id: int):
    err = require_admin()
    if err:
        return err

    u = User.query.get(user_id)
    if not u:
        return json_error("User not found", 404)

    data = request.get_json(silent=True) or {}

    # settings override
    if "pairs" in data:
        try:
            u.pairs = normalize_pairs(str(data["pairs"]))
            u.pair = first_pair(u.pairs)
        except ValueError as e:
            return json_error(str(e), 400)

    if "lot_size" in data:
        lot = safe_float(data["lot_size"])
        if lot is None or lot <= 0 or lot > 100:
            return json_error("lot_size out of range", 400)
        u.lot_size = lot

    u.last_settings_at = now_utc()
    db.session.commit()

    audit("admin_set_settings", u, meta=f"pairs={u.pairs} lot={u.lot_size}")
    return jsonify({"ok": True})


@app.get("/admin/errors")
@limiter.limit("60 per minute")
def admin_errors_placeholder():
    """
    Placeholder endpoint (optional).
    Real errors are in Render logs; you can add stored error table later.
    """
    err = require_admin()
    if err:
        return err
    return jsonify({"ok": True, "items": []})


@app.get("/admin/audit")
@limiter.limit("60 per minute")
def admin_audit():
    err = require_admin()
    if err:
        return err

    limit = safe_int(request.args.get("limit", 50), 50)
    limit = max(1, min(limit, 200))

    rows = AuditLog.query.order_by(AuditLog.id.desc()).limit(limit).all()

    return jsonify({
        "ok": True,
        "items": [
            {
                "id": r.id,
                "at": r.at.isoformat() if r.at else None,
                "actor": r.actor,
                "action": r.action,
                "target_user_id": r.target_user_id,
                "target_email": r.target_email,
                "ip": r.ip,
                "meta": r.meta,
            } for r in rows
        ]
    })


# ============================================================
# Security headers
# ============================================================
@app.after_request
def add_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return resp


# ============================================================
# Ensure schema exists
# ============================================================
with app.app_context():
    ensure_schema()


# ============================================================
# Local run
# ============================================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
