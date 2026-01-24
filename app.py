import os
import secrets
import base64
import hmac
import hashlib
import json
import smtplib
from email.message import EmailMessage
from datetime import datetime, timezone, timedelta

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError
from sqlalchemy import text

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import stripe

# -------------------------
# App / Config
# -------------------------
app = Flask(__name__)

FRONTEND_ORIGINS = [
    "https://676trades.org",
    "https://www.676trades.org",
]

# CORS must allow admin + jwt headers
CORS(
    app,
    resources={r"/*": {"origins": FRONTEND_ORIGINS}},
    allow_headers=["Content-Type", "Authorization", "X-API-Key", "X-Admin-Token"],
    methods=["GET", "POST", "OPTIONS"],
)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["60 per minute"],
)

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///db.sqlite3")

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Used by Flask (not JWT)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", secrets.token_hex(32))

db = SQLAlchemy(app)

# -------------------------
# Security / Admin config
# -------------------------
JWT_SECRET = os.getenv("JWT_SECRET", "").strip() or os.getenv("SECRET_KEY", "").strip() or app.config["SECRET_KEY"]
JWT_EXPIRES_MIN = int(os.getenv("JWT_EXPIRES_MIN", "120"))

ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "").strip()
ADMIN_ALLOWED_IPS = [x.strip() for x in os.getenv("ADMIN_ALLOWED_IPS", "").split(",") if x.strip()]

# -------------------------
# Stripe config
# -------------------------
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "").strip()
STRIPE_PRICE_ID = os.getenv("STRIPE_PRICE_ID", "").strip()   # must be price_...
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "").strip()
APP_BASE_URL = os.getenv("APP_BASE_URL", "https://676trades.org").strip()
TRIAL_DAYS = int(os.getenv("TRIAL_DAYS", "5"))

if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

# -------------------------
# Email (password reset) config (optional)
# -------------------------
SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "").strip()
SMTP_PASS = os.getenv("SMTP_PASS", "").strip()
SMTP_FROM = os.getenv("SMTP_FROM", "support@676trades.org").strip()
SUPPORT_EMAIL = os.getenv("SUPPORT_EMAIL", "support@676trades.org").strip()

# -------------------------
# Supported markets policy
# -------------------------
# Public supported markets (beginner-friendly launch set)
PUBLIC_ALLOWED_PAIRS = {"XAUUSD", "EURUSD", "GBPUSD", "USDJPY"}

# Locked for now (admin testing only)
ADMIN_TEST_ONLY_PAIRS = {"BTCUSD", "NAS100", "US30"}


# -------------------------
# Models
# -------------------------
class User(db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)

    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)

    # EA auth
    api_key = db.Column(db.String(64), unique=True, nullable=False, index=True)

    enabled = db.Column(db.Boolean, default=False, nullable=False)

    # Backward compatible single symbol
    pair = db.Column(db.String(20), default="XAUUSD", nullable=False)
    # Multi symbols CSV
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

    # Billing fields
    plan = db.Column(db.String(20), default="free", nullable=False)  # free / pro
    subscription_status = db.Column(db.String(30), default="none", nullable=False)  # none/active/past_due/canceled
    trial_ends_at = db.Column(db.DateTime, nullable=True)

    stripe_customer_id = db.Column(db.String(80), nullable=True, index=True)
    stripe_subscription_id = db.Column(db.String(80), nullable=True, index=True)

    # Heartbeat fields
    last_seen_at = db.Column(db.DateTime, nullable=True)
    last_seen_symbol = db.Column(db.String(20), nullable=True)
    last_seen_tf = db.Column(db.String(10), nullable=True)
    last_seen_ip = db.Column(db.String(64), nullable=True)

    # Web/app fields
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    last_login_at = db.Column(db.DateTime, nullable=True)
    last_settings_at = db.Column(db.DateTime, nullable=True)

    # JWT invalidation (force logout)
    token_version = db.Column(db.Integer, default=0, nullable=False)

    # Optional: risk acknowledgement timestamp
    risk_ack_at = db.Column(db.DateTime, nullable=True)

    # Password reset (token stored hashed)
    reset_token_hash = db.Column(db.String(128), nullable=True)
    reset_token_expires_at = db.Column(db.DateTime, nullable=True)


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


# -------------------------
# Helpers
# -------------------------
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


def normalize_pairs(value: str, allowed_set=None) -> str:
    parts = [p.strip().upper() for p in (value or "").split(",")]
    parts = [p for p in parts if p]

    if not parts:
        raise ValueError("pairs cannot be empty")

    for p in parts:
        if len(p) < 3 or len(p) > 12:
            raise ValueError("pair looks invalid")

    if allowed_set is not None:
        for p in parts:
            if p not in allowed_set:
                supported = ", ".join(sorted(allowed_set))
                raise ValueError(f"{p} is not supported yet. Supported: {supported}")

    seen = set()
    out = []
    for p in parts:
        if p not in seen:
            seen.add(p)
            out.append(p)

    return ",".join(out)


def first_pair(pairs_csv: str) -> str:
    try:
        return (pairs_csv or "XAUUSD").split(",")[0].strip().upper() or "XAUUSD"
    except Exception:
        return "XAUUSD"


def now_utc():
    return datetime.now(timezone.utc)


def dt_iso(dt):
    return dt.isoformat() if dt else None


def client_ip():
    cf = request.headers.get("CF-Connecting-IP", "").strip()
    if cf:
        return cf
    xff = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    if xff:
        return xff
    return request.remote_addr or ""


# -------------------------
# JWT (simple HS256)
# -------------------------
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)


def jwt_encode(payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    msg = f"{h}.{p}".encode()
    sig = hmac.new(JWT_SECRET.encode(), msg, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url(sig)}"


def jwt_decode(token: str) -> dict:
    try:
        h, p, s = token.split(".")
        msg = f"{h}.{p}".encode()
        sig = _b64url_decode(s)
        exp_sig = hmac.new(JWT_SECRET.encode(), msg, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, exp_sig):
            raise ValueError("bad signature")
        payload = json.loads(_b64url_decode(p).decode())
        return payload
    except Exception:
        raise ValueError("invalid token")


def issue_access_token(user: User) -> str:
    exp = int((now_utc() + timedelta(minutes=JWT_EXPIRES_MIN)).timestamp())
    payload = {
        "sub": user.id,
        "email": user.email,
        "tv": int(user.token_version),
        "exp": exp,
    }
    return jwt_encode(payload)


def require_jwt():
    auth = request.headers.get("Authorization", "").strip()
    if not auth.startswith("Bearer "):
        return None, json_error("Missing Authorization Bearer token", 401)
    token = auth.split(" ", 1)[1].strip()
    try:
        payload = jwt_decode(token)
    except Exception:
        return None, json_error("Invalid token", 401)

    exp = payload.get("exp")
    if not exp or int(exp) < int(now_utc().timestamp()):
        return None, json_error("Token expired", 401)

    uid = payload.get("sub")
    if not uid:
        return None, json_error("Invalid token", 401)

    user = User.query.get(int(uid))
    if not user:
        return None, json_error("Invalid token", 401)

    if int(payload.get("tv", -1)) != int(user.token_version):
        return None, json_error("Session invalidated. Please login again.", 401)

    return user, None


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
    t = user.trial_ends_at
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return now_utc() < t


def is_paid_active(user: User) -> bool:
    return user.subscription_status == "active"


def ensure_can_trade(user: User):
    if is_paid_active(user) or trial_active(user):
        return None
    if user.enabled:
        user.enabled = False
        db.session.commit()
    return json_error("Payment required. Please start your free trial / subscribe.", 402)


def ea_connected(user: User, minutes=5) -> bool:
    if not user.last_seen_at:
        return False
    t = user.last_seen_at
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return now_utc() - t < timedelta(minutes=minutes)


# -------------------------
# Admin auth + IP lock
# -------------------------
def require_admin():
    if not ADMIN_TOKEN:
        return False, json_error("Admin not configured on server.", 500)

    token = request.headers.get("X-Admin-Token", "").strip()
    if token != ADMIN_TOKEN:
        return False, json_error("Unauthorized", 401)

    if ADMIN_ALLOWED_IPS:
        ip = client_ip()
        if ip not in ADMIN_ALLOWED_IPS:
            return False, json_error("Forbidden (IP not allowed)", 403)

    return True, None


# -------------------------
# Email helper (optional)
# -------------------------
def send_email(to_email: str, subject: str, body: str) -> bool:
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASS:
        # Not configured -> return False (but routes will still return generic OK)
        return False

    try:
        msg = EmailMessage()
        msg["From"] = SMTP_FROM
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.set_content(body)

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as s:
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
        return True
    except Exception as e:
        print("Email send failed:", str(e))
        return False


# -------------------------
# Auto-migration (Postgres safe)
# -------------------------
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
            add_col('ALTER TABLE "user" ADD COLUMN last_seen_tf VARCHAR(10) NULL')
        if "last_seen_ip" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN last_seen_ip VARCHAR(64) NULL')

        # jwt invalidation + risk + reset
        if "token_version" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0')
        if "risk_ack_at" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN risk_ack_at TIMESTAMPTZ NULL')
        if "reset_token_hash" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN reset_token_hash VARCHAR(128) NULL')
        if "reset_token_expires_at" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN reset_token_expires_at TIMESTAMPTZ NULL')

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


# -------------------------
# Preflight helper (OPTIONS)
# -------------------------
@app.route("/<path:_any>", methods=["OPTIONS"])
def any_options(_any):
    return ("", 204)


# -------------------------
# Routes: Health
# -------------------------
@app.get("/")
def root():
    return jsonify({"ok": True, "service": "mt5-control-backend", "version": "v2-jwt-admin-pairlock"})


@app.get("/health")
def health():
    return jsonify({"ok": True})


# -------------------------
# Routes: Auth (JWT for website)
# -------------------------
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
        token_version=0,
    )

    try:
        db.session.add(user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return json_error("Email already registered", 409)

    token = issue_access_token(user)
    return jsonify({"ok": True, "message": "Registered", "access_token": token, "api_key": api_key})


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

    token = issue_access_token(user)
    return jsonify({"ok": True, "access_token": token, "api_key": user.api_key})


@app.post("/auth/logout-all")
def logout_all():
    user, err = require_jwt()
    if err:
        return err

    user.token_version = int(user.token_version) + 1
    db.session.commit()
    return jsonify({"ok": True})


@app.post("/auth/rotate-key")
@limiter.limit("10 per hour")
def rotate_key_user():
    user, err = require_jwt()
    if err:
        return err

    user.api_key = secrets.token_hex(24)
    db.session.commit()
    return jsonify({"ok": True, "api_key": user.api_key})


# -------------------------
# Password reset (email optional)
# -------------------------
@app.post("/auth/forgot-password")
@limiter.limit("20 per hour")
def forgot_password():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()

    # Always return OK (avoid account enumeration)
    if not email:
        return jsonify({"ok": True})

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"ok": True})

    raw = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    user.reset_token_hash = token_hash
    user.reset_token_expires_at = now_utc() + timedelta(minutes=30)
    db.session.commit()

    reset_link = f"{APP_BASE_URL}/reset.html?token={raw}"
    body = (
        "You requested a password reset for 676Trades.\n\n"
        f"Reset link (valid ~30 minutes):\n{reset_link}\n\n"
        "If you did not request this, you can ignore this email.\n"
        f"Support: {SUPPORT_EMAIL}\n"
    )

    send_email(email, "676Trades - Password reset", body)
    return jsonify({"ok": True})


@app.post("/auth/reset-password")
@limiter.limit("20 per hour")
def reset_password():
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    new_password = (data.get("password") or "").strip()

    if not token or not new_password:
        return json_error("token and password required", 400)

    token_hash = hashlib.sha256(token.encode()).hexdigest()
    user = User.query.filter_by(reset_token_hash=token_hash).first()
    if not user or not user.reset_token_expires_at:
        return json_error("Invalid or expired token", 400)

    exp = user.reset_token_expires_at
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    if now_utc() > exp:
        return json_error("Invalid or expired token", 400)

    user.password_hash = generate_password_hash(new_password)
    user.reset_token_hash = None
    user.reset_token_expires_at = None
    user.token_version = int(user.token_version) + 1  # force logout all sessions
    db.session.commit()

    return jsonify({"ok": True})


# -------------------------
# Routes: Control (EA + Dashboard)
# Dashboard uses JWT; EA uses X-API-Key
# -------------------------
@app.get("/api/v1/status")
@limiter.limit("120 per minute")
def status():
    # allow EA (X-API-Key) OR website (JWT)
    user, err = require_api_key()
    if err:
        user, err2 = require_jwt()
        if err2:
            return err  # keep original error message for EA callers

    pairs_csv = (user.pairs or user.pair or "XAUUSD").strip() or "XAUUSD"
    online = ea_connected(user, minutes=5)

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
        "trial_ends_at": dt_iso(user.trial_ends_at),

        # heartbeat snapshot
        "ea_connected": bool(online),
        "last_seen_at": dt_iso(user.last_seen_at),

        # optional risk ack
        "risk_ack_at": dt_iso(user.risk_ack_at),
    })


@app.post("/api/v1/toggle")
@limiter.limit("60 per minute")
def toggle():
    user, err = require_jwt()
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
    user, err = require_jwt()
    if err:
        return err

    pay_err = ensure_can_trade(user)
    if pay_err:
        return pay_err

    data = request.get_json(silent=True) or {}

    # Enforce public supported markets only
    if "pairs" in data:
        try:
            user.pairs = normalize_pairs(str(data["pairs"]), allowed_set=PUBLIC_ALLOWED_PAIRS)
            user.pair = first_pair(user.pairs)
        except ValueError as e:
            return json_error(str(e), 400)

    if "pair" in data and "pairs" not in data:
        try:
            single = normalize_pairs(str(data["pair"]), allowed_set=PUBLIC_ALLOWED_PAIRS)
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

    if data.get("risk_ack", False):
        user.risk_ack_at = now_utc()

    user.last_settings_at = now_utc()
    db.session.commit()
    return status()


# -------------------------
# EA Heartbeat (EA calls with X-API-Key)
# -------------------------
@app.post("/api/v1/heartbeat")
@limiter.limit("120 per minute")
def heartbeat():
    user, err = require_api_key()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    user.last_seen_at = now_utc()
    user.last_seen_symbol = (data.get("symbol") or "").strip().upper()[:20] or user.last_seen_symbol
    user.last_seen_tf = (data.get("tf") or "").strip().upper()[:10] or user.last_seen_tf
    user.last_seen_ip = client_ip()[:64] or user.last_seen_ip
    db.session.commit()
    return jsonify({"ok": True})


# -------------------------
# Billing routes (JWT)
# -------------------------
@app.get("/billing/status")
@limiter.limit("60 per minute")
def billing_status():
    user, err = require_jwt()
    if err:
        return err

    return jsonify({
        "ok": True,
        "plan": user.plan,
        "subscription_status": user.subscription_status,
        "trial_ends_at": dt_iso(user.trial_ends_at),
        "trial_active": trial_active(user),
    })


@app.post("/billing/create-checkout-session")
@limiter.limit("20 per hour")
def create_checkout_session():
    user, err = require_jwt()
    if err:
        return err

    if not STRIPE_SECRET_KEY or not STRIPE_PRICE_ID:
        return json_error("Stripe not configured on server.", 500)

    if not user.stripe_customer_id:
        cust = stripe.Customer.create(email=user.email, metadata={"user_id": str(user.id)})
        user.stripe_customer_id = cust["id"]
        db.session.commit()

    if not user.trial_ends_at:
        user.trial_ends_at = now_utc() + timedelta(days=TRIAL_DAYS)
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

    return jsonify({"ok": True, "url": session.url})


@app.post("/billing/create-portal-session")
@limiter.limit("30 per hour")
def create_portal_session():
    user, err = require_jwt()
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


# -------------------------
# Stripe webhook
# -------------------------
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
        status = obj.get("status")

        user = get_user_by_customer(customer_id)
        if user:
            user.stripe_subscription_id = subscription_id

            if status in ("active", "trialing"):
                user.subscription_status = "active"
                user.plan = "pro"
            elif status in ("past_due", "unpaid"):
                user.subscription_status = "past_due"
                user.plan = "free"
            else:
                user.subscription_status = "canceled"
                user.plan = "free"
                user.enabled = False

            db.session.commit()

    return jsonify({"ok": True})


# -------------------------
# Trades routes (EA can post with X-API-Key; website can read with JWT)
# -------------------------
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
    user, err = require_jwt()
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
                "opened_at": dt_iso(r.opened_at),
            }
            for r in rows
        ]
    })


# -------------------------
# Admin routes (X-Admin-Token + optional IP lock)
# -------------------------
@app.get("/admin/users")
@limiter.limit("60 per minute")
def admin_users():
    ok, err = require_admin()
    if err:
        return err

    q = (request.args.get("q") or "").strip().lower()
    query = User.query
    if q:
        query = query.filter(User.email.ilike(f"%{q}%"))

    users = query.order_by(User.id.desc()).limit(200).all()

    return jsonify({
        "ok": True,
        "items": [
            {
                "id": u.id,
                "email": u.email,
                "plan": u.plan,
                "subscription_status": u.subscription_status,
                "enabled": bool(u.enabled),
                "pairs": u.pairs,
                "lot_size": float(u.lot_size),
                "last_seen_at": dt_iso(u.last_seen_at),
                "online": ea_connected(u, minutes=5),
            }
            for u in users
        ]
    })


@app.get("/admin/user/<int:user_id>/activity")
@limiter.limit("60 per minute")
def admin_user_activity(user_id: int):
    ok, err = require_admin()
    if err:
        return err

    u = User.query.get(user_id)
    if not u:
        return json_error("User not found", 404)

    trades = (
        Trade.query.filter_by(user_id=u.id)
        .order_by(Trade.id.desc())
        .limit(25)
        .all()
    )

    return jsonify({
        "ok": True,
        "user": {
            "id": u.id,
            "email": u.email,
            "plan": u.plan,
            "subscription_status": u.subscription_status,
            "enabled": bool(u.enabled),
            "pairs": u.pairs,
            "lot_size": float(u.lot_size),
            "created_at": dt_iso(u.created_at),
            "last_login_at": dt_iso(u.last_login_at),
            "last_settings_at": dt_iso(u.last_settings_at),
            "last_seen_at": dt_iso(u.last_seen_at),
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
                "deal_id": t.deal_id,
                "profit": t.profit,
                "opened_at": dt_iso(t.opened_at),
            }
            for t in trades
        ]
    })


@app.post("/admin/user/<int:user_id>/force-enabled")
def admin_force_enabled(user_id: int):
    ok, err = require_admin()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    enabled = bool(data.get("enabled", False))

    u = User.query.get(user_id)
    if not u:
        return json_error("User not found", 404)

    u.enabled = enabled
    db.session.commit()
    return jsonify({"ok": True, "enabled": bool(u.enabled)})


@app.post("/admin/user/<int:user_id>/rotate-api-key")
def admin_rotate_api_key(user_id: int):
    ok, err = require_admin()
    if err:
        return err

    u = User.query.get(user_id)
    if not u:
        return json_error("User not found", 404)

    u.api_key = secrets.token_hex(24)
    db.session.commit()
    return jsonify({"ok": True, "api_key": u.api_key})


@app.post("/admin/user/<int:user_id>/override-billing")
def admin_override_billing(user_id: int):
    ok, err = require_admin()
    if err:
        return err

    u = User.query.get(user_id)
    if not u:
        return json_error("User not found", 404)

    data = request.get_json(silent=True) or {}
    plan = (data.get("plan") or "").strip().lower()
    sub = (data.get("subscription_status") or "").strip().lower()

    if plan and plan not in ("free", "pro"):
        return json_error("plan must be free or pro", 400)
    if sub and sub not in ("none", "active", "past_due", "canceled"):
        return json_error("subscription_status invalid", 400)

    if plan:
        u.plan = plan
    if sub:
        u.subscription_status = sub

    if u.subscription_status != "active":
        u.enabled = False

    db.session.commit()
    return jsonify({"ok": True})


@app.post("/admin/user/<int:user_id>/override-settings")
def admin_override_settings(user_id: int):
    ok, err = require_admin()
    if err:
        return err

    u = User.query.get(user_id)
    if not u:
        return json_error("User not found", 404)

    data = request.get_json(silent=True) or {}

    # Admin can set public + test-only pairs
    admin_allowed = PUBLIC_ALLOWED_PAIRS | ADMIN_TEST_ONLY_PAIRS

    if "pairs" in data:
        try:
            u.pairs = normalize_pairs(str(data["pairs"]), allowed_set=admin_allowed)
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
    return jsonify({"ok": True})


@app.post("/admin/user/<int:user_id>/force-logout")
def admin_force_logout(user_id: int):
    ok, err = require_admin()
    if err:
        return err

    u = User.query.get(user_id)
    if not u:
        return json_error("User not found", 404)

    u.token_version = int(u.token_version) + 1
    db.session.commit()
    return jsonify({"ok": True})


# -------------------------
# Security headers
# -------------------------
@app.after_request
def add_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return resp


# -------------------------
# Ensure schema exists
# -------------------------
with app.app_context():
    ensure_schema()


# -------------------------
# Local run
# -------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
