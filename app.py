import os
import secrets
import base64
import hmac
import hashlib
import json
from datetime import datetime, timezone, timedelta

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError
from sqlalchemy import text

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from flask_mail import Mail, Message

import stripe

# -------------------------
# App / Config
# -------------------------
app = Flask(__name__)

def parse_origins():
    """
    Use env var FRONTEND_ORIGINS="https://a.com,https://b.com"
    If missing, fall back to old domain so current site keeps working.
    """
    raw = os.getenv("FRONTEND_ORIGINS", "").strip()
    if raw:
        return [x.strip() for x in raw.split(",") if x.strip()]
    return [
        "https://676trades.org",
        "https://www.676trades.org",
    ]

FRONTEND_ORIGINS = parse_origins()

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
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", secrets.token_hex(32))

db = SQLAlchemy(app)

# -------------------------
# Mail (password reset)
# -------------------------
# Works with your provider SMTP settings on Render.
# If you don't set these env vars, reset endpoints will return a clear error.
app.config["MAIL_SERVER"] = os.getenv("MAIL_SERVER", "").strip()
app.config["MAIL_PORT"] = int(os.getenv("MAIL_PORT", "587"))
app.config["MAIL_USE_TLS"] = os.getenv("MAIL_USE_TLS", "true").lower() == "true"
app.config["MAIL_USE_SSL"] = os.getenv("MAIL_USE_SSL", "false").lower() == "true"
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME", "").strip()
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD", "").strip()
app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_DEFAULT_SENDER", "").strip()  # e.g. "Caribbean Covenant <support@domain>"
mail = Mail(app)

# -------------------------
# Security / Admin config
# -------------------------
JWT_SECRET = (os.getenv("JWT_SECRET", "").strip()
              or os.getenv("SECRET_KEY", "").strip()
              or app.config["SECRET_KEY"])

JWT_EXPIRES_MIN = int(os.getenv("JWT_EXPIRES_MIN", "1440"))  # 24h

ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "").strip()
ADMIN_ALLOWED_IPS = [x.strip() for x in os.getenv("ADMIN_ALLOWED_IPS", "").split(",") if x.strip()]

# -------------------------
# Branding / URLs
# -------------------------
APP_NAME = os.getenv("APP_NAME", "Caribbean Covenant").strip()
APP_BASE_URL = os.getenv("APP_BASE_URL", "https://676trades.org").strip()  # update later to your new domain
SUPPORT_EMAIL = os.getenv("SUPPORT_EMAIL", "support@676trades.org").strip()

# -------------------------
# Stripe config (optional)
# -------------------------
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "").strip()
STRIPE_PRICE_ID = os.getenv("STRIPE_PRICE_ID", "").strip()
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "").strip()
TRIAL_DAYS = int(os.getenv("TRIAL_DAYS", "5"))

if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

# -------------------------
# Models
# -------------------------
class User(db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)

    # Auth
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)

    # Old: API key (you can keep it; not harmful)
    api_key = db.Column(db.String(64), unique=True, nullable=False, index=True)

    # --- COMMUNITY PROFILE (NEW) ---
    display_name = db.Column(db.String(80), nullable=True)
    bio = db.Column(db.String(500), nullable=True)
    country = db.Column(db.String(60), nullable=True)   # Jamaica / UK / Canada etc.
    parish = db.Column(db.String(60), nullable=True)    # optional
    denomination = db.Column(db.String(80), nullable=True)
    looking_for = db.Column(db.String(200), nullable=True)  # short statement
    faith_statement = db.Column(db.String(300), nullable=True)
    age_range = db.Column(db.String(20), nullable=True)  # e.g. "25-34" (avoid DOB for now)

    # --- TRADING FIELDS (legacy; safe to keep during transition) ---
    enabled = db.Column(db.Boolean, default=False, nullable=False)
    pair = db.Column(db.String(20), default="XAUUSD", nullable=False)
    pairs = db.Column(db.String(255), default="XAUUSD", nullable=False)
    lot_size = db.Column(db.Float, default=0.01, nullable=False)
    sl_mode = db.Column(db.String(20), default="dynamic", nullable=False)
    tp_mode = db.Column(db.String(20), default="rr", nullable=False)
    min_pips = db.Column(db.Integer, default=50, nullable=False)
    sl_buffer_pips = db.Column(db.Integer, default=5, nullable=False)
    rr = db.Column(db.Float, default=1.0, nullable=False)
    pattern_tp_mult = db.Column(db.Float, default=1.5, nullable=False)
    fixed_sl_pips = db.Column(db.Integer, default=50, nullable=False)
    fixed_tp_pips = db.Column(db.Integer, default=50, nullable=False)

    # Billing
    plan = db.Column(db.String(20), default="free", nullable=False)
    subscription_status = db.Column(db.String(30), default="none", nullable=False)
    trial_ends_at = db.Column(db.DateTime, nullable=True)
    stripe_customer_id = db.Column(db.String(80), nullable=True, index=True)
    stripe_subscription_id = db.Column(db.String(80), nullable=True, index=True)

    # Status
    last_seen_at = db.Column(db.DateTime, nullable=True)
    last_seen_symbol = db.Column(db.String(20), nullable=True)
    last_seen_tf = db.Column(db.String(10), nullable=True)
    last_seen_ip = db.Column(db.String(64), nullable=True)

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    last_login_at = db.Column(db.DateTime, nullable=True)
    last_settings_at = db.Column(db.DateTime, nullable=True)

    token_version = db.Column(db.Integer, default=0, nullable=False)
    risk_ack_at = db.Column(db.DateTime, nullable=True)

    # Password reset
    reset_token_hash = db.Column(db.String(128), nullable=True)
    reset_token_expires_at = db.Column(db.DateTime, nullable=True)


class Group(db.Model):
    __tablename__ = "group"

    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(80), unique=True, nullable=False, index=True)  # stable identifier
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.String(500), nullable=True)
    is_public = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)


class GroupMember(db.Model):
    __tablename__ = "group_member"

    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey("group.id"), index=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), index=True, nullable=False)
    joined_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    __table_args__ = (
        db.UniqueConstraint("group_id", "user_id", name="uq_group_member"),
    )


class GroupPost(db.Model):
    __tablename__ = "group_post"

    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey("group.id"), index=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), index=True, nullable=False)

    content = db.Column(db.String(1200), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)


class Trade(db.Model):
    __tablename__ = "trade"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), index=True, nullable=False)
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

def normalize_pairs(value: str) -> str:
    parts = [p.strip().upper() for p in (value or "").split(",")]
    parts = [p for p in parts if p]
    for p in parts:
        if len(p) < 3 or len(p) > 12:
            raise ValueError("pair looks invalid")
    seen, out = set(), []
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
        return None, json_error("Token expired. Please login again.", 401)

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
# Password reset helpers
# -------------------------
def _hash_token(raw: str) -> str:
    # Store only hash in DB (safer if DB leaked)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def _send_reset_email(to_email: str, reset_url: str):
    if not app.config["MAIL_SERVER"] or not app.config["MAIL_DEFAULT_SENDER"]:
        raise RuntimeError("MAIL not configured")

    subject = f"{APP_NAME} — Password reset"
    body = (
        f"Hello,\n\n"
        f"We received a request to reset your password for {APP_NAME}.\n\n"
        f"Reset link:\n{reset_url}\n\n"
        f"If you did not request this, you can ignore this email.\n\n"
        f"Support: {SUPPORT_EMAIL}\n"
    )

    msg = Message(subject=subject, recipients=[to_email], body=body)
    mail.send(msg)

# -------------------------
# Auto-migration (Postgres safe)
# -------------------------
def ensure_schema():
    uri = app.config["SQLALCHEMY_DATABASE_URI"]
    is_postgres = uri.startswith("postgresql")
    if not is_postgres:
        db.create_all()
        seed_default_groups()
        return

    with db.engine.begin() as conn:
        # base user table
        conn.execute(text("""CREATE TABLE IF NOT EXISTS "user" (id SERIAL PRIMARY KEY)"""))

        cols = {
            r[0] for r in conn.execute(text("""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_schema='public' AND table_name='user'
            """)).fetchall()
        }

        def add_col(sql): conn.execute(text(sql))

        # auth cols
        if "email" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN email VARCHAR(255)')
            add_col('CREATE UNIQUE INDEX IF NOT EXISTS ix_user_email ON "user"(email)')
        if "password_hash" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN password_hash VARCHAR(255)')
        if "api_key" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN api_key VARCHAR(64)')
            add_col('CREATE UNIQUE INDEX IF NOT EXISTS ix_user_api_key ON "user"(api_key)')

        # community profile cols
        if "display_name" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN display_name VARCHAR(80)')
        if "bio" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN bio VARCHAR(500)')
        if "country" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN country VARCHAR(60)')
        if "parish" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN parish VARCHAR(60)')
        if "denomination" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN denomination VARCHAR(80)')
        if "looking_for" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN looking_for VARCHAR(200)')
        if "faith_statement" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN faith_statement VARCHAR(300)')
        if "age_range" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN age_range VARCHAR(20)')

        # legacy trading cols (keep)
        if "enabled" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN enabled BOOLEAN NOT NULL DEFAULT FALSE')
        if "pair" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN pair VARCHAR(20) NOT NULL DEFAULT \'XAUUSD\'')
        if "pairs" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN pairs VARCHAR(255) NOT NULL DEFAULT \'XAUUSD\'')
        if "lot_size" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN lot_size DOUBLE PRECISION NOT NULL DEFAULT 0.01')
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

        # billing cols
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

        # status cols
        if "created_at" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()')
        if "last_login_at" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN last_login_at TIMESTAMPTZ NULL')
        if "last_settings_at" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN last_settings_at TIMESTAMPTZ NULL')
        if "last_seen_at" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN last_seen_at TIMESTAMPTZ NULL')
        if "last_seen_symbol" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN last_seen_symbol VARCHAR(20) NULL')
        if "last_seen_tf" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN last_seen_tf VARCHAR(10) NULL')
        if "last_seen_ip" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN last_seen_ip VARCHAR(64) NULL')

        if "token_version" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0')
        if "risk_ack_at" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN risk_ack_at TIMESTAMPTZ NULL')
        if "reset_token_hash" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN reset_token_hash VARCHAR(128) NULL')
        if "reset_token_expires_at" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN reset_token_expires_at TIMESTAMPTZ NULL')

        # trades table (legacy)
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

        # community tables
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS "group" (
                id SERIAL PRIMARY KEY,
                slug VARCHAR(80) UNIQUE NOT NULL,
                name VARCHAR(120) NOT NULL,
                description VARCHAR(500) NULL,
                is_public BOOLEAN NOT NULL DEFAULT TRUE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """))
        conn.execute(text('CREATE INDEX IF NOT EXISTS ix_group_slug ON "group"(slug)'))

        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS group_member (
                id SERIAL PRIMARY KEY,
                group_id INTEGER NOT NULL REFERENCES "group"(id),
                user_id INTEGER NOT NULL REFERENCES "user"(id),
                joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                CONSTRAINT uq_group_member UNIQUE(group_id, user_id)
            )
        """))
        conn.execute(text('CREATE INDEX IF NOT EXISTS ix_group_member_group_id ON group_member(group_id)'))
        conn.execute(text('CREATE INDEX IF NOT EXISTS ix_group_member_user_id ON group_member(user_id)'))

        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS group_post (
                id SERIAL PRIMARY KEY,
                group_id INTEGER NOT NULL REFERENCES "group"(id),
                user_id INTEGER NOT NULL REFERENCES "user"(id),
                content VARCHAR(1200) NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """))
        conn.execute(text('CREATE INDEX IF NOT EXISTS ix_group_post_group_id ON group_post(group_id)'))
        conn.execute(text('CREATE INDEX IF NOT EXISTS ix_group_post_user_id ON group_post(user_id)'))

    seed_default_groups()

def seed_default_groups():
    """
    Create starter groups once. Safe to run every boot.
    """
    defaults = [
        ("christian-singles-jamaica", "Christian Singles — Jamaica",
         "Faith-centered discussion for singles in Jamaica. Calm conversation, no pressure."),
        ("caribbean-diaspora", "Caribbean Diaspora — UK / Canada / US",
         "For Caribbean Christians abroad who want shared culture and shared faith."),
        ("prayer-discernment", "Prayer & Discernment",
         "Discussion prompts focused on wisdom, peace, and discernment in relationships."),
        ("preparing-for-marriage", "Preparing for Marriage",
         "Conversations on communication, boundaries, family, finances, and purpose."),
    ]
    try:
        for slug, name, desc in defaults:
            exists = Group.query.filter_by(slug=slug).first()
            if not exists:
                db.session.add(Group(slug=slug, name=name, description=desc, is_public=True))
        db.session.commit()
    except Exception:
        db.session.rollback()

# -------------------------
# Preflight helper
# -------------------------
@app.route("/<path:_any>", methods=["OPTIONS"])
def any_options(_any):
    return ("", 204)

# -------------------------
# Routes: Health
# -------------------------
@app.get("/")
def root():
    return jsonify({"ok": True, "service": "caribbean-covenant-backend", "app": APP_NAME})

@app.get("/health")
def health():
    return jsonify({"ok": True})

# -------------------------
# Routes: Auth (JWT)
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
        created_at=now_utc(),
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

@app.get("/auth/me")
def auth_me():
    user, err = require_jwt()
    if err:
        return err
    return jsonify({
        "ok": True,
        "profile": {
            "id": user.id,
            "email": user.email,
            "display_name": user.display_name,
            "plan": user.plan,
            "subscription_status": user.subscription_status,
            "trial_ends_at": dt_iso(user.trial_ends_at),
            "created_at": dt_iso(user.created_at),
            "last_login_at": dt_iso(user.last_login_at),
        }
    })

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
# Auth: Forgot / Reset password (NEW)
# -------------------------
@app.post("/auth/forgot-password")
@limiter.limit("10 per hour")
def forgot_password():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    if not email:
        return json_error("Email required", 400)

    user = User.query.filter_by(email=email).first()
    # Always return ok (prevents account enumeration)
    if not user:
        return jsonify({"ok": True})

    raw_token = secrets.token_urlsafe(32)
    user.reset_token_hash = _hash_token(raw_token)
    user.reset_token_expires_at = now_utc() + timedelta(minutes=30)
    db.session.commit()

    reset_url = f"{APP_BASE_URL}/reset.html?token={raw_token}&email={email}"

    try:
        _send_reset_email(email, reset_url)
    except Exception:
        # Still return ok for privacy; log server-side if you want
        return jsonify({"ok": True})

    return jsonify({"ok": True})

@app.post("/auth/reset-password")
@limiter.limit("10 per hour")
def reset_password():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    token = (data.get("token") or "").strip()
    new_password = (data.get("new_password") or "").strip()

    if not email or not token or not new_password:
        return json_error("email, token, new_password required", 400)
    if len(new_password) < 8:
        return json_error("Password must be at least 8 characters.", 400)

    user = User.query.filter_by(email=email).first()
    if not user or not user.reset_token_hash or not user.reset_token_expires_at:
        return json_error("Invalid or expired token", 400)

    exp = user.reset_token_expires_at
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    if now_utc() > exp:
        return json_error("Invalid or expired token", 400)

    if _hash_token(token) != user.reset_token_hash:
        return json_error("Invalid or expired token", 400)

    user.password_hash = generate_password_hash(new_password)
    user.reset_token_hash = None
    user.reset_token_expires_at = None

    # invalidate all sessions
    user.token_version = int(user.token_version) + 1
    db.session.commit()

    return jsonify({"ok": True})

# -------------------------
# COMMUNITY MVP (NEW)
# -------------------------
@app.get("/api/v1/me")
def me_get():
    user, err = require_jwt()
    if err:
        return err

    return jsonify({
        "ok": True,
        "me": {
            "email": user.email,
            "display_name": user.display_name,
            "bio": user.bio,
            "country": user.country,
            "parish": user.parish,
            "denomination": user.denomination,
            "looking_for": user.looking_for,
            "faith_statement": user.faith_statement,
            "age_range": user.age_range,
            "created_at": dt_iso(user.created_at),
        }
    })

@app.post("/api/v1/me")
@limiter.limit("60 per minute")
def me_post():
    user, err = require_jwt()
    if err:
        return err

    data = request.get_json(silent=True) or {}

    def s(key, maxlen):
        v = (data.get(key) or "").strip()
        if not v:
            return None
        return v[:maxlen]

    user.display_name = s("display_name", 80) or user.display_name
    user.bio = s("bio", 500)
    user.country = s("country", 60)
    user.parish = s("parish", 60)
    user.denomination = s("denomination", 80)
    user.looking_for = s("looking_for", 200)
    user.faith_statement = s("faith_statement", 300)
    user.age_range = s("age_range", 20)

    db.session.commit()
    return me_get()

PROMPTS = [
    "What does a Christ-centered marriage mean to you in everyday life?",
    "How do you like to handle conflict in a respectful and healthy way?",
    "What values do you want your home to be built on?",
    "How do you practice your faith throughout the week?",
    "What does accountability look like to you in a relationship?",
    "How do you balance purpose, work, and family in your future?",
    "What boundaries help you date with peace and clarity?",
    "What role should prayer play in courtship and decision-making?",
    "What is something God has been teaching you recently?",
    "How do you want to communicate during stressful seasons?",
]

@app.get("/api/v1/prompts")
def prompts():
    # no auth required; safe public content
    return jsonify({"ok": True, "items": PROMPTS})

@app.get("/api/v1/groups")
def list_groups():
    user, err = require_jwt()
    if err:
        return err

    groups = Group.query.order_by(Group.id.asc()).all()
    my = {m.group_id for m in GroupMember.query.filter_by(user_id=user.id).all()}

    return jsonify({
        "ok": True,
        "items": [
            {
                "id": g.id,
                "slug": g.slug,
                "name": g.name,
                "description": g.description,
                "is_public": bool(g.is_public),
                "joined": (g.id in my),
                "created_at": dt_iso(g.created_at),
            } for g in groups
        ]
    })

@app.post("/api/v1/groups/join")
@limiter.limit("60 per minute")
def join_group():
    user, err = require_jwt()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    gid = safe_int(data.get("group_id"))
    if not gid:
        return json_error("group_id required", 400)

    g = Group.query.get(gid)
    if not g:
        return json_error("Group not found", 404)

    try:
        db.session.add(GroupMember(group_id=g.id, user_id=user.id))
        db.session.commit()
    except IntegrityError:
        db.session.rollback()  # already joined

    return jsonify({"ok": True})

@app.get("/api/v1/groups/<int:group_id>/posts")
def get_group_posts(group_id: int):
    user, err = require_jwt()
    if err:
        return err

    # must be a member to view (simple safety rule)
    mem = GroupMember.query.filter_by(group_id=group_id, user_id=user.id).first()
    if not mem:
        return json_error("Join the group to view posts.", 403)

    limit = safe_int(request.args.get("limit", 50), 50)
    limit = max(1, min(limit, 200))

    posts = (
        GroupPost.query
        .filter_by(group_id=group_id)
        .order_by(GroupPost.id.desc())
        .limit(limit)
        .all()
    )

    # Map user display names quickly
    user_ids = list({p.user_id for p in posts})
    users = User.query.filter(User.id.in_(user_ids)).all() if user_ids else []
    u_map = {u.id: (u.display_name or "Member") for u in users}

    return jsonify({
        "ok": True,
        "items": [
            {
                "id": p.id,
                "group_id": p.group_id,
                "user_id": p.user_id,
                "display_name": u_map.get(p.user_id, "Member"),
                "content": p.content,
                "created_at": dt_iso(p.created_at),
            } for p in posts
        ]
    })

@app.post("/api/v1/groups/<int:group_id>/posts")
@limiter.limit("60 per minute")
def create_group_post(group_id: int):
    user, err = require_jwt()
    if err:
        return err

    mem = GroupMember.query.filter_by(group_id=group_id, user_id=user.id).first()
    if not mem:
        return json_error("Join the group to post.", 403)

    data = request.get_json(silent=True) or {}
    content = (data.get("content") or "").strip()
    if not content:
        return json_error("content required", 400)

    content = content[:1200]
    db.session.add(GroupPost(group_id=group_id, user_id=user.id, content=content))
    db.session.commit()
    return jsonify({"ok": True})

# -------------------------
# LEGACY: Control (EA + Dashboard) — unchanged
# -------------------------
@app.get("/api/v1/status")
@limiter.limit("120 per minute")
def status():
    user = None
    err = None

    has_auth = request.headers.get("Authorization", "").strip().startswith("Bearer ")
    if has_auth:
        user, err = require_jwt()
        if err:
            return err
    else:
        user, err = require_api_key()
        if err:
            return err

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

        "plan": user.plan,
        "subscription_status": user.subscription_status,
        "trial_ends_at": dt_iso(user.trial_ends_at),

        "ea_connected": bool(online),
        "last_seen_at": dt_iso(user.last_seen_at),
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

    if data.get("risk_ack", False):
        user.risk_ack_at = now_utc()

    user.last_settings_at = now_utc()
    db.session.commit()
    return status()

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
# Billing routes (kept)
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
# Admin routes (kept)
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
                "display_name": u.display_name,
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

with app.app_context():
    ensure_schema()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
