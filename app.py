import os
import secrets
from datetime import datetime, timezone, timedelta

from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError
from sqlalchemy import text

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import stripe

# JWT (PyJWT)
import jwt


# -------------------------
# App / Config
# -------------------------
app = Flask(__name__)

FRONTEND_ORIGINS = [
    "https://676trades.org",
    "https://www.676trades.org",
]

# Secrets / JWT
SECRET_KEY = os.getenv("SECRET_KEY", "").strip()
if not SECRET_KEY:
    # You MUST set this in Render env vars in production.
    # Using a random fallback would invalidate tokens on each restart.
    raise RuntimeError("SECRET_KEY is required (set it in Render env vars).")

JWT_ISSUER = os.getenv("JWT_ISSUER", "676trades").strip()
JWT_EXPIRES_MIN = int(os.getenv("JWT_EXPIRES_MIN", "1440"))  # default 24h

# Admin protection
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "").strip()

# CORS:
# - Allow Authorization (JWT) + X-API-Key + X-Admin-Token
# - Allow OPTIONS preflight
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

db = SQLAlchemy(app)

# -------------------------
# Stripe config
# -------------------------
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "").strip()
STRIPE_PRICE_ID = os.getenv("STRIPE_PRICE_ID", "").strip()   # must be price_...
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "").strip()
APP_BASE_URL = os.getenv("APP_BASE_URL", "https://676trades.org").strip()  # frontend
TRIAL_DAYS = int(os.getenv("TRIAL_DAYS", "5"))

if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY


# -------------------------
# Models
# -------------------------
class User(db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)

    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)

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

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    last_login_at = db.Column(db.DateTime, nullable=True)

    # Heartbeat / EA last seen (if you already added these previously, keep them)
    last_seen_at = db.Column(db.DateTime, nullable=True)
    last_seen_ip = db.Column(db.String(64), nullable=True)
    last_seen_symbol = db.Column(db.String(32), nullable=True)
    last_seen_tf = db.Column(db.String(16), nullable=True)


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
# CORS Preflight Hardening
# -------------------------
@app.before_request
def _preflight_ok():
    # Some setups fail preflight due to limiter/OPTIONS handling.
    # This guarantees OPTIONS returns OK + CORS headers.
    if request.method == "OPTIONS":
        origin = request.headers.get("Origin", "")
        resp = make_response("")
        if origin in FRONTEND_ORIGINS:
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Vary"] = "Origin"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-API-Key, X-Admin-Token"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        return resp


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


# -------------------------
# JWT helpers
# -------------------------
def create_jwt_for_user(user: User) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "iss": JWT_ISSUER,
        "sub": str(user.id),
        "email": user.email,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=JWT_EXPIRES_MIN)).timestamp()),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def get_user_from_jwt():
    auth = request.headers.get("Authorization", "").strip()
    if not auth.startswith("Bearer "):
        return None
    token = auth.split(" ", 1)[1].strip()
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"], issuer=JWT_ISSUER)
        uid = int(payload.get("sub"))
        return User.query.get(uid)
    except Exception:
        return None


def require_api_key():
    api_key = request.headers.get("X-API-Key", "").strip()
    if not api_key:
        return None, json_error("Missing X-API-Key header", 401)

    user = User.query.filter_by(api_key=api_key).first()
    if not user:
        return None, json_error("Invalid API key", 401)

    return user, None


def require_user():
    """
    Backward compatible:
    - EA uses X-API-Key
    - Frontend can use Bearer JWT
    """
    # 1) API key
    api_key = request.headers.get("X-API-Key", "").strip()
    if api_key:
        user = User.query.filter_by(api_key=api_key).first()
        if user:
            return user, None
        return None, json_error("Invalid API key", 401)

    # 2) JWT
    user = get_user_from_jwt()
    if user:
        return user, None

    return None, json_error("Unauthorized", 401)


def require_admin():
    token = request.headers.get("X-Admin-Token", "").strip()
    if not ADMIN_TOKEN:
        return json_error("Admin not configured.", 500)
    if not token or token != ADMIN_TOKEN:
        return json_error("Unauthorized", 401)
    return None


def trial_active(user: User) -> bool:
    if not user.trial_ends_at:
        return False
    now = datetime.now(timezone.utc)
    t = user.trial_ends_at
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return now < t


def is_paid_active(user: User) -> bool:
    return user.subscription_status == "active"


def ensure_can_trade(user: User):
    if is_paid_active(user) or trial_active(user):
        return None

    if user.enabled:
        user.enabled = False
        db.session.commit()

    return json_error("Payment required. Please start your free trial / subscribe.", 402)


def ea_connected(user: User, minutes: int = 5) -> bool:
    if not user.last_seen_at:
        return False
    now = datetime.now(timezone.utc)
    t = user.last_seen_at
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return now - t < timedelta(minutes=minutes)


# -------------------------
# Auto-migration (keeps Postgres from breaking)
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

        # heartbeat fields
        if "last_seen_at" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN last_seen_at TIMESTAMPTZ NULL')
        if "last_seen_ip" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN last_seen_ip VARCHAR(64) NULL')
        if "last_seen_symbol" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN last_seen_symbol VARCHAR(32) NULL')
        if "last_seen_tf" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN last_seen_tf VARCHAR(16) NULL')

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
# Routes: Health
# -------------------------
@app.get("/")
def root():
    return jsonify({"ok": True, "service": "mt5-control-backend", "version": "v1"})


@app.get("/health")
def health():
    return jsonify({"ok": True})


# -------------------------
# Routes: Auth (JWT + API key)
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
    )

    try:
        db.session.add(user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return json_error("Email already registered", 409)

    token = create_jwt_for_user(user)

    return jsonify({
        "ok": True,
        "message": "Registered",
        "api_key": api_key,
        "token": token,   # NEW (JWT)
    })


@app.post("/auth/login")
@limiter.limit("30 per hour")
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = (data.get("password") or "").strip()

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        return json_error("Invalid email or password", 401)

    user.last_login_at = datetime.now(timezone.utc)
    db.session.commit()

    token = create_jwt_for_user(user)

    return jsonify({
        "ok": True,
        "api_key": user.api_key,  # keep for EA / legacy frontend
        "token": token,           # NEW (JWT)
    })


@app.post("/auth/rotate-key")
@limiter.limit("10 per hour")
def rotate_key():
    # allow via JWT or API key
    user, err = require_user()
    if err:
        return err

    user.api_key = secrets.token_hex(24)
    db.session.commit()

    # rotate should also refresh JWT
    token = create_jwt_for_user(user)

    return jsonify({"ok": True, "api_key": user.api_key, "token": token})


# -------------------------
# Routes: Control (EA + Dashboard)
# -------------------------
@app.get("/api/v1/status")
@limiter.limit("120 per minute")
def status():
    user, err = require_user()
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

        # EA heartbeat snapshot
        "ea_connected": ea_connected(user),
        "last_seen_at": user.last_seen_at.isoformat() if user.last_seen_at else None,
    })


@app.post("/api/v1/toggle")
@limiter.limit("60 per minute")
def toggle():
    user, err = require_user()
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
    user, err = require_user()
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

    db.session.commit()
    return status()


# -------------------------
# EA Heartbeat (POST from EA)
# -------------------------
@app.post("/api/v1/heartbeat")
@limiter.limit("120 per minute")
def heartbeat():
    user, err = require_api_key()  # EA uses X-API-Key
    if err:
        return err

    data = request.get_json(silent=True) or {}
    symbol = (data.get("symbol") or "").strip().upper()[:32] or None
    tf = (data.get("tf") or "").strip()[:16] or None

    user.last_seen_at = datetime.now(timezone.utc)
    user.last_seen_ip = (request.headers.get("CF-Connecting-IP") or request.remote_addr or "")[:64]
    user.last_seen_symbol = symbol
    user.last_seen_tf = tf
    db.session.commit()

    return jsonify({"ok": True})


# -------------------------
# Billing routes (frontend uses JWT or X-API-Key)
# -------------------------
@app.get("/billing/status")
@limiter.limit("60 per minute")
def billing_status():
    user, err = require_user()
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
    user, err = require_user()
    if err:
        return err

    if not STRIPE_SECRET_KEY or not STRIPE_PRICE_ID:
        return json_error("Stripe not configured on server.", 500)

    if not user.stripe_customer_id:
        cust = stripe.Customer.create(email=user.email, metadata={"user_id": str(user.id)})
        user.stripe_customer_id = cust["id"]
        db.session.commit()

    if not user.trial_ends_at:
        user.trial_ends_at = datetime.now(timezone.utc) + timedelta(days=TRIAL_DAYS)
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
    user, err = require_user()
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
# Admin routes (example list users) - CORS now works
# -------------------------
@app.get("/admin/users")
@limiter.limit("60 per minute")
def admin_users():
    err = require_admin()
    if err:
        return err

    q = (request.args.get("q") or "").strip().lower()
    query = User.query
    if q:
        query = query.filter(User.email.ilike(f"%{q}%"))

    rows = query.order_by(User.id.desc()).limit(200).all()

    items = []
    for u in rows:
        items.append({
            "id": u.id,
            "email": u.email,
            "plan": u.plan,
            "subscription_status": u.subscription_status,
            "enabled": bool(u.enabled),
            "pairs": u.pairs,
            "online": ea_connected(u),
            "last_seen_at": u.last_seen_at.isoformat() if u.last_seen_at else None,
        })

    return jsonify({"ok": True, "items": items})


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
# Trades routes
# -------------------------
@app.post("/api/v1/trades")
@limiter.limit("120 per minute")
def post_trade():
    user, err = require_api_key()  # EA posts trades
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
    user, err = require_user()
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
