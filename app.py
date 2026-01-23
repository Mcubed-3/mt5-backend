import os
import secrets
from datetime import datetime, timezone

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

# CORS: allow ONLY your frontend origins
CORS(
    app,
    resources={r"/*": {"origins": ["https://676trades.org", "https://www.676trades.org"]}},
)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["60 per minute"],
)

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///db.sqlite3")

# Normalize Postgres URLs and force psycopg v3
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# -------------------------
# Stripe config (Render env vars)
# -------------------------
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "").strip()
STRIPE_PRICE_ID = os.getenv("STRIPE_PRICE_ID", "").strip()
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "").strip()

# Where Stripe sends users back after checkout
FRONTEND_URL = os.getenv("FRONTEND_URL", "https://676trades.org").strip().rstrip("/")

if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY


# -------------------------
# Plan rules
# -------------------------
FREE_MAX_PAIRS = 1
PRO_MAX_PAIRS = 4

FREE_MAX_LOT = 0.01
PRO_MAX_LOT = 1.0


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

    # Backward compatible (single symbol)
    pair = db.Column(db.String(20), default="XAUUSD", nullable=False)

    # NEW: multiple symbols as CSV: "XAUUSD,EURUSD,GBPUSD,USDJPY"
    pairs = db.Column(db.String(255), default="XAUUSD", nullable=False)

    lot_size = db.Column(db.Float, default=0.01, nullable=False)

    # --- SL/TP settings ---
    sl_mode = db.Column(db.String(20), default="dynamic", nullable=False)          # dynamic | fixed
    tp_mode = db.Column(db.String(20), default="rr", nullable=False)              # rr | pattern_mult | fixed

    min_pips = db.Column(db.Integer, default=50, nullable=False)
    sl_buffer_pips = db.Column(db.Integer, default=5, nullable=False)

    rr = db.Column(db.Float, default=1.0, nullable=False)
    pattern_tp_mult = db.Column(db.Float, default=1.5, nullable=False)

    fixed_sl_pips = db.Column(db.Integer, default=50, nullable=False)
    fixed_tp_pips = db.Column(db.Integer, default=50, nullable=False)

    # --- account profile fields (useful now) ---
    display_name = db.Column(db.String(80), nullable=True)
    last_login_at = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # --- Stripe subscription fields ---
    plan = db.Column(db.String(20), default="free", nullable=False)  # free/pro
    subscription_status = db.Column(db.String(20), default="none", nullable=False)  # none/trialing/active/past_due/canceled/incomplete
    stripe_customer_id = db.Column(db.String(80), nullable=True, index=True)
    stripe_subscription_id = db.Column(db.String(80), nullable=True, index=True)

    # useful timestamps (optional but helpful)
    trial_ends_at = db.Column(db.DateTime, nullable=True)
    current_period_end = db.Column(db.DateTime, nullable=True)


class Trade(db.Model):
    __tablename__ = "trade"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), index=True, nullable=False)
    user = db.relationship("User", backref="trades")

    symbol = db.Column(db.String(20), nullable=False)
    side = db.Column(db.String(10), nullable=False)  # BUY / SELL

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


def require_api_key():
    api_key = request.headers.get("X-API-Key", "").strip()
    if not api_key:
        return None, json_error("Missing X-API-Key header", 401)

    user = User.query.filter_by(api_key=api_key).first()
    if not user:
        return None, json_error("Invalid API key", 401)

    return user, None


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


def has_access(user: User) -> bool:
    """
    Only allow EA control when user is trialing or active.
    """
    return (user.subscription_status in ("trialing", "active"))


def plan_limits(user: User):
    if has_access(user):
        return ("pro", PRO_MAX_PAIRS, PRO_MAX_LOT)
    return ("free", FREE_MAX_PAIRS, FREE_MAX_LOT)


def clamp_enabled_for_unpaid(user: User):
    """
    Safety: unpaid users must never have enabled=true.
    """
    if not has_access(user) and user.enabled:
        user.enabled = False
        db.session.commit()


def unix_to_dt(ts):
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc)
    except Exception:
        return None


# -------------------------
# Auto-migration
# -------------------------
def ensure_schema():
    uri = app.config["SQLALCHEMY_DATABASE_URI"]
    is_postgres = uri.startswith("postgresql")
    if not is_postgres:
        db.create_all()
        return

    with db.engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS "user" (
                id SERIAL PRIMARY KEY
            )
        """))

        cols = {
            r[0]
            for r in conn.execute(text("""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_schema='public' AND table_name='user'
            """)).fetchall()
        }

        def add_col(sql: str):
            conn.execute(text(sql))

        # base auth
        if "email" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN email VARCHAR(255)')
            add_col('CREATE UNIQUE INDEX IF NOT EXISTS ix_user_email ON "user"(email)')
        if "password_hash" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN password_hash VARCHAR(255)')
        if "api_key" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN api_key VARCHAR(64)')
            add_col('CREATE UNIQUE INDEX IF NOT EXISTS ix_user_api_key ON "user"(api_key)')

        # core settings
        if "enabled" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN enabled BOOLEAN NOT NULL DEFAULT FALSE')
        if "pair" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN pair VARCHAR(20) NOT NULL DEFAULT \'XAUUSD\'')
        if "pairs" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN pairs VARCHAR(255) NOT NULL DEFAULT \'XAUUSD\'')
        if "lot_size" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN lot_size DOUBLE PRECISION NOT NULL DEFAULT 0.01')

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

        # profile
        if "display_name" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN display_name VARCHAR(80)')
        if "last_login_at" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN last_login_at TIMESTAMPTZ')
        if "created_at" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()')

        # stripe fields
        if "plan" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN plan VARCHAR(20) NOT NULL DEFAULT \'free\'')
        if "subscription_status" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN subscription_status VARCHAR(20) NOT NULL DEFAULT \'none\'')
        if "stripe_customer_id" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN stripe_customer_id VARCHAR(80)')
            add_col('CREATE INDEX IF NOT EXISTS ix_user_stripe_customer_id ON "user"(stripe_customer_id)')
        if "stripe_subscription_id" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN stripe_subscription_id VARCHAR(80)')
            add_col('CREATE INDEX IF NOT EXISTS ix_user_stripe_subscription_id ON "user"(stripe_subscription_id)')
        if "trial_ends_at" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN trial_ends_at TIMESTAMPTZ')
        if "current_period_end" not in cols:
            add_col('ALTER TABLE "user" ADD COLUMN current_period_end TIMESTAMPTZ')

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
# Stripe helpers
# -------------------------
def stripe_enabled():
    return bool(STRIPE_SECRET_KEY and STRIPE_PRICE_ID)


def update_user_from_subscription(user: User, sub: dict):
    """
    sub is Stripe subscription object (dict).
    """
    status = (sub.get("status") or "none").lower()
    user.subscription_status = status

    user.stripe_subscription_id = sub.get("id") or user.stripe_subscription_id

    # trial_end/current_period_end are unix timestamps
    user.trial_ends_at = unix_to_dt(sub.get("trial_end"))
    user.current_period_end = unix_to_dt(sub.get("current_period_end"))

    # plan mapping: trialing/active => pro else free
    user.plan = "pro" if status in ("trialing", "active") else "free"


# -------------------------
# Routes: Health
# -------------------------
@app.get("/")
def root():
    return jsonify({"ok": True, "service": "mt5-control-backend", "version": "v2"})


@app.get("/health")
def health():
    return jsonify({"ok": True, "stripe": stripe_enabled()})


# -------------------------
# Routes: Auth
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

    user.last_login_at = datetime.now(timezone.utc)
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
    db.session.commit()

    return jsonify({"ok": True, "api_key": user.api_key})


# -------------------------
# Routes: Billing (Stripe)
# -------------------------
@app.get("/billing/status")
@limiter.limit("60 per minute")
def billing_status():
    user, err = require_api_key()
    if err:
        return err

    clamp_enabled_for_unpaid(user)

    return jsonify({
        "ok": True,
        "plan": user.plan,
        "subscription_status": user.subscription_status,
        "trial_ends_at": user.trial_ends_at.isoformat() if user.trial_ends_at else None,
        "current_period_end": user.current_period_end.isoformat() if user.current_period_end else None,
        "has_access": has_access(user),
    })


@app.post("/billing/checkout")
@limiter.limit("30 per hour")
def billing_checkout():
    """
    Creates a Stripe Checkout session for subscription.
    The 5-day trial is enforced by Stripe.
    """
    if not stripe_enabled():
        return json_error("Stripe is not configured on the server.", 500)

    user, err = require_api_key()
    if err:
        return err

    # Create Stripe customer if needed
    if not user.stripe_customer_id:
        cust = stripe.Customer.create(email=user.email, metadata={"user_id": str(user.id)})
        user.stripe_customer_id = cust["id"]
        db.session.commit()

    success_url = f"{FRONTEND_URL}/billing.html?success=1"
    cancel_url = f"{FRONTEND_URL}/billing.html?canceled=1"

    session = stripe.checkout.Session.create(
        mode="subscription",
        customer=user.stripe_customer_id,
        line_items=[{"price": STRIPE_PRICE_ID, "quantity": 1}],
        subscription_data={
            "trial_period_days": 5,   # ✅ your free trial
            "metadata": {"user_id": str(user.id)}
        },
        client_reference_id=str(user.id),
        success_url=success_url,
        cancel_url=cancel_url,
    )

    return jsonify({"ok": True, "checkout_url": session["url"]})


@app.post("/billing/webhook")
def stripe_webhook():
    """
    Stripe sends subscription updates here.
    Make sure STRIPE_WEBHOOK_SECRET is set.
    """
    if not STRIPE_WEBHOOK_SECRET:
        return json_error("Webhook secret not configured.", 500)

    payload = request.data
    sig_header = request.headers.get("Stripe-Signature", "")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except Exception:
        return json_error("Invalid webhook signature", 400)

    event_type = event.get("type")
    obj = event.get("data", {}).get("object", {})

    # 1) Checkout finished (customer paid/started subscription)
    if event_type == "checkout.session.completed":
        customer_id = obj.get("customer")
        subscription_id = obj.get("subscription")

        user = None
        if customer_id:
            user = User.query.filter_by(stripe_customer_id=customer_id).first()

        if user and subscription_id:
            try:
                sub = stripe.Subscription.retrieve(subscription_id)
                update_user_from_subscription(user, sub)
                db.session.commit()
            except Exception:
                pass

    # 2) Subscription lifecycle changes
    if event_type in ("customer.subscription.created", "customer.subscription.updated", "customer.subscription.deleted"):
        customer_id = obj.get("customer")
        subscription_id = obj.get("id")

        user = None
        if customer_id:
            user = User.query.filter_by(stripe_customer_id=customer_id).first()

        if user:
            update_user_from_subscription(user, obj)
            # If canceled/inactive -> disable EA immediately
            clamp_enabled_for_unpaid(user)
            db.session.commit()

    return jsonify({"ok": True})


# -------------------------
# Routes: Control (EA + Dashboard)
# -------------------------
@app.get("/api/v1/status")
@limiter.limit("120 per minute")
def status():
    user, err = require_api_key()
    if err:
        return err

    clamp_enabled_for_unpaid(user)

    pairs_csv = (user.pairs or user.pair or "XAUUSD").strip() or "XAUUSD"

    return jsonify({
        "ok": True,
        "enabled": bool(user.enabled),

        "pair": first_pair(pairs_csv),   # backward compatibility
        "pairs": pairs_csv,              # new

        "lot_size": float(user.lot_size),

        "sl_mode": user.sl_mode,
        "tp_mode": user.tp_mode,
        "min_pips": int(user.min_pips),
        "sl_buffer_pips": int(user.sl_buffer_pips),
        "rr": float(user.rr),
        "pattern_tp_mult": float(user.pattern_tp_mult),
        "fixed_sl_pips": int(user.fixed_sl_pips),
        "fixed_tp_pips": int(user.fixed_tp_pips),

        # billing info (useful for UI)
        "plan": user.plan,
        "subscription_status": user.subscription_status,
        "has_access": has_access(user),
    })


@app.post("/api/v1/toggle")
@limiter.limit("60 per minute")
def toggle():
    user, err = require_api_key()
    if err:
        return err

    if not has_access(user):
        user.enabled = False
        db.session.commit()
        return json_error("Payment required. Please subscribe to enable the algorithm.", 402)

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

    if not has_access(user):
        user.enabled = False
        db.session.commit()
        return json_error("Payment required. Please subscribe to change settings.", 402)

    # enforce plan limits
    plan_name, max_pairs, max_lot = plan_limits(user)

    data = request.get_json(silent=True) or {}

    # pairs (accept "pairs" OR "pair")
    if "pairs" in data:
        try:
            csv = normalize_pairs(str(data["pairs"]))
        except ValueError as e:
            return json_error(str(e), 400)

        count = len(csv.split(","))
        if count > max_pairs:
            return json_error(f"Plan limit: max {max_pairs} pairs for {plan_name}.", 403)

        user.pairs = csv
        user.pair = first_pair(csv)  # keep single in sync

    if "pair" in data and "pairs" not in data:
        try:
            csv = normalize_pairs(str(data["pair"]))
        except ValueError as e:
            return json_error(str(e), 400)

        count = len(csv.split(","))
        if count > max_pairs:
            return json_error(f"Plan limit: max {max_pairs} pairs for {plan_name}.", 403)

        user.pairs = csv
        user.pair = first_pair(csv)

    # lot size
    if "lot_size" in data:
        lot = safe_float(data["lot_size"])
        if lot is None:
            return json_error("lot_size must be a number", 400)
        if lot <= 0 or lot > 100:
            return json_error("lot_size out of range", 400)
        if lot > max_lot:
            return json_error(f"Plan limit: max lot size {max_lot} for {plan_name}.", 403)
        user.lot_size = lot

    # sl/tp modes
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

    # bounds
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
# Routes: Trades (EA posts results, UI reads)
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
# Local run (Render uses gunicorn)
# -------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
