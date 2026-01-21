import os
import secrets
from datetime import datetime, timezone

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


# -------------------------
# App / Config
# -------------------------
app = Flask(__name__)

# CORS: allow ONLY your frontend origins
CORS(
    app,
    resources={r"/*": {"origins": ["https://676trades.org", "https://www.676trades.org"]}},
)

# Rate limiting: global defaults
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
# Models
# -------------------------
class User(db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)

    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)

    api_key = db.Column(db.String(64), unique=True, nullable=False, index=True)

    enabled = db.Column(db.Boolean, default=False, nullable=False)

    # NOTE: allow comma-separated symbols list here (length increased)
    pair = db.Column(db.String(128), default="XAUUSD", nullable=False)

    lot_size = db.Column(db.Float, default=0.01, nullable=False)

    # --- SL/TP settings ---
    sl_mode = db.Column(db.String(20), default="dynamic", nullable=False)     # dynamic | fixed
    tp_mode = db.Column(db.String(20), default="rr", nullable=False)          # rr | pattern_mult | fixed

    min_pips = db.Column(db.Integer, default=50, nullable=False)
    sl_buffer_pips = db.Column(db.Integer, default=5, nullable=False)

    rr = db.Column(db.Float, default=1.0, nullable=False)
    pattern_tp_mult = db.Column(db.Float, default=1.5, nullable=False)

    fixed_sl_pips = db.Column(db.Integer, default=50, nullable=False)
    fixed_tp_pips = db.Column(db.Integer, default=50, nullable=False)

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)


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


def validate_symbol_list(raw: str):
    """
    Accept:
      - "XAUUSD"
      - "XAUUSD,EURUSD,GBPUSD,USDJPY"
    Enforces safe characters and per-symbol length.
    Returns (cleaned_string, list_of_symbols) or (None, None) on invalid.
    """
    s = (raw or "").strip().upper()
    if not s:
        return None, None

    # overall length guard
    if len(s) < 3 or len(s) > 128:
        return None, None

    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,_.")
    if any(ch not in allowed for ch in s):
        return None, None

    parts = [p.strip() for p in s.split(",") if p.strip()]
    if not parts:
        return None, None

    # each symbol sanity check
    for p in parts:
        if len(p) < 3 or len(p) > 20:
            return None, None

    # de-dupe while keeping order
    seen = set()
    uniq = []
    for p in parts:
        if p not in seen:
            seen.add(p)
            uniq.append(p)

    return ",".join(uniq), uniq


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
# Routes: Control (EA + Dashboard)
# -------------------------
@app.get("/api/v1/status")
@limiter.limit("120 per minute")
def status():
    user, err = require_api_key()
    if err:
        return err

    return jsonify(
        {
            "ok": True,
            "enabled": bool(user.enabled),
            "pair": user.pair,
            "lot_size": float(user.lot_size),

            "sl_mode": user.sl_mode,
            "tp_mode": user.tp_mode,
            "min_pips": int(user.min_pips),
            "sl_buffer_pips": int(user.sl_buffer_pips),
            "rr": float(user.rr),
            "pattern_tp_mult": float(user.pattern_tp_mult),
            "fixed_sl_pips": int(user.fixed_sl_pips),
            "fixed_tp_pips": int(user.fixed_tp_pips),
        }
    )


@app.post("/api/v1/toggle")
@limiter.limit("60 per minute")
def toggle():
    user, err = require_api_key()
    if err:
        return err

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

    data = request.get_json(silent=True) or {}

    # basic
    if "pair" in data:
        cleaned, _symbols = validate_symbol_list(str(data["pair"]))
        if not cleaned:
            return json_error("pair/symbol list looks invalid", 400)
        user.pair = cleaned

    if "lot_size" in data:
        lot = safe_float(data["lot_size"])
        if lot is None:
            return json_error("lot_size must be a number", 400)
        if lot <= 0 or lot > 100:
            return json_error("lot_size out of range", 400)
        user.lot_size = lot

    # sl/tp settings
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

    # ints/floats with bounds
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
    return status()  # return full settings


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

    return jsonify(
        {
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
            ],
        }
    )


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
# Ensure tables exist
# -------------------------
with app.app_context():
    db.create_all()


# -------------------------
# Local run (Render uses gunicorn)
# -------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
