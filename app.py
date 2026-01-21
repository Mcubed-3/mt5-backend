import os
import secrets
from datetime import datetime

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
    pair = db.Column(db.String(20), default="XAUUSD", nullable=False)
    lot_size = db.Column(db.Float, default=0.01, nullable=False)

    # -------------------------
    # SL/TP Controls (NEW)
    # -------------------------
    # sl_mode: dynamic|fixed
    sl_mode = db.Column(db.String(20), default="dynamic", nullable=False)
    # tp_mode: rr|pattern_mult|fixed
    tp_mode = db.Column(db.String(20), default="rr", nullable=False)

    # minimum pips we allow for risk/targets
    min_pips = db.Column(db.Integer, default=50, nullable=False)
    # buffer beyond pattern high/low when SL is dynamic
    sl_buffer_pips = db.Column(db.Integer, default=5, nullable=False)

    # if tp_mode=rr then TP = risk * rr
    rr = db.Column(db.Float, default=1.0, nullable=False)
    # if tp_mode=pattern_mult then TP = pattern_size * pattern_tp_mult
    pattern_tp_mult = db.Column(db.Float, default=1.5, nullable=False)

    # if sl_mode=fixed / tp_mode=fixed
    fixed_sl_pips = db.Column(db.Integer, default=50, nullable=False)
    fixed_tp_pips = db.Column(db.Integer, default=50, nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


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
        enabled=False,
        pair="XAUUSD",
        lot_size=0.01,
        # SL/TP defaults already set by model defaults
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

    return jsonify({
        "ok": True,
        "enabled": bool(user.enabled),
        "pair": user.pair,
        "lot_size": float(user.lot_size),

        # SL/TP
        "sl_mode": user.sl_mode,
        "tp_mode": user.tp_mode,
        "min_pips": int(user.min_pips),
        "sl_buffer_pips": int(user.sl_buffer_pips),
        "rr": float(user.rr),
        "pattern_tp_mult": float(user.pattern_tp_mult),
        "fixed_sl_pips": int(user.fixed_sl_pips),
        "fixed_tp_pips": int(user.fixed_tp_pips),
    })


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

    # ---- basic settings ----
    if "pair" in data:
        pair = str(data["pair"]).strip().upper()
        if len(pair) < 3 or len(pair) > 12:
            return json_error("pair looks invalid", 400)
        user.pair = pair

    if "lot_size" in data:
        try:
            lot = float(data["lot_size"])
        except ValueError:
            return json_error("lot_size must be a number", 400)

        if lot <= 0 or lot > 100:
            return json_error("lot_size out of range", 400)
        user.lot_size = lot

    # ---- SL/TP modes ----
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

    # ---- integers ----
    for k in ("min_pips", "sl_buffer_pips", "fixed_sl_pips", "fixed_tp_pips"):
        if k in data:
            try:
                v = int(data[k])
            except ValueError:
                return json_error(f"{k} must be an integer", 400)
            if v < 0 or v > 5000:
                return json_error(f"{k} out of range", 400)
            setattr(user, k, v)

    # ---- floats ----
    for k in ("rr", "pattern_tp_mult"):
        if k in data:
            try:
                v = float(data[k])
            except ValueError:
                return json_error(f"{k} must be a number", 400)
            if v <= 0 or v > 50:
                return json_error(f"{k} out of range", 400)
            setattr(user, k, v)

    db.session.commit()

    # return everything so UI can refresh instantly
    return jsonify({
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
    })


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
