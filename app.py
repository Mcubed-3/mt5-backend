import os
import secrets
from datetime import datetime

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError

# -------------------------
# App / Config
# -------------------------
app = Flask(__name__)

# Allow ONLY your Cloudflare Pages front-end to call this API from the browser
CORS(
    app,
    resources={r"/*": {"origins": ["https://676trades.org", "https://www.676trades.org"]}},
)

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///db.sqlite3")

# Normalize Render-style Postgres URLs
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Force psycopg v3 driver (prevents SQLAlchemy from defaulting to psycopg2)
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# -------------------------
# Models
# -------------------------
class User(db.Model):
    __tablename__ = "user"  # keep explicit since Postgres is case-sensitive-ish with quoting

    id = db.Column(db.Integer, primary_key=True)

    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)

    api_key = db.Column(db.String(64), unique=True, nullable=False, index=True)

    enabled = db.Column(db.Boolean, default=False, nullable=False)
    pair = db.Column(db.String(20), default="XAUUSD", nullable=False)
    lot_size = db.Column(db.Float, default=0.01, nullable=False)

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
    )

    try:
        db.session.add(user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return json_error("Email already registered", 409)

    return jsonify({"ok": True, "message": "Registered", "api_key": api_key})

@app.post("/auth/login")
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = (data.get("password") or "").strip()

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        return json_error("Invalid email or password", 401)

    return jsonify({"ok": True, "api_key": user.api_key})

# -------------------------
# Routes: EA + Dashboard Control (API key protected)
# -------------------------
@app.get("/api/v1/status")
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
        }
    )

@app.post("/api/v1/toggle")
def toggle():
    user, err = require_api_key()
    if err:
        return err

    user.enabled = not user.enabled
    db.session.commit()

    return jsonify({"ok": True, "enabled": bool(user.enabled)})

@app.post("/api/v1/settings")
def settings():
    user, err = require_api_key()
    if err:
        return err

    data = request.get_json(silent=True) or {}

    pair = data.get("pair", None)
    lot_size = data.get("lot_size", None)

    if pair is not None:
        pair = str(pair).strip().upper()
        if len(pair) < 3 or len(pair) > 12:
            return json_error("pair looks invalid", 400)
        user.pair = pair

    if lot_size is not None:
        try:
            lot_size = float(lot_size)
        except ValueError:
            return json_error("lot_size must be a number", 400)

        if lot_size <= 0 or lot_size > 100:
            return json_error("lot_size out of range", 400)
        user.lot_size = lot_size

    db.session.commit()

    return jsonify(
        {
            "ok": True,
            "enabled": bool(user.enabled),
            "pair": user.pair,
            "lot_size": float(user.lot_size),
        }
    )

# -------------------------
# Ensure tables exist (safe in prod; will create if missing)
# -------------------------
with app.app_context():
    db.create_all()

# -------------------------
# Local run (Render uses gunicorn)
# -------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))

