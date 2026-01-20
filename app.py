import os
import secrets
from datetime import datetime
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from sqlalchemy.exc import IntegrityError

# -------------------------
# App / Config
# -------------------------
app = Flask(__name__)
CORS(app)

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///db.sqlite3")

# Normalize Render URLs
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Force psycopg v3 (prevents psycopg2 errors)
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace(
        "postgresql://", "postgresql+psycopg://", 1
    )

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# -------------------------
# Models
# -------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)

    api_key = db.Column(db.String(64), unique=True, nullable=False, index=True)

    enabled = db.Column(db.Boolean, default=False, nullable=False)
    pair = db.Column(db.String(20), default="XAUUSD", nullable=False)
    lot_size = db.Column(db.Float, default=0.01, nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

# -------------------------
# TEMP ADMIN ROUTE (DB INIT)
# -------------------------
@app.get("/admin/init-db")
def init_db():
    with app.app_context():
        db.create_all()
    return jsonify({"ok": True, "message": "Database tables created."})

# -------------------------
# Helpers
# -------------------------
def json_error(message, code=400):
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
        return json_error("Email and password required")

    api_key = secrets.token_hex(24)

    user = User(
        email=email,
        password_hash=generate_password_hash(password),
        api_key=api_key,
        enabled=False,
        pair="XAUUSD",
        lot_size=0.01
    )

    try:
        db.session.add(user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return json_error("Email already registered", 409)

    return jsonify({
        "ok": True,
        "message": "Registered",
        "api_key": api_key
    })

@app.post("/auth/login")
def login():
    data = request.get_json(silent=True) or {}
