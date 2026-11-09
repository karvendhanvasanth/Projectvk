import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import smtplib
import sqlite3
import time
from email.message import EmailMessage
from pathlib import Path
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.getenv("DATABASE_PATH", ROOT / "data" / "northstar.db"))
APP_ENV = os.getenv("APP_ENV", "development").lower()
SECRET_KEY = os.getenv("SECRET_KEY", "dev-only-change-this-secret-before-deploying")
COOKIE_NAME = "northstar_session"
SESSION_SECONDS = 604800
RESET_SECONDS = 1800
ROUNDS = 310000
if APP_ENV == "production" and SECRET_KEY == "dev-only-change-this-secret-before-deploying":
    raise RuntimeError("Set SECRET_KEY before production.")
app = FastAPI(title="Northstar Authentication API", version="1.0.0")

def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    return db

def init_db():
    with connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,email TEXT NOT NULL UNIQUE COLLATE NOCASE,password_hash TEXT NOT NULL,created_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS password_resets(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,token_hash TEXT NOT NULL UNIQUE,expires_at INTEGER NOT NULL,used INTEGER NOT NULL DEFAULT 0,created_at INTEGER NOT NULL);
        """)
        db.commit()

@app.on_event("startup")
def startup(): init_db()

class RegisterBody(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
class LoginBody(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)
class ForgotBody(BaseModel):
    email: EmailStr
class ResetBody(BaseModel):
    token: str = Field(min_length=32, max_length=256)
    password: str = Field(min_length=8, max_length=128)

def password_hash(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ROUNDS)
    return base64.urlsafe_b64encode(salt).decode() + "$" + base64.urlsafe_b64encode(digest).decode()

def verify_password(password, stored):
    try:
        salt_text, _ = stored.split("$", 1)
        salt = base64.urlsafe_b64decode(salt_text.encode())
        return hmac.compare_digest(password_hash(password, salt), stored)
    except (ValueError, TypeError): return False

def issue_session(user_id):
    payload = base64.urlsafe_b64encode(json.dumps({"sub": user_id, "exp": int(time.time()) + SESSION_SECONDS}, separators=(",", ":")).encode()).decode().rstrip("=")
    signature = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).digest()
    return payload + "." + base64.urlsafe_b64encode(signature).decode().rstrip("=")

def read_session(token):
    try:
        payload, signature = token.split(".", 1)
        expected = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).digest()
        supplied = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
        if not hmac.compare_digest(expected, supplied): return None
        data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        return int(data["sub"]) if data["exp"] >= int(time.time()) else None
    except (ValueError, KeyError, TypeError, json.JSONDecodeError): return None

def current_user(request: Request):
    token = request.cookies.get(COOKIE_NAME)
    user_id = read_session(token) if token else None
    if not user_id: raise HTTPException(status_code=401, detail="Please sign in to continue.")
    with connect() as db:
        user = db.execute("SELECT id,name,email,created_at FROM users WHERE id=?", (user_id,)).fetchone()
    if not user: raise HTTPException(status_code=401, detail="Session is no longer valid.")
    return dict(user)

def send_reset_email(email, token):
    host = os.getenv("SMTP_HOST")
    url = os.getenv("APP_BASE_URL", "http://localhost:8000") + "/?reset_token=" + token + "#reset"
    if not host:
        if APP_ENV == "development": print(f"[DEV PASSWORD RESET] {email}: {url}")
        return
    message = EmailMessage()
    message["Subject"] = "Reset your Northstar password"
    message["From"] = os.getenv("SMTP_FROM", os.getenv("SMTP_USER", "no-reply@localhost"))
    message["To"] = email
    message.set_content("We received a request to reset your Northstar password. This link expires in 30 minutes:\n" + url + "\n\nIf you did not request this, ignore this email.")
    with smtplib.SMTP(host, int(os.getenv("SMTP_PORT", "587"))) as server:
        server.starttls()
        if os.getenv("SMTP_USER"): server.login(os.getenv("SMTP_USER"), os.getenv("SMTP_PASSWORD", ""))
        server.send_message(message)

@app.get("/api/health")
def health(): return {"status":"ok","database":"sqlite"}

@app.post("/api/register", status_code=201)
def register(body: RegisterBody, response: Response):
    name, email = body.name.strip(), str(body.email).strip().lower()
    if len(name) < 2 or not re.search(r"\d", body.password):
        raise HTTPException(status_code=400, detail="Use a name with at least 2 characters and a password with at least one number.")
    with connect() as db:
        if db.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
            raise HTTPException(status_code=409, detail="An account with this email already exists.")
        cursor = db.execute("INSERT INTO users(name,email,password_hash,created_at) VALUES(?,?,?,?)", (name,email,password_hash(body.password),int(time.time())))
        db.commit()
        user_id = cursor.lastrowid
    response.set_cookie(COOKIE_NAME, issue_session(user_id), httponly=True, secure=APP_ENV=="production", samesite="lax", max_age=SESSION_SECONDS, path="/")
    return {"message":"Account created successfully.","user":{"id":user_id,"name":name,"email":email}}

@app.post("/api/login")
def login(body: LoginBody, response: Response):
    with connect() as db: user = db.execute("SELECT * FROM users WHERE email=?", (str(body.email).lower(),)).fetchone()
    if not user or not verify_password(body.password,user["password_hash"]):
        raise HTTPException(status_code=401, detail="Email or password is incorrect.")
    response.set_cookie(COOKIE_NAME, issue_session(user["id"]), httponly=True, secure=APP_ENV=="production", samesite="lax", max_age=SESSION_SECONDS, path="/")
    return {"message":"Signed in successfully.","user":{"id":user["id"],"name":user["name"],"email":user["email"]}}

@app.get("/api/me")
def me(user=Depends(current_user)): return {"user":user}

@app.post("/api/logout")
def logout(response: Response):
    response.delete_cookie(COOKIE_NAME,path="/",httponly=True,samesite="lax",secure=APP_ENV=="production")
    return {"message":"Signed out."}

@app.post("/api/forgot-password")
def forgot_password(body: ForgotBody):
    email = str(body.email).lower()
    with connect() as db:
        user = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if user:
            token = secrets.token_urlsafe(32)
            db.execute("UPDATE password_resets SET used=1 WHERE user_id=? AND used=0", (user["id"],))
            db.execute("INSERT INTO password_resets(user_id,token_hash,expires_at,created_at) VALUES(?,?,?,?)", (user["id"],hashlib.sha256(token.encode()).hexdigest(),int(time.time())+RESET_SECONDS,int(time.time())))
            db.commit()
            send_reset_email(email,token)
            if APP_ENV == "development":
                return {"message":"If an account exists, reset instructions have been prepared.","development_reset_url":os.getenv("APP_BASE_URL","http://localhost:8000")+"/?reset_token="+token+"#reset"}
    return {"message":"If an account exists for this email, reset instructions will be sent."}

@app.post("/api/reset-password")
def reset_password(body: ResetBody):
    if not re.search(r"\d", body.password): raise HTTPException(status_code=400,detail="Password must contain at least one number.")
    token_hash = hashlib.sha256(body.token.encode()).hexdigest()
    with connect() as db:
        reset = db.execute("SELECT id,user_id FROM password_resets WHERE token_hash=? AND used=0 AND expires_at>?", (token_hash,int(time.time()))).fetchone()
        if not reset: raise HTTPException(status_code=400,detail="This reset link is invalid or has expired.")
        db.execute("UPDATE users SET password_hash=? WHERE id=?", (password_hash(body.password),reset["user_id"]))
        db.execute("UPDATE password_resets SET used=1 WHERE user_id=?", (reset["user_id"],))
        db.commit()
    return {"message":"Password updated. You can now sign in."}

app.mount("/", StaticFiles(directory=ROOT, html=True), name="website")
