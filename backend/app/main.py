from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from datetime import date, datetime, time as datetime_time, timezone
from pathlib import Path
from typing import Iterator
from urllib.parse import urlsplit

import psycopg
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from psycopg.rows import dict_row

ROOT = Path(__file__).resolve().parents[2]
FRONTEND = ROOT / "frontend"
# For local development, use the project .env values even if an old shell export
# is still set. Render injects its own environment and does not deploy this file.
load_dotenv(ROOT / ".env", override=True)

configured_db = os.getenv("DATABASE_PATH", "./data/shortener.sqlite")
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
USE_POSTGRES = DATABASE_URL.startswith(("postgres://", "postgresql://"))
if DATABASE_URL and not USE_POSTGRES:
    raise RuntimeError("DATABASE_URL must be a PostgreSQL connection URI")
DB_PATH = Path(configured_db)
if not USE_POSTGRES:
    if not DB_PATH.is_absolute():
        DB_PATH = ROOT / DB_PATH
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
SCHEMA_PATH = Path(__file__).with_name("schema.postgres.sql" if USE_POSTGRES else "schema.sql")

app = FastAPI(title="Custom URL Shortener", version="1.0.0")
request_attempts: dict[str, list[float]] = {}


@app.exception_handler(HTTPException)
async def http_error_response(_request: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"error": exc.detail}, headers=exc.headers)


@app.exception_handler(RequestValidationError)
async def validation_error_response(_request: Request, _exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(status_code=422, content={"error": "Invalid request data"})


class DatabaseConnection:
    """Small adapter so the same query code works with SQLite and PostgreSQL."""

    def __init__(self, connection, postgres: bool):
        self.raw = connection
        self.postgres = postgres

    def execute(self, statement: str, parameters=()):
        if self.postgres:
            statement = statement.replace("?", "%s")
        return self.raw.execute(statement, parameters)


@contextmanager
def connect_db() -> Iterator[DatabaseConnection]:
    if USE_POSTGRES:
        raw_connection = psycopg.connect(DATABASE_URL, row_factory=dict_row)
    else:
        raw_connection = sqlite3.connect(DB_PATH, timeout=10)
        raw_connection.row_factory = sqlite3.Row
        raw_connection.execute("PRAGMA foreign_keys = ON")
    connection = DatabaseConnection(raw_connection, USE_POSTGRES)
    try:
        yield connection
        raw_connection.commit()
    except Exception:
        raw_connection.rollback()
        raise
    finally:
        raw_connection.close()


def initialize_database() -> None:
    with connect_db() as connection:
        if USE_POSTGRES:
            schema = SCHEMA_PATH.read_text(encoding="utf-8")
            for statement in schema.split(";"):
                if statement.strip():
                    connection.execute(statement)
        else:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.raw.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
            api_columns = {row["name"] for row in connection.execute("PRAGMA table_info(api_keys)")}
            if "expires_at" not in api_columns:
                connection.execute("ALTER TABLE api_keys ADD COLUMN expires_at TEXT")
            request_columns = {row["name"] for row in connection.execute("PRAGMA table_info(api_key_requests)")}
            if "requested_expires_at" not in request_columns:
                connection.execute("ALTER TABLE api_key_requests ADD COLUMN requested_expires_at TEXT")


initialize_database()


class ShortenBody(BaseModel):
    url: str = Field(min_length=1, max_length=8192)


class KeyRequestBody(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    email: str = Field(min_length=3, max_length=254)
    reason: str = Field(default="", max_length=1000)
    expiresAt: str


class AdminKeyBody(BaseModel):
    owner: str = Field(min_length=1, max_length=120)
    email: str = Field(default="", max_length=254)
    expiresAt: str = ""


class ExpirationBody(BaseModel):
    expiresAt: str = ""


class LoginBody(BaseModel):
    username: str = ""
    password: str = ""


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def as_utc_datetime(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def api_key_auth(request: Request) -> dict:
    authorization = request.headers.get("authorization", "")
    bearer_match = re.match(r"^Bearer\s+(.+)$", authorization, re.IGNORECASE)
    raw_key = request.headers.get("x-api-key") or (bearer_match.group(1) if bearer_match else "")
    if not raw_key:
        raise HTTPException(status_code=401, detail="API key required")
    with connect_db() as connection:
        record = connection.execute("SELECT * FROM api_keys WHERE key_hash = ?", (hash_api_key(raw_key),)).fetchone()
    if record is None:
        raise HTTPException(status_code=401, detail="Invalid API key")
    if not record["is_active"]:
        raise HTTPException(status_code=403, detail="API key has been revoked")
    if record["expires_at"] and as_utc_datetime(record["expires_at"]) <= datetime.now(timezone.utc):
        raise HTTPException(status_code=403, detail="API key has expired")
    return dict(record)


def admin_configured() -> bool:
    return bool(os.getenv("ADMIN_USER") and os.getenv("ADMIN_PASSWORD")
                and os.getenv("ADMIN_PASSWORD") != "replace-with-a-long-random-password")


def signing_key() -> bytes:
    return f"url-shortener-admin:{os.getenv('ADMIN_USER', '')}:{os.getenv('ADMIN_PASSWORD', '')}".encode()


def admin_signature(payload: str) -> str:
    return hmac.new(signing_key(), payload.encode(), hashlib.sha256).hexdigest()


def has_admin_session(request: Request) -> bool:
    token = request.cookies.get("admin_session", "")
    try:
        payload, supplied = token.rsplit(".", 1)
        expires_at = int(payload)
    except (ValueError, TypeError):
        return False
    return expires_at > int(time.time() * 1000) and hmac.compare_digest(supplied, admin_signature(payload))


def require_admin(request: Request) -> None:
    if not admin_configured():
        raise HTTPException(status_code=503, detail="Admin access is disabled. Set ADMIN_USER and a non-example ADMIN_PASSWORD.")
    if not has_admin_session(request):
        raise HTTPException(status_code=401, detail="Admin login required")


def require_same_origin(request: Request) -> None:
    origin = request.headers.get("origin")
    if not origin:
        raise HTTPException(status_code=403, detail="Origin header required")
    try:
        if urlsplit(origin).netloc.lower() != request.headers.get("host", "").lower():
            raise HTTPException(status_code=403, detail="Cross-origin request rejected")
    except ValueError as exc:
        raise HTTPException(status_code=403, detail="Invalid Origin header") from exc


def parse_expiration(value: str | None) -> str | None:
    if not value:
        return None
    try:
        parsed = date.fromisoformat(value)
    except ValueError:
        raise HTTPException(status_code=400, detail="Choose a valid expiration date that is today or later.")
    if parsed.isoformat() != value or parsed < datetime.now(timezone.utc).date():
        raise HTTPException(status_code=400, detail="Choose a valid expiration date that is today or later.")
    return datetime.combine(parsed, datetime_time.max, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def new_api_key() -> tuple[str, str, str]:
    secret = f"sk_live_{secrets.token_urlsafe(32)}"
    return secret, hash_api_key(secret), secret[:15]


def json_row(row: sqlite3.Row | None) -> dict | None:
    return dict(row) if row is not None else None


def admin_dashboard_data() -> dict:
    with connect_db() as connection:
        keys = connection.execute("""SELECT k.id, k.owner, k.email, k.key_prefix, k.is_active, k.expires_at, k.created_at,
            COUNT(s.id) AS link_count FROM api_keys k LEFT JOIN short_urls s ON s.api_key_id = k.id
            GROUP BY k.id ORDER BY k.created_at DESC""").fetchall()
        total_links = connection.execute("SELECT COUNT(*) AS count FROM short_urls").fetchone()["count"]
        total_clicks = connection.execute("SELECT COUNT(*) AS count FROM clicks").fetchone()["count"]
        requests = connection.execute("""SELECT r.id, r.requester_name, r.email, r.reason, r.requested_expires_at,
            r.status, r.created_at, r.reviewed_at, k.key_prefix FROM api_key_requests r
            LEFT JOIN api_keys k ON k.id = r.api_key_id
            ORDER BY CASE r.status WHEN 'pending' THEN 0 ELSE 1 END, r.created_at DESC LIMIT 200""").fetchall()
    return {"keys": [json_row(row) for row in keys], "requests": [json_row(row) for row in requests],
            "totalLinks": total_links, "totalClicks": total_clicks}


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/admin", include_in_schema=False)
def admin_page() -> FileResponse:
    return FileResponse(FRONTEND / "admin.html")


@app.get("/admin/login", include_in_schema=False)
def admin_login_page() -> FileResponse:
    return FileResponse(FRONTEND / "admin-login.html")


@app.get("/api-key/request", include_in_schema=False)
def request_key_page() -> FileResponse:
    return FileResponse(FRONTEND / "request-key.html")


@app.post("/api/key-requests", status_code=202, dependencies=[Depends(require_same_origin)])
def create_key_request(body: KeyRequestBody, request: Request) -> dict:
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    attempts = [stamp for stamp in request_attempts.get(client_ip, []) if stamp > now - 3600]
    if len(attempts) >= 5:
        raise HTTPException(status_code=429, detail="Too many requests. Please try again in an hour.")
    attempts.append(now)
    request_attempts[client_ip] = attempts
    name = body.name.strip()
    email = body.email.strip().lower()
    reason = body.reason.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Enter your name (up to 120 characters).")
    if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email):
        raise HTTPException(status_code=400, detail="Enter a valid email address.")
    expiration = parse_expiration(body.expiresAt)
    if expiration is None:
        raise HTTPException(status_code=400, detail="Choose a valid expiration date that is today or later.")
    with connect_db() as connection:
        pending = connection.execute("SELECT id FROM api_key_requests WHERE lower(email) = lower(?) AND status = 'pending'", (email,)).fetchone()
        if not pending:
            connection.execute("INSERT INTO api_key_requests (requester_name, email, reason, requested_expires_at) VALUES (?, ?, ?, ?)",
                               (name, email, reason or None, expiration))
    return {"message": "Request received"}


@app.post("/api/admin/login", dependencies=[Depends(require_same_origin)])
def admin_login(body: LoginBody, response: Response) -> dict:
    if not admin_configured():
        raise HTTPException(status_code=503, detail="Admin access is disabled. Set ADMIN_USER and a non-example ADMIN_PASSWORD.")
    user_ok = hmac.compare_digest(body.username.encode(), os.getenv("ADMIN_USER", "").encode())
    pass_ok = hmac.compare_digest(body.password.encode(), os.getenv("ADMIN_PASSWORD", "").encode())
    if not (user_ok and pass_ok):
        raise HTTPException(status_code=401, detail="Incorrect username or password. Please try again.")
    expiry_ms = int((time.time() + 8 * 60 * 60) * 1000)
    payload = str(expiry_ms)
    secure = (os.getenv("BASE_URL") or os.getenv("RENDER_EXTERNAL_URL") or "").startswith("https://")
    response.set_cookie("admin_session", f"{payload}.{admin_signature(payload)}", max_age=8 * 60 * 60,
                        httponly=True, secure=secure, samesite="strict", path="/")
    response.headers["Cache-Control"] = "no-store"
    return {"ok": True}


@app.get("/api/admin/dashboard", dependencies=[Depends(require_admin)])
def get_admin_dashboard() -> dict:
    return admin_dashboard_data()


@app.post("/api/admin/keys", status_code=201, dependencies=[Depends(require_admin), Depends(require_same_origin)])
def create_admin_key(body: AdminKeyBody, response: Response) -> dict:
    owner = body.owner.strip()
    email = body.email.strip()
    if not owner:
        raise HTTPException(status_code=400, detail="Enter an owner name (up to 120 characters).")
    if email and not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email):
        raise HTTPException(status_code=400, detail="Enter a valid email address or leave it blank.")
    expiration = parse_expiration(body.expiresAt)
    secret, digest, prefix = new_api_key()
    with connect_db() as connection:
        connection.execute("INSERT INTO api_keys (owner, email, key_hash, key_prefix, expires_at) VALUES (?, ?, ?, ?, ?)",
                           (owner, email or None, digest, prefix, expiration))
    response.headers["Cache-Control"] = "no-store"
    return {"apiKey": secret}


@app.post("/api/admin/keys/{key_id}/expiration", dependencies=[Depends(require_admin), Depends(require_same_origin)])
def update_expiration(key_id: int, body: ExpirationBody) -> dict:
    expiration = parse_expiration(body.expiresAt)
    with connect_db() as connection:
        result = connection.execute("UPDATE api_keys SET expires_at = ? WHERE id = ?", (expiration, key_id))
        if not result.rowcount:
            raise HTTPException(status_code=404, detail="API key not found")
    return {"ok": True}


@app.post("/api/admin/requests/{request_id}/approve", status_code=201,
          dependencies=[Depends(require_admin), Depends(require_same_origin)])
def approve_key_request(request_id: int, response: Response) -> dict:
    secret, digest, prefix = new_api_key()
    try:
        with connect_db() as connection:
            connection.execute("BEGIN IMMEDIATE" if not USE_POSTGRES else "BEGIN")
            key_request = connection.execute("SELECT * FROM api_key_requests WHERE id = ? AND status = 'pending'", (request_id,)).fetchone()
            if not key_request:
                raise HTTPException(status_code=404, detail="That request was already reviewed or does not exist.")
            expiry = key_request["requested_expires_at"]
            if expiry and as_utc_datetime(expiry) <= datetime.now(timezone.utc):
                raise HTTPException(status_code=409, detail="The requested expiration date has passed. Ask the user to submit a new request.")
            inserted = connection.execute("INSERT INTO api_keys (owner, email, key_hash, key_prefix, expires_at) VALUES (?, ?, ?, ?, ?) RETURNING id",
                                          (key_request["requester_name"], key_request["email"], digest, prefix, expiry))
            inserted_id = inserted.fetchone()["id"]
            connection.execute("UPDATE api_key_requests SET status = 'approved', api_key_id = ?, reviewed_at = CURRENT_TIMESTAMP WHERE id = ?",
                               (inserted_id, request_id))
    except (sqlite3.Error, psycopg.Error) as exc:
        raise HTTPException(status_code=409, detail="That request was already reviewed.") from exc
    response.headers["Cache-Control"] = "no-store"
    return {"apiKey": secret}


@app.post("/api/admin/requests/{request_id}/reject", dependencies=[Depends(require_admin), Depends(require_same_origin)])
def reject_key_request(request_id: int) -> dict:
    with connect_db() as connection:
        result = connection.execute("UPDATE api_key_requests SET status = 'rejected', reviewed_at = CURRENT_TIMESTAMP WHERE id = ? AND status = 'pending'", (request_id,))
        if not result.rowcount:
            raise HTTPException(status_code=404, detail="That request was already reviewed or does not exist.")
    return {"ok": True}


@app.post("/api/admin/keys/{key_id}/toggle", dependencies=[Depends(require_admin), Depends(require_same_origin)])
def toggle_key(key_id: int) -> dict:
    with connect_db() as connection:
        result = connection.execute("UPDATE api_keys SET is_active = NOT is_active WHERE id = ?", (key_id,))
        if not result.rowcount:
            raise HTTPException(status_code=404, detail="API key not found")
    return {"ok": True}


@app.post("/api/admin/logout", dependencies=[Depends(require_admin), Depends(require_same_origin)])
def admin_logout(response: Response) -> dict:
    secure = (os.getenv("BASE_URL") or os.getenv("RENDER_EXTERNAL_URL") or "").startswith("https://")
    response.delete_cookie("admin_session", path="/", httponly=True, secure=secure, samesite="strict")
    return {"ok": True}


@app.post("/api/v1/shorten", status_code=201)
def shorten_url(body: ShortenBody, request: Request, response: Response, api_key: dict = Depends(api_key_auth)) -> dict:
    try:
        parsed = urlsplit(body.url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError
        parsed.port  # Accessing this validates the port syntax/range.
    except ValueError:
        raise HTTPException(status_code=400, detail="url must be a valid http or https URL")
    with connect_db() as connection:
        for _attempt in range(5):
            short_code = secrets.token_hex(4)
            inserted = connection.execute("INSERT INTO short_urls (api_key_id, original_url, short_code) VALUES (?, ?, ?) ON CONFLICT(short_code) DO NOTHING",
                                           (api_key["id"], body.url, short_code))
            if inserted.rowcount:
                break
        else:
            raise HTTPException(status_code=503, detail="Could not allocate a short code. Please retry.")
    base_url = (os.getenv("BASE_URL") or os.getenv("RENDER_EXTERNAL_URL") or f"http://localhost:{os.getenv('PORT', '3000')}").rstrip("/")
    return {"shortCode": short_code, "shortUrl": f"{base_url}/s/{short_code}", "originalUrl": body.url}


@app.get("/api/v1/analytics/{short_code}")
def get_analytics(short_code: str, api_key: dict = Depends(api_key_auth)) -> dict:
    with connect_db() as connection:
        link = connection.execute("SELECT * FROM short_urls WHERE short_code = ? AND api_key_id = ?", (short_code, api_key["id"])).fetchone()
        if not link:
            raise HTTPException(status_code=404, detail="Short URL not found")
        stats = connection.execute('SELECT COUNT(*) AS "totalClicks", MAX(clicked_at) AS "lastClickedAt" FROM clicks WHERE short_url_id = ?', (link["id"],)).fetchone()
        recent = connection.execute('SELECT clicked_at AS "clickedAt", user_agent AS "userAgent" FROM clicks WHERE short_url_id = ? ORDER BY clicked_at DESC LIMIT 100', (link["id"],)).fetchall()
    return {"shortCode": link["short_code"], "originalUrl": link["original_url"], "createdAt": link["created_at"],
            **dict(stats), "recentClicks": [dict(row) for row in recent]}


@app.get("/s/{short_code}")
def redirect_short_url(short_code: str, request: Request) -> RedirectResponse:
    with connect_db() as connection:
        link = connection.execute("SELECT * FROM short_urls WHERE short_code = ?", (short_code,)).fetchone()
        if not link:
            raise HTTPException(status_code=404, detail="Short URL not found")
        raw_ip = request.client.host if request.client else ""
        try:
            parsed_ip = ipaddress.ip_address(raw_ip)
            anonymized_ip = str(ipaddress.ip_network(f"{parsed_ip}/{24 if parsed_ip.version == 4 else 48}", strict=False).network_address)
        except ValueError:
            anonymized_ip = None
        connection.execute("INSERT INTO clicks (short_url_id, user_agent, ip_address) VALUES (?, ?, ?)",
                           (link["id"], request.headers.get("user-agent"), anonymized_ip))
    return RedirectResponse(link["original_url"], status_code=302)


app.mount("/", StaticFiles(directory=FRONTEND, html=True), name="frontend")
