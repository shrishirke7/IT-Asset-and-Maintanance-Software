import json
import os
import re
import secrets
import hashlib
import hmac
import subprocess
import uuid
import ipaddress
import threading
import unicodedata
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import quote

import psycopg
from flask import Flask, abort, jsonify, redirect, request, send_from_directory, session
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash

ROOT = Path(__file__).resolve().parent
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", ROOT / "uploads"))
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
LOGIN_MEDIA_DIR = UPLOAD_DIR / "login-branding"
LOGIN_MEDIA_DIR.mkdir(parents=True, exist_ok=True)
PROFILE_MEDIA_DIR = UPLOAD_DIR / 'profiles'
PROFILE_MEDIA_DIR.mkdir(parents=True, exist_ok=True)
APP_SECRET = os.getenv("APP_SECRET", "")
if len(APP_SECRET) < 40:
    raise RuntimeError("APP_SECRET must be a randomly generated secret of at least 40 characters")

app = Flask(__name__, static_folder=None)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.secret_key = APP_SECRET
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "true").lower() == "true",
    SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=12 * 1024 * 1024,
    PERMANENT_SESSION_LIFETIME=60 * 60 * 8,
)
DATABASE_URL = os.environ["DATABASE_URL"]
RECOVERY_QUESTIONS = ("Favourite animal", "Favourite colour", "Favourite food")
RECOVERY_GENERIC_MESSAGE = "If the account and answers match, the password was reset. Try signing in."
RECOVERY_DUMMY_HASH = generate_password_hash("not-a-real-recovery-answer")
LOGIN_DUMMY_HASH = generate_password_hash("not-a-real-login-password")


def db():
    return psycopg.connect(DATABASE_URL, connect_timeout=8)


def normalize_recovery_answer(value):
    return " ".join(unicodedata.normalize("NFKC", str(value or "")).casefold().split())


def recovery_answer_hashes(values):
    if not isinstance(values, list) or len(values) != len(RECOVERY_QUESTIONS):
        return None
    answers = [normalize_recovery_answer(value) for value in values]
    if any(len(answer) < 3 or len(answer) > 200 for answer in answers):
        return None
    return [generate_password_hash(answer) for answer in answers]


def matches_recovery_answer(stored_hash, answer):
    try:
        return check_password_hash(stored_hash, answer)
    except (ValueError, TypeError, AttributeError):
        return False


def init_db():
    with db() as conn:
        schema = (ROOT / "schema.sql").read_text(encoding="utf-8")
        for statement in schema.split(";"):
            if statement.strip():
                conn.execute(statement)
        conn.execute("INSERT INTO app_state(key,value) VALUES('assets','[]'),('software','[]'),('departments','[]'),('maintenance','[]'),('manual_users','[]'),('network_ranges','[]'),('network_scan','{}'),('scanner_heartbeat','{}'),('scanner_ip_status','{}'),('settings','{}') ON CONFLICT(key) DO NOTHING")


def signed_in(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        profile = session.get("profile")
        if not profile:
            return jsonify(error="sign_in_required"), 401
        username = str(profile.get("username", "")).casefold()
        with db() as conn:
            row = conn.execute("SELECT value FROM app_state WHERE key='manual_users'").fetchone()
        users = row[0] if row else []
        account = next((u for u in users if str(u.get("username", "")).casefold() == username), None)
        try:
            current_version = int(account.get("auth_version", 0)) if account else -1
            session_version = int(session.get("auth_version", 0))
        except (TypeError, ValueError):
            current_version, session_version = -1, 0
        if not account or not account.get("enabled", True) or current_version != session_version:
            session.clear()
            return jsonify(error="session_expired_sign_in_again"), 401
        return fn(*args, **kwargs)
    return wrapper


def administrator(fn):
    @wraps(fn)
    @signed_in
    def wrapper(*args, **kwargs):
        if not session.get("is_admin"):
            abort(403)
        return fn(*args, **kwargs)
    return wrapper


def ticket_manager(fn):
    @wraps(fn)
    @signed_in
    def wrapper(*args, **kwargs):
        if not session.get("is_admin") and session.get("profile", {}).get("role") != "IT Ticketing":
            abort(403)
        return fn(*args, **kwargs)
    return wrapper


@app.before_request
def check_api_origin():
    if request.path.startswith("/api/") and request.method in ("POST", "PUT", "PATCH", "DELETE"):
        origin = request.headers.get("Origin")
        if origin and origin.rstrip("/") != request.host_url.rstrip("/"):
            abort(403)
        if request.headers.get("X-Requested-With") != "NorthstarIT":
            abort(403)


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("X-Frame-Options", "DENY")
    if request.path in ("/", "/setup", "/api/login", "/api/recovery/reset", "/api/account/recovery-answers"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/")
def index():
    if not setup_complete():
        return redirect("/setup")
    return send_from_directory(ROOT, "index.html")


def setup_complete():
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='manual_users'").fetchone()
    users = row[0] if row else []
    return any(u.get("enabled", True) and u.get("password_hash") and u.get("role") == "Administrator" for u in users)


@app.get("/setup")
def setup_page():
    if setup_complete():
        return redirect("/")
    return send_from_directory(ROOT, "setup.html")


@app.get("/api/setup/status")
def setup_status():
    return jsonify(configured=setup_complete())


@app.post("/api/setup")
def initial_setup():
    body = request.get_json(silent=True) or {}
    company = str(body.get("company", "")).strip()[:120]
    full_name = str(body.get("full_name", "")).strip()[:120]
    username = str(body.get("username", "")).strip()[:80]
    password = str(body.get("password", ""))
    answer_hashes = recovery_answer_hashes(body.get("recovery_answers"))
    if not full_name or not re.fullmatch(r"[A-Za-z0-9._@-]{3,80}", username):
        return jsonify(error="Enter the administrator name and a valid username (3–80 letters, numbers, dots, underscores, @, or hyphens)."), 400
    if len(password) < 10 or len(password) > 1024:
        return jsonify(error="Choose a password with at least 10 characters."), 400
    if not answer_hashes:
        return jsonify(error="Answer all three recovery questions (3–200 characters each)."), 400
    with db() as conn:
        conn.execute("SELECT pg_advisory_xact_lock(hashtext('northstar-first-setup'))")
        row = conn.execute("SELECT value FROM app_state WHERE key='manual_users' FOR UPDATE").fetchone()
        users = row[0] if row else []
        if any(u.get("enabled", True) and u.get("password_hash") and u.get("role") == "Administrator" for u in users):
            return jsonify(error="Setup is already complete. Sign in instead."), 409
        if any(str(u.get("username", "")).casefold() == username.casefold() for u in users):
            return jsonify(error="That username already exists."), 409
        users.append({"id":username,"username":username,"name":full_name,"email":"","site":"","dept":"","role":"Administrator","enabled":True,"source":"manual","password_hash":generate_password_hash(password),"auth_version":0,"recovery_answer_hashes":answer_hashes})
        conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='manual_users'", (json.dumps(users),))
        settings_row=conn.execute("SELECT value FROM app_state WHERE key='settings' FOR UPDATE").fetchone()
        settings=settings_row[0] if settings_row else {}
        branding=dict(settings.get("loginBranding", {}))
        if company:
            branding['companyName'] = company
            settings.update(companyName=company, loginBranding=branding)
        conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='settings'",(json.dumps(settings),))
    return jsonify(ok=True, redirect="/"), 201


@app.get("/api/login-branding")
def get_login_branding():
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='settings'").fetchone()
    settings = row[0] if row else {}
    branding = settings.get("loginBranding", {})
    return jsonify({
        "companyName": str(branding.get("companyName") or settings.get("companyName") or "")[:120],
        "tagline": str(branding.get("tagline") or "")[:180],
        "showTagline": branding.get("showTagline", True) is not False,
        "logoUrl": str(branding.get("logoUrl") or "")[:300],
        "slides": branding.get("slides", [])[:5] if isinstance(branding.get("slides", []), list) else [],
        "slideInterval": max(3, min(30, int(branding.get("slideInterval", 6) or 6))),
    })


@app.get("/profile-media/<path:filename>")
def profile_media(filename):
    if Path(filename).name != filename or Path(filename).suffix.lower() not in (".png", ".jpg", ".jpeg", ".webp"):
        abort(404)
    return send_from_directory(PROFILE_MEDIA_DIR, filename, max_age=3600)

@app.get("/login-media/<path:filename>")
def login_media(filename):
    if Path(filename).name != filename or Path(filename).suffix.lower() not in (".png", ".jpg", ".jpeg", ".webp"):
        abort(404)
    return send_from_directory(LOGIN_MEDIA_DIR, filename, max_age=3600)


def save_login_image(upload):
    if not upload or not upload.filename:
        return ""
    ext = Path(upload.filename).suffix.lower()
    if ext not in (".png", ".jpg", ".jpeg", ".webp"):
        raise ValueError("Use PNG, JPG, or WebP images only")
    data = upload.stream.read(1536 * 1024 + 1)
    if not data or len(data) > 1536 * 1024:
        raise ValueError("Each sign-in image must be between 1 byte and 1.5 MB")
    valid = (ext == ".png" and data.startswith(b"\x89PNG\r\n\x1a\n")) or (ext in (".jpg", ".jpeg") and data.startswith(b"\xff\xd8\xff")) or (ext == ".webp" and data.startswith(b"RIFF") and data[8:12] == b"WEBP")
    if not valid:
        raise ValueError("The uploaded file does not match its image type")
    filename = f"{uuid.uuid4().hex}{ext}"
    (LOGIN_MEDIA_DIR / filename).write_bytes(data)
    return "/login-media/" + filename


@app.post("/api/admin/login-branding")
@administrator
def save_login_branding():
    try:
        company = str(request.form.get("companyName", "")).strip()[:120]
        tagline = str(request.form.get("tagline", "")).strip()[:180]
        show_tagline = str(request.form.get("showTagline", "true")).strip().lower() in ("true", "yes", "1")
        try:
            interval = max(3, min(30, int(request.form.get("slideInterval", "6"))))
            slides = json.loads(request.form.get("slides", "[]"))
        except (ValueError, TypeError, json.JSONDecodeError):
            return jsonify(error="Invalid slideshow settings"), 400
        if not isinstance(slides, list) or len(slides) > 5 or any(not isinstance(s, dict) or not re.fullmatch(r"/login-media/[a-f0-9]{32}\.(?:png|jpe?g|webp)", str(s.get("imageUrl", ""))) for s in slides):
            return jsonify(error="Add up to 5 valid slideshow images"), 400
        uploads = [image for image in request.files.getlist("slidesUpload") if image and image.filename]
        if len(slides) + len(uploads) > 5:
            return jsonify(error="The sign-in slideshow supports up to 5 images"), 400
        with db() as conn:
            current = (conn.execute("SELECT value FROM app_state WHERE key='settings' FOR UPDATE").fetchone() or ({},))[0]
            branding = dict(current.get("loginBranding", {}))
        new_logo = save_login_image(request.files.get("logo"))
        if new_logo:
            branding["logoUrl"] = new_logo
        for image in uploads:
            image_url = save_login_image(image)
            if image_url:
                slides.append({"imageUrl": image_url, "caption": tagline if show_tagline else ""})
        branding.update(companyName=company, tagline=tagline, showTagline=show_tagline, slides=slides, slideInterval=interval)
        current["companyName"] = company
        current["loginBranding"] = branding
        with db() as conn:
            conn.execute("INSERT INTO app_state(key,value) VALUES('settings',%s::jsonb) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()", (json.dumps(current),))
        return jsonify(ok=True, branding=branding)
    except (ValueError, OSError) as exc:
        return jsonify(error=str(exc)), 400


@app.get("/healthz")
def health():
    try:
        with db() as conn:
            conn.execute("SELECT 1")
        return jsonify(ok=True)
    except Exception:
        return jsonify(ok=False), 503


NETWORK_SCAN_LOCK = threading.Lock()
NETWORK_SCAN_STATE = {"status":"idle", "progress":0, "total":0, "results":[], "error":"", "started_at":"", "finished_at":""}


def _persist_network_scan(state, scan_id):
    with db() as conn:
        conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='network_scan' AND value->>'id'=%s", (json.dumps(state), scan_id))


@app.get("/api/network-scans")
@signed_in
def network_scans():
    with db() as conn:
        ranges = (conn.execute("SELECT value FROM app_state WHERE key='network_ranges'").fetchone() or ([],))[0]
        saved = (conn.execute("SELECT value FROM app_state WHERE key='network_scan'").fetchone() or ({},))[0]
        heartbeat = (conn.execute("SELECT value FROM app_state WHERE key='scanner_heartbeat'").fetchone() or ({},))[0]
    with NETWORK_SCAN_LOCK:
        state = dict(NETWORK_SCAN_STATE)
    if saved:
        state = saved
    if state.get("status") == "running" and state.get("started_at"):
        try:
            started = datetime.fromisoformat(state["started_at"])
            if (datetime.now(timezone.utc) - started).total_seconds() > 1800:
                state.update(status="failed", error="Scan stopped unexpectedly; start a new scan.", finished_at=datetime.now(timezone.utc).isoformat())
                _persist_network_scan(state, state.get("id", ""))
        except (ValueError, TypeError):
            pass
    last_seen = heartbeat.get('last_seen', '')
    try:
        scanner_connected = bool(last_seen) and (datetime.now(timezone.utc) - datetime.fromisoformat(last_seen)).total_seconds() <= 20
    except (ValueError, TypeError):
        scanner_connected = False
    return jsonify(ranges=ranges, scan=state, scannerConnected=scanner_connected)


@app.put("/api/admin/network-scan/ranges")
@administrator
def save_network_scan_ranges():
    body = request.get_json(force=True)
    raw = body.get("ranges", [])
    if not isinstance(raw, list) or len(raw) > 16:
        return jsonify(error="Enter up to 16 private IPv4 network ranges"), 400
    networks = []
    for value in raw:
        try:
            network = ipaddress.ip_network(str(value).strip(), strict=False)
        except ValueError:
            return jsonify(error=f"Invalid network range: {value}"), 400
        if network.version != 4 or not network.is_private or network.is_loopback or network.is_link_local or network.num_addresses > 256:
            return jsonify(error="Only private IPv4 ranges up to /24 can be scanned"), 400
        if network not in networks:
            networks.append(network)
    if sum(len(list(n.hosts())) for n in networks) > 1024:
        return jsonify(error="Combined scan limit is 1,024 addresses"), 400
    values = [str(n) for n in networks]
    with db() as conn:
        conn.execute("INSERT INTO app_state(key,value) VALUES('network_ranges',%s::jsonb) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()", (json.dumps(values),))
    return jsonify(ok=True, ranges=values)


@app.post("/api/admin/network-scan")
@administrator
def start_network_scan():
    global NETWORK_SCAN_STATE
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='network_ranges'").fetchone()
        raw = row[0] if row else []
    if not raw:
        return jsonify(error="Add the authorized private network ranges to scan first"), 400
    networks = [ipaddress.ip_network(value, strict=True) for value in raw]
    hosts_count = sum(len(list(n.hosts())) for n in networks)
    if hosts_count > 1024:
        return jsonify(error="Combined scan limit is 1,024 addresses"), 400
    with db() as conn:
        current = conn.execute("SELECT value FROM app_state WHERE key='network_scan' FOR UPDATE").fetchone()
        prior = current[0] if current else {}
        if prior.get("status") == "running" and prior.get("started_at"):
            try:
                recent = (datetime.now(timezone.utc) - datetime.fromisoformat(prior["started_at"])).total_seconds() < 1800
            except (ValueError, TypeError):
                recent = False
            if recent:
                return jsonify(error="A network scan is already running"), 409
        scan_id = str(uuid.uuid4())
        NETWORK_SCAN_STATE = {"id":scan_id,"status":"queued","progress":0,"total":hosts_count,"results":[],"error":"","started_at":datetime.now(timezone.utc).isoformat(),"finished_at":""}
        conn.execute("INSERT INTO app_state(key,value) VALUES('network_scan',%s::jsonb) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()", (json.dumps(NETWORK_SCAN_STATE),))
    return jsonify(ok=True, scan_id=scan_id, total=hosts_count), 202


def _scanner_authorized():
    supplied = request.headers.get("X-Northstar-Scanner", "")
    return bool(supplied) and secrets.compare_digest(supplied, APP_SECRET)


@app.get("/api/internal/ip-status-task")
def scanner_ip_status_task():
    if not _scanner_authorized():
        abort(403)
    now = datetime.now(timezone.utc)
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='scanner_ip_status' FOR UPDATE").fetchone()
        state = row[0] if row else {}
        prior_time = state.get("finished_at") or state.get("started_at") or ""
        if prior_time:
            try:
                elapsed = (now - datetime.fromisoformat(prior_time)).total_seconds()
                if (not state.get("finished_at") and elapsed < 120) or (state.get("finished_at") and elapsed < 30):
                    return ("", 204)
            except (ValueError, TypeError):
                pass
        ranges = (conn.execute("SELECT value FROM app_state WHERE key='network_ranges'").fetchone() or ([],))[0]
        if not ranges:
            return ("", 204)
        networks = [ipaddress.ip_network(value, strict=True) for value in ranges]
        inventory = (conn.execute("SELECT value FROM app_state WHERE key='assets'").fetchone() or ([],))[0]
        users = (conn.execute("SELECT value FROM app_state WHERE key='manual_users'").fetchone() or ([],))[0]
        targets = set()
        for item, fields in [(a, ("ipAddress", "ip_address")) for a in inventory] + [(u, ("ip_address", "ipAddress")) for u in users]:
            raw_ip = next((item.get(key) for key in fields if item.get(key)), "")
            try:
                ip = ipaddress.ip_address(str(raw_ip).strip())
            except ValueError:
                continue
            if ip.version == 4 and ip.is_private and any(ip in network for network in networks):
                targets.add(str(ip))
        if not targets:
            return ("", 204)
        task_id = str(uuid.uuid4())
        state = {"id":task_id,"targets":sorted(targets, key=lambda value:tuple(int(part) for part in value.split("."))),"started_at":now.isoformat(),"finished_at":""}
        conn.execute("INSERT INTO app_state(key,value) VALUES('scanner_ip_status',%s::jsonb) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()", (json.dumps(state),))
    return jsonify(id=task_id, ips=state["targets"])


@app.post("/api/internal/ip-status-results")
def scanner_ip_status_results():
    if not _scanner_authorized():
        abort(403)
    body = request.get_json(force=True)
    task_id = str(body.get("id", ""))
    responsive = set()
    rows = body.get("online", [])
    if not task_id or not isinstance(rows, list) or len(rows) > 1024:
        return jsonify(error="Invalid IP status result"), 400
    for value in rows:
        try:
            ip = ipaddress.ip_address(str(value))
            if ip.version == 4 and ip.is_private:
                responsive.add(str(ip))
        except ValueError:
            continue
    checked_at = datetime.now(timezone.utc).isoformat()
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='scanner_ip_status' FOR UPDATE").fetchone()
        state = row[0] if row else {}
        if state.get("id") != task_id or state.get("finished_at"):
            return jsonify(error="IP status task is no longer active"), 409
        ranges = (conn.execute("SELECT value FROM app_state WHERE key='network_ranges'").fetchone() or ([],))[0]
        networks = [ipaddress.ip_network(value, strict=True) for value in ranges]
        target_set = set()
        for value in state.get("targets", []):
            try:
                ip = ipaddress.ip_address(value)
                if ip.version == 4 and ip.is_private and any(ip in network for network in networks):
                    target_set.add(str(ip))
            except ValueError:
                continue
        responsive.intersection_update(target_set)
        inventory_row = conn.execute("SELECT value FROM app_state WHERE key='assets' FOR UPDATE").fetchone()
        inventory = inventory_row[0] if inventory_row else []
        users_row = conn.execute("SELECT value FROM app_state WHERE key='manual_users' FOR UPDATE").fetchone()
        users = users_row[0] if users_row else []
        assets_changed = users_changed = False
        for asset in inventory:
            raw_ip = str(asset.get("ipAddress", asset.get("ip_address", ""))).strip()
            if raw_ip not in target_set:
                continue
            asset["status"] = asset["ipStatus"] = "Online" if raw_ip in responsive else "Offline"
            asset["ipCheckedAt"] = checked_at
            if raw_ip in responsive:
                asset["lastSeen"] = checked_at
            assets_changed = True
        for user in users:
            raw_ip = str(user.get("ip_address", user.get("ipAddress", ""))).strip()
            if raw_ip not in target_set:
                continue
            user["ipStatus"] = "Online" if raw_ip in responsive else "Offline"
            user["ipCheckedAt"] = checked_at
            if raw_ip in responsive:
                user["lastSeen"] = checked_at
            users_changed = True
        if assets_changed:
            conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='assets'", (json.dumps(inventory),))
        if users_changed:
            conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='manual_users'", (json.dumps(users),))
        state["finished_at"] = checked_at
        state["online_count"] = len(responsive)
        conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='scanner_ip_status'", (json.dumps(state),))
    return jsonify(ok=True, online=len(responsive), checked=len(target_set))


@app.post("/api/internal/scanner-heartbeat")
def scanner_heartbeat():
    if not _scanner_authorized():
        abort(403)
    state = {"last_seen": datetime.now(timezone.utc).isoformat()}
    with db() as conn:
        conn.execute("INSERT INTO app_state(key,value) VALUES('scanner_heartbeat',%s::jsonb) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()", (json.dumps(state),))
    return jsonify(ok=True)


@app.get("/api/internal/scanner-task")
def scanner_task():
    if not _scanner_authorized():
        abort(403)
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='network_scan' FOR UPDATE").fetchone()
        state = row[0] if row else {}
        ranges = (conn.execute("SELECT value FROM app_state WHERE key='network_ranges'").fetchone() or ([],))[0]
        if ranges and state.get("status") in (None, "", "idle", "completed", "failed"):
            last_run = state.get("finished_at") or state.get("started_at") or ""
            try:
                due = not last_run or (datetime.now(timezone.utc) - datetime.fromisoformat(last_run)).total_seconds() >= 900
            except (ValueError, TypeError):
                due = True
            if due:
                hosts_count = sum(len(list(ipaddress.ip_network(value, strict=True).hosts())) for value in ranges)
                state = {"id":str(uuid.uuid4()),"status":"queued","progress":0,"total":hosts_count,"results":[],"error":"","started_at":datetime.now(timezone.utc).isoformat(),"finished_at":""}
                conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='network_scan'", (json.dumps(state),))
        if state.get("status") != "queued":
            return ("", 204)
        state["status"] = "running"
        conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='network_scan'", (json.dumps(state),))
    return jsonify(id=state.get("id"), ranges=ranges, total=state.get("total", 0))


@app.post("/api/internal/scanner-progress")
def scanner_progress():
    if not _scanner_authorized():
        abort(403)
    body = request.get_json(force=True)
    scan_id = str(body.get("id", ""))
    status = body.get("status")
    if not scan_id or status not in ("running", "completed", "failed"):
        return jsonify(error="Invalid scanner progress update"), 400
    try:
        progress = max(0, min(1024, int(body.get("progress", 0))))
    except (ValueError, TypeError):
        return jsonify(error="Invalid scan progress"), 400
    results = body.get("results", [])
    if not isinstance(results, list) or len(results) > 1024:
        return jsonify(error="Invalid scan results"), 400
    clean = []
    for item in results:
        try:
            ip = ipaddress.ip_address(item.get("ip", ""))
            mac = str(item.get("mac", ""))[:32]
            if ip.version != 4 or not ip.is_private:
                continue
            raw_latency = item.get("latency_ms")
            latency = None if raw_latency is None else max(0, min(60000, int(raw_latency)))
            clean.append({"ip":str(ip), "mac":mac, "hostname":str(item.get("hostname", ""))[:255], "status":"Online", "latency_ms":latency, "last_seen":str(item.get("last_seen", ""))[:64]})
        except (ValueError, TypeError, AttributeError):
            continue
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='network_scan' FOR UPDATE").fetchone()
        state = row[0] if row else {}
        if state.get("id") != scan_id or state.get("status") not in ("queued", "running"):
            return jsonify(error="Scan task is no longer active"), 409
        state.update(status=status, progress=progress, results=clean)
        if body.get("error"):
            state["error"] = "Scanner agent failed. Check Ubuntu network access and ping permissions."
        if status in ("completed", "failed"):
            state["finished_at"] = datetime.now(timezone.utc).isoformat()
        conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='network_scan'", (json.dumps(state),))
        if status == "completed":
            ranges = (conn.execute("SELECT value FROM app_state WHERE key='network_ranges'").fetchone() or ([],))[0]
            networks = [ipaddress.ip_network(value, strict=True) for value in ranges]
            inventory_row = conn.execute("SELECT value FROM app_state WHERE key='assets' FOR UPDATE").fetchone()
            inventory = inventory_row[0] if inventory_row else []
            users_row = conn.execute("SELECT value FROM app_state WHERE key='manual_users' FOR UPDATE").fetchone()
            users = users_row[0] if users_row else []
            online_ips = {item["ip"] for item in clean}
            checked_at = datetime.now(timezone.utc).isoformat()
            assets_changed = False
            users_changed = False
            for asset in inventory:
                try:
                    ip = ipaddress.ip_address(str(asset.get("ipAddress", asset.get("ip_address", ""))).strip())
                except ValueError:
                    continue
                if ip.version != 4 or not any(ip in network for network in networks):
                    continue
                asset["status"] = "Online" if str(ip) in online_ips else "Offline"
                asset["ipStatus"] = asset["status"]
                asset["ipCheckedAt"] = checked_at
                if str(ip) in online_ips:
                    asset["lastSeen"] = checked_at
                assets_changed = True
            for user in users:
                try:
                    ip = ipaddress.ip_address(str(user.get("ip_address", user.get("ipAddress", ""))).strip())
                except ValueError:
                    continue
                if ip.version != 4 or not any(ip in network for network in networks):
                    continue
                user["ipStatus"] = "Online" if str(ip) in online_ips else "Offline"
                user["ipCheckedAt"] = checked_at
                if str(ip) in online_ips:
                    user["lastSeen"] = checked_at
                users_changed = True
            if assets_changed:
                conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='assets'", (json.dumps(inventory),))
            if users_changed:
                conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='manual_users'", (json.dumps(users),))
    return jsonify(ok=True)


@app.post("/api/login")
def login():
    body = request.get_json(silent=True) or {}
    username = str(body.get("username", "")).strip()
    password = str(body.get("password", ""))
    if not username or not password or len(username) > 120 or len(password) > 1024:
        return jsonify(error="Enter your username and password"), 400
    remote_ip = request.remote_addr or "127.0.0.1"
    with db() as conn:
        row = conn.execute("SELECT failures, blocked_until FROM login_attempts WHERE client_ip=%s", (remote_ip,)).fetchone()
        if row and row[1] and row[1] > datetime.now(timezone.utc):
            return jsonify(error="Too many attempts. Wait 15 minutes and try again."), 429
        local_state = conn.execute("SELECT value FROM app_state WHERE key='manual_users'").fetchone()
    local_users = local_state[0] if local_state else []
    local_user = next((u for u in local_users if str(u.get("username", "")).casefold() == username.casefold()), None)
    password_hash = local_user.get("password_hash") if local_user and local_user.get("enabled", True) else LOGIN_DUMMY_HASH
    if local_user and local_user.get("enabled", True) and local_user.get("password_hash"):
        try:
            valid_local = check_password_hash(local_user["password_hash"], password)
        except (ValueError, TypeError):
            valid_local = False
        if valid_local:
            profile = {"username": str(local_user["username"]).lower(), "name": local_user.get("name") or local_user["username"], "email": local_user.get("email", ""), "dept": local_user.get("dept", ""), "site": local_user.get("site", ""), "role": local_user.get("role", "User"), "profile_picture": local_user.get("profile_picture", ""), "groups": []}
            with db() as conn:
                conn.execute("DELETE FROM login_attempts WHERE client_ip=%s", (remote_ip,))
            session.clear()
            session.permanent = True
            session["auth_version"] = int(local_user.get("auth_version", 0) or 0)
            session["is_admin"] = profile["role"] == "Administrator"
            session["profile"] = {key:value for key,value in profile.items() if key != "groups"}
            return jsonify(profile=session["profile"], isAdmin=session["is_admin"])
    else:
        try:
            check_password_hash(password_hash, password)
        except (ValueError, TypeError):
            pass
    with db() as conn:
        conn.execute("INSERT INTO login_attempts(client_ip,failures,blocked_until) VALUES(%s,1,NULL) ON CONFLICT(client_ip) DO UPDATE SET failures=login_attempts.failures+1, blocked_until=CASE WHEN login_attempts.failures+1>=5 THEN now()+interval '15 minutes' ELSE NULL END", (remote_ip,))
    return jsonify(error="Sign-in failed. Check your username and password."), 401


@app.post("/api/recovery/reset")
def recover_account_password():
    body = request.get_json(silent=True) or {}
    username = str(body.get("username", "")).strip()[:120]
    raw_answers = body.get("answers", [])
    new_password = str(body.get("new_password", ""))
    confirm_password = str(body.get("confirm_password", ""))
    if not username or len(new_password) < 10 or len(new_password) > 1024 or new_password != confirm_password:
        return jsonify(message=RECOVERY_GENERIC_MESSAGE), 200
    normalized = [normalize_recovery_answer(a) for a in raw_answers] if isinstance(raw_answers, list) else []
    if len(normalized) != len(RECOVERY_QUESTIONS) or any(len(a) < 3 or len(a) > 200 for a in normalized):
        normalized = ["invalid-answer"] * len(RECOVERY_QUESTIONS)
    remote_ip = request.remote_addr or "127.0.0.1"
    username_key = hmac.new(APP_SECRET.encode(), username.casefold().encode(), hashlib.sha256).hexdigest()
    with db() as conn:
        attempt = conn.execute(
            "SELECT failures,blocked_until FROM recovery_attempts WHERE client_ip=%s AND username_hash=%s",
            (remote_ip, username_key),
        ).fetchone()
        if attempt and attempt[1] and attempt[1] > datetime.now(timezone.utc):
            return jsonify(message="Too many recovery attempts. Wait 15 minutes and try again."), 429
        row = conn.execute("SELECT value FROM app_state WHERE key='manual_users' FOR UPDATE").fetchone()
        users = row[0] if row else []
        account = next((u for u in users if str(u.get("username", "")).casefold() == username.casefold()
                        and u.get("enabled", True) and u.get("password_hash")), None)
        hashes = account.get("recovery_answer_hashes", []) if account else []
        usable_hashes = hashes if isinstance(hashes, list) and len(hashes) == len(RECOVERY_QUESTIONS) else [RECOVERY_DUMMY_HASH] * len(RECOVERY_QUESTIONS)
        checks = [matches_recovery_answer(stored, answer) for stored, answer in zip(usable_hashes, normalized)]
        valid = bool(account and len(hashes) == len(RECOVERY_QUESTIONS) and all(checks))
        if valid:
            account["password_hash"] = generate_password_hash(new_password)
            account["auth_version"] = int(account.get("auth_version", 0) or 0) + 1
            conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='manual_users'", (json.dumps(users),))
            conn.execute("DELETE FROM recovery_attempts WHERE client_ip=%s AND username_hash=%s", (remote_ip, username_key))
            conn.execute("DELETE FROM login_attempts WHERE client_ip=%s", (remote_ip,))
        else:
            conn.execute(
                "INSERT INTO recovery_attempts(client_ip,username_hash,failures,blocked_until) VALUES(%s,%s,1,NULL) "
                "ON CONFLICT(client_ip,username_hash) DO UPDATE SET failures=recovery_attempts.failures+1, "
                "blocked_until=CASE WHEN recovery_attempts.failures+1>=5 THEN now()+interval '15 minutes' ELSE NULL END",
                (remote_ip, username_key),
            )
    return jsonify(message=RECOVERY_GENERIC_MESSAGE), 200


@app.post("/api/account/recovery-answers")
@signed_in
def update_recovery_answers():
    body = request.get_json(silent=True) or {}
    current_password = str(body.get("current_password", ""))
    hashes = recovery_answer_hashes(body.get("answers"))
    if not hashes:
        return jsonify(error="Answer all three recovery questions with 3–200 characters each."), 400
    username = session["profile"].get("username", "")
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='manual_users' FOR UPDATE").fetchone()
        users = row[0] if row else []
        account = next((u for u in users if str(u.get("username", "")).casefold() == username.casefold()), None)
        if not account or not account.get("password_hash") or not check_password_hash(account["password_hash"], current_password):
            return jsonify(error="Current password is incorrect."), 400
        account["recovery_answer_hashes"] = hashes
        conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='manual_users'", (json.dumps(users),))
    return jsonify(ok=True, message="Recovery answers saved securely.")


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


@app.get("/api/profile")
@signed_in
def profile():
    return jsonify(profile=session["profile"], isAdmin=session["is_admin"])


@app.get("/portal")
def public_helpdesk_page():
    return send_from_directory(ROOT, "portal.html")


@app.get("/api/public/portal-options")
def public_portal_options():
    with db() as conn:
        rows = {key: (conn.execute("SELECT value FROM app_state WHERE key=%s", (key,)).fetchone() or ([],))[0]
                for key in ("manual_users", "departments", "settings")}
    users = rows["manual_users"] if isinstance(rows["manual_users"], list) else []
    departments = rows["departments"] if isinstance(rows["departments"], list) else []
    settings = rows["settings"] if isinstance(rows["settings"], dict) else {}
    factories = [{"code": str(f.get("code", "")).strip(), "name": str(f.get("name", "")).strip()}
                 for f in settings.get("factories", []) if isinstance(f, dict) and f.get("code")]
    for code in ("ARG", "ARB", "ARC", "ARF"):
        if not any(f["code"].casefold() == code.casefold() for f in factories):
            factories.append({"code": code, "name": code})
    depts = []
    for item in departments:
        if isinstance(item, list) and len(item) > 6:
            name, factory, kind = item[0], item[6] or item[1], item[8] if len(item) > 8 else "department"
        elif isinstance(item, dict):
            name, factory, kind = item.get("name", ""), item.get("factory", ""), item.get("kind", "department")
        else:
            continue
        if name and factory and kind != "subdepartment":
            depts.append({"name": str(name), "factory": str(factory)})
    employees = []
    for u in users:
        if not isinstance(u, dict) or not u.get("enabled", True) or str(u.get("active", "Active")).lower() == "inactive":
            continue
        name = str(u.get("name") or "").strip()
        dept = str(u.get("dept") or u.get("department") or "").strip()
        site = str(u.get("site") or "").strip()
        key = str(u.get("username") or u.get("id") or "").strip()
        if name and dept and site and key:
            public_key = hashlib.sha256((APP_SECRET + "|" + key.casefold() + "|" + dept.casefold() + "|" + site.casefold()).encode()).hexdigest()
            employees.append({"key": public_key, "name": name, "department": dept, "factory": site})
    return jsonify(factories=factories, departments=depts, employees=employees)


@app.get("/api/public/tickets")
def public_ticket_list():
    kind = request.args.get("kind", "IT help desk")
    if kind not in ("IT help desk", "Material request"):
        return jsonify(error="Choose IT help desk or Material request."), 400
    with db() as conn:
        rows = conn.execute("""
            SELECT t.id,t.kind,t.display_name,t.department,t.factory,t.primary_category,t.sub_category,
                   t.description,t.attachments,t.assigned_to,t.status,t.eta,t.note,t.created_at,t.updated_at,
                   COALESCE((SELECT min(e.created_at) FROM ticket_events e WHERE e.ticket_id=t.id
                             AND e.event_type='updated' AND e.detail ~ '(^|; )status: (Resolved|Closed)(;|$)'), t.updated_at)
            FROM tickets t WHERE t.kind=%s ORDER BY t.created_at DESC LIMIT 5000
        """, (kind,)).fetchall()
    now = datetime.now(timezone.utc)
    result = []
    for r in rows:
        end = r[15] if r[10] in ("Resolved", "Closed") else now
        duration = max(0, int((end - r[13]).total_seconds() // 60))
        photos = []
        for item in (r[8] or []):
            name = Path(str(item.get("path", ""))).name
            if name and name == str(item.get("path", "")).split("/")[-1]:
                photos.append({"name": str(item.get("name") or name)[:160], "url": "/api/public/ticket-attachment?id=" + quote(r[0], safe="") + "&file=" + quote(name, safe="")})
        result.append({"id":r[0],"kind":r[1],"name":r[2],"department":r[3],"factory":r[4],"primary":r[5],"sub":r[6],
                       "description":r[7],"photos":photos,"assigned":r[9],"status":r[10],
                       "eta":r[11].isoformat(timespec="minutes") if r[11] else "","note":r[12],
                       "created":r[13].isoformat(timespec="minutes"),"durationMinutes":duration})
    return jsonify(tickets=result)


@app.get("/api/public/ticket-attachment")
def public_ticket_attachment():
    ticket_id = request.args.get("id", "")
    filename = request.args.get("file", "")
    if not ticket_id or Path(filename).name != filename:
        abort(404)
    with db() as conn:
        row = conn.execute("SELECT attachments FROM tickets WHERE id=%s", (ticket_id,)).fetchone()
    if not row:
        abort(404)
    match = next((item for item in (row[0] or []) if Path(str(item.get("path", ""))).name == filename), None)
    if not match:
        abort(404)
    parts = Path(str(match.get("path", ""))).parts
    if len(parts) != 3 or parts[0] != "tickets" or Path(parts[2]).name != parts[2]:
        abort(404)
    return send_from_directory(UPLOAD_DIR / parts[0] / parts[1], parts[2], as_attachment=False)


@app.post("/api/public/tickets")
def create_public_ticket():
    body = request.get_json(silent=True) or {}
    factory = str(body.get("factory", "")).strip()[:80]
    department = str(body.get("department", "")).strip()[:120]
    employee_key = str(body.get("employee", "")).strip()[:120]
    primary = str(body.get("primary", "IT help desk")).strip()[:80]
    sub = str(body.get("sub", "")).strip()[:80]
    description = str(body.get("description", "")).strip()[:5000]
    kind = "Material request" if body.get("kind") == "Material request" else "IT help desk"
    allowed_sub = {"Network", "Computer", "Printer", "Server", "Other", "ERP", "Software", "Manufacturing", "Laptop", "Desktop", "Monitor", "Network equipment", "Accessory"}
    if not all((factory, department, employee_key, description, sub)) or sub not in allowed_sub:
        return jsonify(error="Select your factory, department, name and issue category, then describe the issue."), 400
    with db() as conn:
        recent = conn.execute("SELECT count(*) FROM tickets WHERE client_ip=%s AND username LIKE 'public-%%' AND created_at>now()-interval '10 minutes'", (request.remote_addr or "127.0.0.1",)).fetchone()[0]
        if recent >= 5:
            return jsonify(error="Too many requests from this network. Please try again in a few minutes."), 429
        state = {key: (conn.execute("SELECT value FROM app_state WHERE key=%s", (key,)).fetchone() or ([],))[0]
                 for key in ("manual_users", "departments", "settings")}
        users = state["manual_users"] if isinstance(state["manual_users"], list) else []
        user = next((u for u in users if isinstance(u, dict)
                     and hashlib.sha256((APP_SECRET + "|" + str(u.get("username") or u.get("id") or "").casefold() + "|" + str(u.get("dept") or u.get("department") or "").casefold() + "|" + str(u.get("site") or "").casefold()).encode()).hexdigest() == employee_key
                     and str(u.get("dept") or u.get("department") or "").casefold() == department.casefold()
                     and str(u.get("site") or "").casefold() == factory.casefold()
                     and u.get("enabled", True) and str(u.get("active", "Active")).lower() != "inactive"), None)
        if not user:
            return jsonify(error="That employee is not active in the selected factory and department. Refresh the portal and choose again."), 400
        depts = state["departments"] if isinstance(state["departments"], list) else []
        dept_exists = any((str(d[0]).casefold() == department.casefold() and str((d[6] or d[1]) if len(d)>6 else "").casefold() == factory.casefold())
                          if isinstance(d, list) and len(d)>1 else
                          isinstance(d, dict) and str(d.get("name", "")).casefold() == department.casefold() and str(d.get("factory", "")).casefold() == factory.casefold()
                          for d in depts)
        custom_factories = (state["settings"] or {}).get("factories", []) if isinstance(state["settings"], dict) else []
        factory_exists = factory.upper() in {"ARG", "ARB", "ARC", "ARF"} or any(isinstance(f, dict) and str(f.get("code", "")).casefold() == factory.casefold() for f in custom_factories)
        if not dept_exists or not factory_exists:
            return jsonify(error="The selected factory or department is no longer available. Refresh the portal."), 400
        remote = request.remote_addr or "127.0.0.1"
        conn.execute("SELECT pg_advisory_xact_lock(hashtext(CURRENT_DATE::text))")
        seq = conn.execute("SELECT count(*) FROM tickets WHERE created_at::date=CURRENT_DATE").fetchone()[0] + 1
        token_date = datetime.now().strftime("%d-%m-%Y")
        ticket_id = f"IT{seq:02d}/{token_date}"
        tracking_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(tracking_token.encode()).hexdigest()
        username = "public-" + token_hash[:24]
        conn.execute("INSERT INTO tickets(id,kind,username,display_name,department,factory,client_ip,primary_category,sub_category,description,public_token_hash) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                     (ticket_id, kind, username, str(user.get("name") or "")[:120], department, factory, remote, primary, sub, description, token_hash))
        conn.execute("INSERT INTO ticket_events(ticket_id,actor,event_type,detail) VALUES(%s,'Public portal','created',%s)", (ticket_id, description[:500]))
    return jsonify(id=ticket_id, tracking_token=tracking_token), 201


@app.post("/api/public/tickets/status")
def get_public_ticket_status():
    tracking_token = str((request.get_json(silent=True) or {}).get("tracking_token", ""))
    if not re.fullmatch(r"[A-Za-z0-9_-]{40,60}", tracking_token):
        abort(404)
    token_hash = hashlib.sha256(tracking_token.encode()).hexdigest()
    with db() as conn:
        row = conn.execute("SELECT id,status,eta,note,updated_at FROM tickets WHERE public_token_hash=%s", (token_hash,)).fetchone()
    if not row:
        abort(404)
    return jsonify(id=row[0], status=row[1], eta=row[2].isoformat(timespec="minutes") if row[2] else "",
                   note=row[3], updated=row[4].isoformat(timespec="minutes") if row[4] else "")


@app.post("/api/account/profile-picture")
@signed_in
def update_profile_picture():
    upload = request.files.get("picture")
    if not upload or not upload.filename:
        return jsonify(error="Choose a profile picture first."), 400
    ext = Path(upload.filename).suffix.lower()
    if ext not in (".png", ".jpg", ".jpeg", ".webp"):
        return jsonify(error="Use a PNG, JPG, or WebP image."), 400
    data = upload.stream.read(2 * 1024 * 1024 + 1)
    valid = (ext == ".png" and data.startswith(b"\x89PNG\r\n\x1a\n")) or (ext in (".jpg", ".jpeg") and data.startswith(b"\xff\xd8\xff")) or (ext == ".webp" and data.startswith(b"RIFF") and data[8:12] == b"WEBP")
    if not data or len(data) > 2 * 1024 * 1024 or not valid:
        return jsonify(error="Use a valid image up to 2 MB."), 400
    username = session["profile"].get("username", "")
    filename = uuid.uuid4().hex + ext
    (PROFILE_MEDIA_DIR / filename).write_bytes(data)
    picture_url = "/profile-media/" + filename
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='manual_users' FOR UPDATE").fetchone()
        users = row[0] if row else []
        account = next((u for u in users if str(u.get("username", "")).casefold() == username.casefold()), None)
        if not account:
            (PROFILE_MEDIA_DIR / filename).unlink(missing_ok=True)
            return jsonify(error="Local account was not found."), 404
        account["profile_picture"] = picture_url
        conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='manual_users'", (json.dumps(users),))
    session["profile"]["profile_picture"] = picture_url
    return jsonify(ok=True, profile_picture=picture_url)

@app.post("/api/account/password")
@signed_in
def change_account_password():
    body = request.get_json(force=True)
    current_password = str(body.get("current_password", ""))
    new_password = str(body.get("new_password", ""))
    confirm_password = str(body.get("confirm_password", ""))
    if len(new_password) < 10 or len(new_password) > 1024:
        return jsonify(error="New password must be at least 10 characters long"), 400
    if new_password != confirm_password:
        return jsonify(error="New password and confirmation do not match"), 400
    username = session["profile"].get("username", "")
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='manual_users' FOR UPDATE").fetchone()
        users = row[0] if row else []
        account = next((u for u in users if str(u.get("username", "")).casefold() == username.casefold()), None)
        if not account or not account.get("password_hash"):
            return jsonify(error="Local account was not found."), 400
        if not check_password_hash(account["password_hash"], current_password):
            return jsonify(error="Current password is incorrect"), 400
        account["password_hash"] = generate_password_hash(new_password)
        account["auth_version"] = int(account.get("auth_version", 0) or 0) + 1
        conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='manual_users'", (json.dumps(users),))
        session["auth_version"] = account["auth_version"]
    return jsonify(ok=True, message="Password changed successfully")


@app.get("/api/data")
@signed_in
def get_data():
    who = session["profile"]
    with db() as conn:
        keys = ("assets", "software", "departments", "maintenance", "manual_users", "settings")
        out = {k: (conn.execute("SELECT value FROM app_state WHERE key=%s", (k,)).fetchone() or ([],))[0] for k in keys}
        if session.get("is_admin"):
            out["users"] = [{k:v for k,v in u.items() if k not in ("password_hash", "recovery_answer_hashes")} | {"source":"manual"} for u in out.pop("manual_users", [])]
        else:
            out.pop("manual_users", None)
            out.pop("settings", None)
            out["assets"] = [a for a in out["assets"] if str(a.get("owner", "")).casefold() in (who["username"].casefold(), who["name"].casefold(), who.get("email", "").casefold())]
            out["software"] = []
            out["maintenance"] = []
            out["users"] = [who]
        return jsonify(**out)


@app.put("/api/data")
@administrator
def save_data():
    body = request.get_json(force=True)
    with db() as conn:
        for key in ("assets", "software", "departments", "maintenance", "manual_users", "settings"):
            if key in body:
                value = body[key]
                if key == "assets" and isinstance(value, list):
                    current = (conn.execute("SELECT value FROM app_state WHERE key='assets'").fetchone() or ([],))[0]
                    prior_by_tag = {str(a.get("tag", "")).casefold(): a for a in current}
                    reconciled = []
                    for item in value:
                        asset = dict(item)
                        prior = prior_by_tag.get(str(asset.get("tag", "")).casefold(), {})
                        old_ip = str(prior.get("ipAddress", prior.get("ip_address", ""))).strip()
                        new_ip = str(asset.get("ipAddress", asset.get("ip_address", ""))).strip()
                        if prior and old_ip == new_ip:
                            for field in ("status", "ipStatus", "ipCheckedAt", "lastSeen"):
                                if field in prior:
                                    asset[field] = prior[field]
                        else:
                            asset["status"] = "Not checked"
                            asset["ipStatus"] = "Not checked"
                            asset["ipCheckedAt"] = ""
                        reconciled.append(asset)
                    value = reconciled
                if key == "manual_users":
                    current = (conn.execute("SELECT value FROM app_state WHERE key='manual_users'").fetchone() or ([],))[0]
                    existing = {str(u.get("username", "")).casefold(): u for u in current}
                    clean = []
                    for item in value:
                        user = dict(item)
                        username = str(user.get("username", "")).strip()
                        if not username:
                            continue
                        if not re.fullmatch(r"[A-Za-z0-9._@-]{3,80}", username):
                            return jsonify(error="Usernames must be 3–80 letters, numbers, dots, underscores, @, or hyphens."), 400
                        prior = existing.get(username.casefold(), {})
                        old_ip = str(prior.get("ip_address", prior.get("ipAddress", ""))).strip()
                        new_ip = str(user.get("ip_address", user.get("ipAddress", ""))).strip()
                        if prior and old_ip == new_ip:
                            for field in ("ipStatus", "ipCheckedAt", "lastSeen"):
                                if field in prior:
                                    user[field] = prior[field]
                        elif new_ip:
                            user["ipStatus"] = "Not checked"
                            user["ipCheckedAt"] = ""
                        new_password = user.pop("password", "")
                        user.pop("password_confirm", None)
                        if new_password:
                            if len(new_password) < 10 or len(new_password) > 1024:
                                return jsonify(error="Account passwords must be at least 10 characters long."), 400
                            user["password_hash"] = generate_password_hash(new_password)
                            user["auth_version"] = int(prior.get("auth_version", 0) or 0) + 1
                        elif prior.get("password_hash"):
                            user["password_hash"] = prior["password_hash"]
                            user["auth_version"] = int(prior.get("auth_version", 0) or 0)
                        if prior.get("recovery_answer_hashes"):
                            user["recovery_answer_hashes"] = prior["recovery_answer_hashes"]
                        if "password_hash" not in user:
                            user["password_hash"] = ""
                        user["username"] = username
                        user["role"] = user.get("role") if user.get("role") in ("Administrator", "IT Ticketing") else "User"
                        user["enabled"] = user.get("enabled", True)
                        clean.append(user)
                    if not any(u.get("enabled", True) and u.get("role") == "Administrator" and u.get("password_hash") for u in clean):
                        return jsonify(error="Keep at least one enabled Administrator account with a password."), 400
                    value = clean
                conn.execute("INSERT INTO app_state(key,value) VALUES(%s,%s::jsonb) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()", (key, json.dumps(value)))
    return jsonify(ok=True)


def ticket_json(row):
    return {"id":row[0],"kind":row[1],"username":row[2],"name":row[3],"dept":row[4],"site":row[5],"ip":str(row[6] or ""),"primary":row[7],"sub":row[8],"description":row[9],"material":row[10],"files":row[11],"assigned":row[12],"status":row[13],"eta":row[14].isoformat(timespec="minutes") if row[14] else "","note":row[15],"updated":row[16].isoformat(timespec="minutes") if row[16] else ""}


TICKET_COLUMNS = "id,kind,username,display_name,department,factory,client_ip,primary_category,sub_category,description,material,attachments,assigned_to,status,eta,note,updated_at"


@app.get("/api/tickets")
@signed_in
def list_tickets():
    with db() as conn:
        if session.get("is_admin") or session.get("profile", {}).get("role") == "IT Ticketing":
            rows = conn.execute(f"SELECT {TICKET_COLUMNS} FROM tickets ORDER BY created_at DESC LIMIT 1000").fetchall()
        else:
            rows = conn.execute(f"SELECT {TICKET_COLUMNS} FROM tickets WHERE username=%s ORDER BY created_at DESC LIMIT 250", (session["profile"]["username"],)).fetchall()
    return jsonify(tickets=[ticket_json(r) for r in rows])


@app.get("/api/tickets/<path:ticket_id>/attachments/<path:filename>")
@signed_in
def ticket_attachment(ticket_id, filename):
    with db() as conn:
        row = conn.execute("SELECT username,attachments FROM tickets WHERE id=%s", (ticket_id,)).fetchone()
    if not row:
        abort(404)
    if not session.get("is_admin") and session.get("profile", {}).get("role") != "IT Ticketing" and row[0] != session["profile"]["username"]:
        abort(403)
    match = next((item for item in row[1] if Path(item.get("path", "")).name == filename), None)
    if not match:
        abort(404)
    return send_from_directory(UPLOAD_DIR / "tickets" / ticket_id.split("/")[-1], filename, as_attachment=False)


@app.post("/api/tickets")
@signed_in
def create_ticket():
    form = request.form
    description = form.get("description", "").strip()
    kind = form.get("kind", "IT help desk")
    primary = form.get("primary", "")
    sub = form.get("sub", "")
    if not description or not sub or kind not in ("IT help desk", "Material request"):
        return jsonify(error="Complete the issue description and category"), 400
    files = request.files.getlist("files")
    if len(files) > 3:
        return jsonify(error="Attach up to three screenshots"), 400
    token_date = datetime.now().strftime("%d-%m-%Y")
    ticket_dir = UPLOAD_DIR / "tickets" / token_date
    ticket_dir.mkdir(parents=True, exist_ok=True)
    profile = session["profile"]
    remote = request.remote_addr
    with db() as conn:
        conn.execute("SELECT pg_advisory_xact_lock(hashtext(CURRENT_DATE::text))")
        seq = conn.execute("SELECT count(*) FROM tickets WHERE created_at::date=CURRENT_DATE").fetchone()[0] + 1
        ticket_id = f"IT{seq:02d}/{token_date}"
        saved = []
        for f in files:
            if not f.filename:
                continue
            if f.mimetype not in ("image/png", "image/jpeg", "image/gif", "image/webp"):
                return jsonify(error="Only image attachments are accepted"), 400
            ext = Path(secure_filename(f.filename)).suffix[:10]
            stored = f"{ticket_id.replace('/', '-')}-{uuid.uuid4().hex}{ext}"
            f.save(ticket_dir / stored)
            saved.append({"name":secure_filename(f.filename),"path":f"tickets/{token_date}/{stored}"})
        conn.execute("INSERT INTO tickets(id,kind,username,display_name,department,factory,client_ip,primary_category,sub_category,description,material,attachments) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)", (ticket_id,kind,profile["username"],profile["name"],profile.get("department", ""),profile.get("site", ""),remote,primary,sub,description,form.get("material", ""),json.dumps(saved)))
        conn.execute("INSERT INTO ticket_events(ticket_id,actor,event_type,detail) VALUES(%s,%s,'created',%s)", (ticket_id,profile["username"],description[:500]))
    return jsonify(id=ticket_id), 201


@app.patch("/api/tickets/<path:ticket_id>")
@ticket_manager
def update_ticket(ticket_id):
    body = request.get_json(force=True)
    allowed = {"assigned":"assigned_to", "status":"status", "eta":"eta", "note":"note"}
    fields = [(allowed[k], (None if k == "eta" and v == "" else v)) for k,v in body.items() if k in allowed]
    if not fields:
        return jsonify(error="No supported fields to update"), 400
    if "status" in body and body["status"] not in ("Open", "In progress", "Resolved", "Closed"):
        return jsonify(error="Invalid status"), 400
    if "assigned" in body and len(str(body["assigned"])) > 160:
        return jsonify(error="Assignee name is too long."), 400
    if "eta" in body and body["eta"] not in (None, "") and len(str(body["eta"])) > 40:
        return jsonify(error="Invalid ETA."), 400
    assignments = ", ".join(f"{column}=%s" for column,_ in fields)
    with db() as conn:
        cur = conn.execute(f"UPDATE tickets SET {assignments}, updated_at=now() WHERE id=%s RETURNING id", [v for _,v in fields]+[ticket_id])
        if not cur.fetchone():
            abort(404)
        detail = "; ".join(f"{k}: {v}" for k,v in body.items() if k in allowed)[:1000]
        conn.execute("INSERT INTO ticket_events(ticket_id,actor,event_type,detail) VALUES(%s,%s,'updated',%s)", (ticket_id,session["profile"]["username"],detail))
    return jsonify(ok=True)


@app.post("/api/tickets/<path:ticket_id>/worklog")
@ticket_manager
def add_ticket_worklog(ticket_id):
    body = request.get_json(silent=True) or {}
    detail = str(body.get("detail", "")).strip()
    if not detail or len(detail) > 3000:
        return jsonify(error="Enter a work update (up to 3000 characters)."), 400
    actor = str(session.get("profile", {}).get("name") or session["profile"].get("username", "IT"))[:120]
    with db() as conn:
        row = conn.execute("UPDATE tickets SET note=%s,updated_at=now() WHERE id=%s RETURNING id", (detail, ticket_id)).fetchone()
        if not row:
            abort(404)
        conn.execute("INSERT INTO ticket_events(ticket_id,actor,event_type,detail) VALUES(%s,%s,'worklog',%s)", (ticket_id, actor, detail))
    return jsonify(ok=True)


@app.get("/api/tickets/<path:ticket_id>/worklog")
@ticket_manager
def list_ticket_worklog(ticket_id):
    with db() as conn:
        if not conn.execute("SELECT 1 FROM tickets WHERE id=%s", (ticket_id,)).fetchone():
            abort(404)
        rows = conn.execute("SELECT actor,detail,created_at FROM ticket_events WHERE ticket_id=%s AND event_type IN ('created','updated','worklog') ORDER BY created_at DESC LIMIT 100", (ticket_id,)).fetchall()
    return jsonify(events=[{"actor":r[0],"detail":r[1],"created":r[2].isoformat(timespec="minutes")} for r in rows])


@app.get("/api/backups")
@administrator
def backup_list():
    path = Path(os.getenv("BACKUP_DIR", "/backups"))
    files = sorted(path.glob("northstar-*.tar.gz"), key=lambda x:x.stat().st_mtime, reverse=True) if path.exists() else []
    return jsonify(backups=[{"name":p.name,"size":p.stat().st_size,"created":datetime.fromtimestamp(p.stat().st_mtime,timezone.utc).isoformat()} for p in files[:100]])


@app.get("/api/backups/<path:name>")
@administrator
def download_backup(name):
    if not re.fullmatch(r"northstar-(daily|weekly|monthly|manual)-[0-9T-]+\.tar\.gz", name):
        abort(404)
    return send_from_directory(os.getenv("BACKUP_DIR", "/backups"), name, as_attachment=True)


@app.post("/api/backups")
@administrator
def create_manual_backup():
    try:
        result = subprocess.run(["python", str(ROOT / "backup.py"), "manual"], capture_output=True, text=True, check=True, timeout=1800)
        return jsonify(name=result.stdout.strip())
    except subprocess.TimeoutExpired:
        return jsonify(error="Backup is taking longer than expected. Check server logs."), 504
    except subprocess.CalledProcessError as exc:
        app.logger.error("Manual backup failed: %s", exc.stderr[-1000:])
        return jsonify(error="Backup failed. Check server logs."), 500


@app.errorhandler(413)
def too_large(_):
    return jsonify(error="Request too large (maximum 12 MB)"), 413


init_db()
