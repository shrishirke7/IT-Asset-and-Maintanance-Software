import base64
import json
import os
import re
import secrets
import ssl
import subprocess
import uuid
import hashlib
import ipaddress
import threading
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse

import psycopg
from flask import Flask, abort, jsonify, request, send_from_directory, session
from flask.wrappers import Response
from ldap3 import BASE, Connection, Server, SIMPLE, Tls
from ldap3.utils.conv import escape_filter_chars
from cryptography.fernet import Fernet
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash

ROOT = Path(__file__).resolve().parent
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", ROOT / "uploads"))
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
LOGIN_MEDIA_DIR = UPLOAD_DIR / "login-branding"
LOGIN_MEDIA_DIR.mkdir(parents=True, exist_ok=True)
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
LDAP_URL = os.getenv("LDAP_URL", "")
LDAP_BASE_DN = os.getenv("LDAP_BASE_DN", "")
LDAP_UPN_SUFFIX = os.getenv("LDAP_UPN_SUFFIX", "")
LDAP_BIND_USER = os.getenv("LDAP_BIND_USER", "")
LDAP_BIND_PASSWORD_B64 = os.getenv("LDAP_BIND_PASSWORD_B64", "")
LDAP_CA_FILE = os.getenv("LDAP_CA_FILE", "/run/secrets/ad-ca.pem")
LDAP_SITE_ATTRIBUTE = os.getenv("LDAP_SITE_ATTRIBUTE", "physicalDeliveryOfficeName")
ADMIN_GROUP_DNS = [x.strip().casefold() for x in os.getenv("AD_ADMIN_GROUP_DNS", "").split(";") if x.strip()]
FACTORY_MAP = {"arg": "ARG", "arb": "ARB", "arc": "ARC", "arf": "ARF"}


def db():
    return psycopg.connect(DATABASE_URL, connect_timeout=8)


def init_db():
    with db() as conn:
        schema = (ROOT / "schema.sql").read_text(encoding="utf-8")
        for statement in schema.split(";"):
            if statement.strip():
                conn.execute(statement)
        conn.execute("INSERT INTO app_state(key,value) VALUES('assets','[]'),('software','[]'),('departments','[]'),('maintenance','[]'),('manual_users','[]'),('network_ranges','[]'),('network_scan','{}'),('settings','{}') ON CONFLICT(key) DO NOTHING")
        manual_row = conn.execute("SELECT value FROM app_state WHERE key='manual_users' FOR UPDATE").fetchone()
        manual_users = manual_row[0] if manual_row else []
        username_exists = any(str(u.get("username", "")).casefold() == "administrator1" for u in manual_users)
        if not username_exists:
            manual_users.append({"username":"administrator1", "id":"administrator1", "name":"Local Administrator", "site":"", "dept":"", "role":"Administrator", "enabled":True, "source":"manual", "password_hash":generate_password_hash(os.getenv("LOCAL_ADMIN_PASSWORD", "Admin@123"))})
            conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='manual_users'", (json.dumps(manual_users),))


def directory_server():
    parsed = urlparse(LDAP_URL)
    if parsed.scheme not in ("ldaps", "ldap") or not parsed.hostname:
        raise ValueError("LDAP_URL must be ldaps://host:636 or ldap://host:389 with StartTLS enabled")
    if parsed.scheme == "ldap" and os.getenv("LDAP_STARTTLS", "true").lower() != "true":
        raise ValueError("Plain, unencrypted LDAP is disabled. Enable StartTLS or use LDAPS.")
    ca_file = LDAP_CA_FILE if Path(LDAP_CA_FILE).is_file() and Path(LDAP_CA_FILE).stat().st_size else None
    tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=ca_file, version=ssl.PROTOCOL_TLS_CLIENT)
    return Server(parsed.hostname, port=parsed.port or (636 if parsed.scheme == "ldaps" else 389), use_ssl=parsed.scheme == "ldaps", tls=tls, connect_timeout=6)


def directory_connection(user, password):
    server = directory_server()
    conn = Connection(server, user=user, password=password, authentication=SIMPLE, auto_bind=False, raise_exceptions=True, receive_timeout=8)
    conn.open()
    if server.ssl is False:
        conn.start_tls()
    conn.bind()
    return conn


def directory_fernet():
    # The credential key is derived from the persistent server APP_SECRET and is
    # never sent to the browser. Keep APP_SECRET safe and include it in backups.
    key = base64.urlsafe_b64encode(hashlib.sha256(APP_SECRET.encode("utf-8")).digest())
    return Fernet(key)


def clean_directory_config(data, require_password=True):
    data = data or {}
    name = str(data.get("name", "")).strip()[:100]
    host = str(data.get("host", "")).strip()
    if "://" in host or "/" in host or "@" in host or any(ch.isspace() for ch in host):
        raise ValueError("Enter only the directory server hostname or IP address")
    if not (re.fullmatch(r"[A-Za-z0-9.-]+", host) or (":" in host and _valid_ipv6(host))):
        raise ValueError("Enter a valid hostname or IP address")
    port = int(data.get("port") or 636)
    security = str(data.get("security", "ldaps")).lower()
    if not name or not host or not 1 <= port <= 65535:
        raise ValueError("Server name, host and a valid port are required")
    if security not in ("ldaps", "starttls"):
        raise ValueError("Directory connections must use LDAPS or StartTLS")
    result = {
        "name": name, "host": host, "port": port, "security": security,
        "bind_dn": str(data.get("bind_dn", "")).strip()[:512],
        "base_dn": str(data.get("base_dn", "")).strip()[:512],
        "user_filter": str(data.get("user_filter", "(&(objectCategory=person)(objectClass=user))")).strip()[:1000],
        "group_filter": str(data.get("group_filter", "(&(objectCategory=group)(objectClass=group))")).strip()[:1000],
        "username_attribute": str(data.get("username_attribute", "sAMAccountName")).strip()[:100],
        "display_attribute": str(data.get("display_attribute", "displayName")).strip()[:100],
        "email_attribute": str(data.get("email_attribute", "mail")).strip()[:100],
        "department_attribute": str(data.get("department_attribute", "department")).strip()[:100],
        "password": str(data.get("password", "")),
    }
    if not result["bind_dn"] or not result["base_dn"] or not result["user_filter"] or not result["group_filter"]:
        raise ValueError("Bind DN, Base DN, and user/group filters are required")
    for attribute in (result["username_attribute"],result["display_attribute"],result["email_attribute"],result["department_attribute"]):
        if not re.fullmatch(r"(?:[A-Za-z][A-Za-z0-9-]*|[0-9]+(?:\.[0-9]+)+)", attribute):
            raise ValueError("Use valid LDAP attribute names (for example sAMAccountName, displayName, or entryUUID)")
    if require_password and not result["password"]:
        raise ValueError("Bind password is required")
    if result["password"] and len(result["password"]) > 1024:
        raise ValueError("Bind password is too long")
    return result


def _valid_ipv6(host):
    try:
        return ipaddress.ip_address(host).version == 6
    except ValueError:
        return False


def directory_connection_for(config, password):
    tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=LDAP_CA_FILE if Path(LDAP_CA_FILE).is_file() else None, version=ssl.PROTOCOL_TLS_CLIENT)
    server = Server(config["host"], port=config["port"], use_ssl=config["security"] == "ldaps", tls=tls, connect_timeout=8)
    conn = Connection(server, user=config["bind_dn"], password=password, authentication=SIMPLE, auto_bind=False, raise_exceptions=True, receive_timeout=12)
    conn.open()
    if config["security"] == "starttls":
        conn.start_tls()
    conn.bind()
    return conn


def directory_entry_value(attributes, key, default=""):
    value = attributes.get(key, default)
    if isinstance(value, list):
        value = value[0] if value else default
    if isinstance(value, bytes):
        return value.hex()
    return str(value or default)


def read_profile(username, conn):
    filt = f"(&(objectCategory=person)(objectClass=user)(sAMAccountName={escape_filter_chars(username)}))"
    attrs = ["sAMAccountName", "displayName", "mail", "department", "title", "memberOf", LDAP_SITE_ATTRIBUTE, "userAccountControl"]
    if not conn.search(LDAP_BASE_DN, filt, attributes=attrs, size_limit=2) or len(conn.entries) != 1:
        raise ValueError("The AD user profile could not be found or is not unique")
    entry = conn.entries[0]
    def attr(name, default=""):
        return str(entry[name].value or default) if name in entry else default
    groups = [str(x) for x in (entry["memberOf"].values if "memberOf" in entry else [])]
    raw_site = attr(LDAP_SITE_ATTRIBUTE).strip()
    site = FACTORY_MAP.get(raw_site.casefold(), raw_site.upper() if raw_site.upper() in FACTORY_MAP.values() else "")
    return {
        "username": attr("sAMAccountName", username).lower(),
        "name": attr("displayName", username),
        "email": attr("mail"),
        "department": attr("department"),
        "site": site,
        "title": attr("title"),
        "groups": groups,
    }


def is_admin(profile):
    return bool(set(x.casefold() for x in profile.get("groups", [])) & set(ADMIN_GROUP_DNS))


def signed_in(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("profile"):
            return jsonify(error="sign_in_required"), 401
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


@app.before_request
def check_api_origin():
    if request.path.startswith("/api/") and request.method in ("POST", "PUT", "PATCH", "DELETE"):
        origin = request.headers.get("Origin")
        if origin and origin.rstrip("/") != request.host_url.rstrip("/"):
            abort(403)
        if request.headers.get("X-Requested-With") != "NorthstarIT":
            abort(403)


@app.get("/")
def index():
    return send_from_directory(ROOT, "index.html")


@app.get("/api/login-branding")
def get_login_branding():
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='settings'").fetchone()
    settings = row[0] if row else {}
    branding = settings.get("loginBranding", {})
    return jsonify({
        "companyName": str(branding.get("companyName") or settings.get("companyName") or "Swarnshilp")[:120],
        "tagline": str(branding.get("tagline") or "Elegance in every connection")[:180],
        "logoUrl": str(branding.get("logoUrl") or "")[:300],
        "slides": branding.get("slides", [])[:5] if isinstance(branding.get("slides", []), list) else [],
        "slideInterval": max(3, min(30, int(branding.get("slideInterval", 6) or 6))),
    })


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
        company = str(request.form.get("companyName", "Swarnshilp")).strip()[:120] or "Swarnshilp"
        tagline = str(request.form.get("tagline", "Elegance in every connection")).strip()[:180] or "Elegance in every connection"
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
                slides.append({"imageUrl": image_url, "caption": tagline})
        branding.update(companyName=company, tagline=tagline, slides=slides, slideInterval=interval)
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
    return jsonify(ranges=ranges, scan=state)


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


@app.get("/api/internal/scanner-task")
def scanner_task():
    if not _scanner_authorized():
        abort(403)
    with db() as conn:
        row = conn.execute("SELECT value FROM app_state WHERE key='network_scan' FOR UPDATE").fetchone()
        state = row[0] if row else {}
        if state.get("status") != "queued":
            return ("", 204)
        ranges = (conn.execute("SELECT value FROM app_state WHERE key='network_ranges'").fetchone() or ([],))[0]
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
    return jsonify(ok=True)


@app.post("/api/login")
def login():
    body = request.get_json(silent=True) or {}
    username = str(body.get("username", "")).strip().split("\\")[-1]
    password = str(body.get("password", ""))
    if not username or not password or len(username) > 120 or len(password) > 1024:
        return jsonify(error="Enter your AD username and password"), 400
    remote_ip = request.remote_addr or "127.0.0.1"
    with db() as conn:
        row = conn.execute("SELECT failures, blocked_until FROM login_attempts WHERE client_ip=%s", (remote_ip,)).fetchone()
        if row and row[1] and row[1] > datetime.now(timezone.utc):
            return jsonify(error="Too many attempts. Wait 15 minutes and try again."), 429
        local_state = conn.execute("SELECT value FROM app_state WHERE key='manual_users'").fetchone()
    local_users = local_state[0] if local_state else []
    local_user = next((u for u in local_users if str(u.get("username", "")).casefold() == username.casefold()), None)
    if local_user and local_user.get("enabled", True) and local_user.get("password_hash"):
        try:
            valid_local = check_password_hash(local_user["password_hash"], password)
        except (ValueError, TypeError):
            valid_local = False
        if valid_local:
            profile = {"username": str(local_user["username"]).lower(), "name": local_user.get("name") or local_user["username"], "email": local_user.get("email", ""), "dept": local_user.get("dept", ""), "site": local_user.get("site", ""), "role": local_user.get("role", "User"), "groups": []}
            with db() as conn:
                conn.execute("DELETE FROM login_attempts WHERE client_ip=%s", (remote_ip,))
            session.clear()
            session.permanent = True
            session["is_admin"] = profile["role"] == "Administrator"
            session["profile"] = {key:value for key,value in profile.items() if key != "groups"}
            return jsonify(profile=session["profile"], isAdmin=session["is_admin"])
    bind_name = username if "@" in username else f"{username}@{LDAP_UPN_SUFFIX}" if LDAP_UPN_SUFFIX else username
    try:
        user_conn = directory_connection(bind_name, password)
        user_conn.unbind()
        if not LDAP_BIND_USER or not LDAP_BIND_PASSWORD_B64:
            raise RuntimeError("Configure a read-only LDAP service account in .env")
        bind_password = base64.b64decode(LDAP_BIND_PASSWORD_B64).decode("utf-8")
        svc = directory_connection(LDAP_BIND_USER, bind_password)
        try:
            profile = read_profile(username, svc)
        finally:
            svc.unbind()
        # Disabled AD accounts are never allowed to establish an application session.
        if profile["username"] != username.lower():
            return jsonify(error="AD account is disabled or could not be verified"), 403
        with db() as conn:
            conn.execute("DELETE FROM login_attempts WHERE client_ip=%s", (remote_ip,))
        session.clear()
        session.permanent = True
        session["is_admin"] = is_admin(profile)
        session["profile"] = {key:value for key,value in profile.items() if key != "groups"}
        return jsonify(profile=profile, isAdmin=session["is_admin"])
    except Exception as exc:
        # Never return LDAP diagnostics or user credentials to the browser.
        with db() as conn:
            conn.execute("INSERT INTO login_attempts(client_ip,failures,blocked_until) VALUES(%s,1,NULL) ON CONFLICT(client_ip) DO UPDATE SET failures=login_attempts.failures+1, blocked_until=CASE WHEN login_attempts.failures+1>=5 THEN now()+interval '15 minutes' ELSE NULL END", (remote_ip,))
        app.logger.warning("AD sign-in failed: %s", type(exc).__name__)
        return jsonify(error="AD sign-in failed. Check your credentials or ask the administrator to check LDAP connectivity."), 401


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


@app.get("/api/profile")
@signed_in
def profile():
    return jsonify(profile=session["profile"], isAdmin=session["is_admin"])


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
            return jsonify(error="This account uses Active Directory. Change its password in Active Directory."), 400
        if not check_password_hash(account["password_hash"], current_password):
            return jsonify(error="Current password is incorrect"), 400
        account["password_hash"] = generate_password_hash(new_password)
        conn.execute("UPDATE app_state SET value=%s::jsonb,updated_at=now() WHERE key='manual_users'", (json.dumps(users),))
    return jsonify(ok=True, message="Password changed successfully")


@app.post("/api/admin/directory-sync")
@administrator
def sync_directory():
    bind_password = base64.b64decode(LDAP_BIND_PASSWORD_B64).decode("utf-8")
    conn = directory_connection(LDAP_BIND_USER, bind_password)
    try:
        conn.search(LDAP_BASE_DN, "(&(objectCategory=person)(objectClass=user))", attributes=["sAMAccountName", "displayName", "mail", "department", "title", "memberOf", LDAP_SITE_ATTRIBUTE, "userAccountControl"])
        synced = []
        for e in conn.entries:
            username = str(e["sAMAccountName"].value or "").lower()
            if not username:
                continue
            display = str(e["displayName"].value or username) if "displayName" in e else username
            email = str(e["mail"].value or "") if "mail" in e else ""
            dept = str(e["department"].value or "") if "department" in e else ""
            title = str(e["title"].value or "") if "title" in e else ""
            raw_site = str(e[LDAP_SITE_ATTRIBUTE].value or "").strip() if LDAP_SITE_ATTRIBUTE in e else ""
            site = FACTORY_MAP.get(raw_site.casefold(), raw_site.upper() if raw_site.upper() in FACTORY_MAP.values() else "")
            uac = int(e["userAccountControl"].value or 0) if "userAccountControl" in e else 0
            enabled = not bool(uac & 2)
            synced.append((username, display, email, dept, site, title, json.dumps([str(g) for g in (e["memberOf"].values if "memberOf" in e else [])]), enabled))
        with db() as out:
            out.execute("UPDATE directory_users SET enabled=false WHERE NOT (username = ANY(%s))", ([record[0] for record in synced],))
            for rec in synced:
                out.execute("INSERT INTO directory_users(username,display_name,email,department,factory,title,groups,enabled) VALUES(%s,%s,%s,%s,%s,%s,%s::jsonb,%s) ON CONFLICT(username) DO UPDATE SET display_name=excluded.display_name,email=excluded.email,department=excluded.department,factory=excluded.factory,title=excluded.title,groups=excluded.groups,enabled=excluded.enabled,synced_at=now()", rec)
        return jsonify(synced=len(synced), message="Directory sync complete")
    finally:
        conn.unbind()


@app.get("/api/directory/users")
@administrator
def directory_users():
    with db() as conn:
        rows = conn.execute("SELECT username,display_name,email,department,factory,title,enabled FROM directory_users ORDER BY display_name").fetchall()
        synced = conn.execute("SELECT o.username,o.display_name,o.email,o.department,o.factory,o.title,o.enabled,s.name FROM directory_objects o JOIN directory_servers s ON s.id=o.server_id WHERE o.object_type='user' ORDER BY o.display_name LIMIT 10000").fetchall()
    users = [{"username":r[0],"name":r[1],"email":r[2],"department":r[3],"site":r[4],"title":r[5],"enabled":r[6]} for r in rows]
    users.extend({"username":r[0],"name":r[1],"email":r[2],"department":r[3],"site":r[4],"title":r[5],"enabled":r[6],"active":"Active" if r[6] else "Disabled","role":"Employee","directory":r[7]} for r in synced if r[0])
    return jsonify(users=users)


def directory_config_from_row(row):
    return {"id": str(row[0]), "name": row[1], "host": row[2], "port": row[3], "security": row[4],
            "bind_dn": row[5], "encrypted_password": row[6], "base_dn": row[7], "user_filter": row[8],
            "group_filter": row[9], "username_attribute": row[10], "display_attribute": row[11],
            "email_attribute": row[12], "department_attribute": row[13], "enabled": row[14],
            "last_sync": row[15].isoformat(timespec="minutes") if row[15] else "", "last_error": row[16]}


DIRECTORY_SERVER_COLUMNS = "id,name,host,port,security,bind_dn,encrypted_password,base_dn,user_filter,group_filter,username_attribute,display_attribute,email_attribute,department_attribute,enabled,last_sync,last_error"


@app.get("/api/admin/directory-servers")
@administrator
def list_directory_servers():
    with db() as conn:
        rows = conn.execute(f"SELECT {DIRECTORY_SERVER_COLUMNS} FROM directory_servers ORDER BY name").fetchall()
        configs = [directory_config_from_row(r) for r in rows]
        for item in configs:
            item.pop("encrypted_password", None)
            item["has_password"] = True
        objects = conn.execute("SELECT server_id,object_type,object_id,username,display_name,email,department,factory,title,groups,enabled,synced_at FROM directory_objects ORDER BY display_name LIMIT 10000").fetchall()
    return jsonify(servers=configs, objects=[{"server_id":str(r[0]),"type":r[1],"id":r[2],"username":r[3],"name":r[4],"email":r[5],"department":r[6],"factory":r[7],"title":r[8],"groups":r[9],"enabled":r[10],"synced_at":r[11].isoformat(timespec="minutes")} for r in objects])


@app.post("/api/admin/directory-servers/test")
@administrator
def test_directory_server():
    try:
        body = request.get_json(force=True)
        config = clean_directory_config(body, require_password=False)
        password = config["password"]
        if not password and body.get("id"):
            with db() as saved_db:
                row = saved_db.execute("SELECT encrypted_password FROM directory_servers WHERE id=%s", (body["id"],)).fetchone()
            if not row: raise ValueError("Directory server not found")
            password = directory_fernet().decrypt(row[0].encode()).decode()
        if not password: raise ValueError("Bind password is required")
        conn = directory_connection_for(config, password)
        try:
            ok = conn.search(config["base_dn"], "(objectClass=*)", search_scope=BASE, attributes=["objectClass"], size_limit=1)
            if not ok:
                raise ValueError("Base DN could not be verified")
        finally:
            conn.unbind()
        return jsonify(ok=True, message="Secure directory connection and Base DN verified")
    except Exception as exc:
        app.logger.warning("Directory connection test failed: %s", type(exc).__name__)
        return jsonify(error="Connection failed. Check host, TLS certificate, port, bind DN, password, and Base DN."), 400


@app.post("/api/admin/directory-servers")
@administrator
def create_directory_server():
    try:
        config = clean_directory_config(request.get_json(force=True))
        server_id = uuid.uuid4()
        encrypted = directory_fernet().encrypt(config["password"].encode()).decode()
        with db() as conn:
            conn.execute("INSERT INTO directory_servers(id,name,host,port,security,bind_dn,encrypted_password,base_dn,user_filter,group_filter,username_attribute,display_attribute,email_attribute,department_attribute,enabled) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)", (server_id,config["name"],config["host"],config["port"],config["security"],config["bind_dn"],encrypted,config["base_dn"],config["user_filter"],config["group_filter"],config["username_attribute"],config["display_attribute"],config["email_attribute"],config["department_attribute"],bool((request.get_json(silent=True) or {}).get("enabled", True))))
        return jsonify(id=str(server_id), ok=True), 201
    except (ValueError, TypeError) as exc:
        return jsonify(error=str(exc)), 400


@app.put("/api/admin/directory-servers/<uuid:server_id>")
@administrator
def update_directory_server(server_id):
    try:
        body = request.get_json(force=True)
        config = clean_directory_config(body, require_password=False)
        with db() as conn:
            row = conn.execute("SELECT encrypted_password FROM directory_servers WHERE id=%s", (server_id,)).fetchone()
            if not row:
                return jsonify(error="Directory server not found"), 404
            encrypted = directory_fernet().encrypt(config["password"].encode()).decode() if config["password"] else row[0]
            conn.execute("UPDATE directory_servers SET name=%s,host=%s,port=%s,security=%s,bind_dn=%s,encrypted_password=%s,base_dn=%s,user_filter=%s,group_filter=%s,username_attribute=%s,display_attribute=%s,email_attribute=%s,department_attribute=%s,enabled=%s,last_error='' WHERE id=%s", (config["name"],config["host"],config["port"],config["security"],config["bind_dn"],encrypted,config["base_dn"],config["user_filter"],config["group_filter"],config["username_attribute"],config["display_attribute"],config["email_attribute"],config["department_attribute"],bool(body.get("enabled", True)),server_id))
        return jsonify(ok=True)
    except (ValueError, TypeError) as exc:
        return jsonify(error=str(exc)), 400


@app.delete("/api/admin/directory-servers/<uuid:server_id>")
@administrator
def delete_directory_server(server_id):
    with db() as conn:
        conn.execute("DELETE FROM directory_servers WHERE id=%s", (server_id,))
    return jsonify(ok=True)


@app.post("/api/admin/directory-servers/<uuid:server_id>/sync")
@administrator
def sync_configured_directory(server_id):
    with db() as conn:
        row = conn.execute(f"SELECT {DIRECTORY_SERVER_COLUMNS} FROM directory_servers WHERE id=%s AND enabled=true", (server_id,)).fetchone()
    if not row:
        return jsonify(error="Enabled directory server not found"), 404
    saved = directory_config_from_row(row)
    try:
        password = directory_fernet().decrypt(saved["encrypted_password"].encode()).decode()
        conn = directory_connection_for(saved, password)
        try:
            attrs = list(dict.fromkeys([saved["username_attribute"],saved["display_attribute"],saved["email_attribute"],saved["department_attribute"],"memberOf","userAccountControl","title",LDAP_SITE_ATTRIBUTE,"objectGUID","entryUUID","objectClass"]))
            records = []
            for object_type, query in (("user",saved["user_filter"]),("group",saved["group_filter"])):
                for entry in conn.extend.standard.paged_search(saved["base_dn"],query,attributes=attrs,paged_size=500,generator=True):
                    if entry.get("type") != "searchResEntry":
                        continue
                    values = entry.get("attributes", {})
                    object_id = directory_entry_value(values,"objectGUID") or directory_entry_value(values,"entryUUID") or str(entry.get("dn", ""))
                    if not object_id:
                        continue
                    username = directory_entry_value(values,saved["username_attribute"])
                    display = directory_entry_value(values,saved["display_attribute"],username or object_id)
                    uac = directory_entry_value(values,"userAccountControl","0")
                    enabled = object_type == "group" or not (uac.isdigit() and int(uac) & 2)
                    member_groups = values.get("memberOf", [])
                    if not isinstance(member_groups,list): member_groups = [member_groups] if member_groups else []
                    raw_factory = directory_entry_value(values,LDAP_SITE_ATTRIBUTE)
                    factory = FACTORY_MAP.get(raw_factory.casefold(), raw_factory.upper() if raw_factory.upper() in FACTORY_MAP.values() else "")
                    records.append((object_type,object_id,username,display,directory_entry_value(values,saved["email_attribute"]),directory_entry_value(values,saved["department_attribute"]),factory,directory_entry_value(values,"title"),json.dumps([str(v) for v in member_groups]),enabled))
        finally:
            conn.unbind()
        with db() as out:
            for object_type in ("user","group"):
                ids = [r[1] for r in records if r[0] == object_type]
                out.execute("UPDATE directory_objects SET enabled=false,synced_at=now() WHERE server_id=%s AND object_type=%s AND NOT (object_id = ANY(%s))",(server_id,object_type,ids))
            for record in records:
                out.execute("INSERT INTO directory_objects(server_id,object_type,object_id,username,display_name,email,department,factory,title,groups,enabled) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s) ON CONFLICT(server_id,object_type,object_id) DO UPDATE SET username=excluded.username,display_name=excluded.display_name,email=excluded.email,department=excluded.department,factory=excluded.factory,title=excluded.title,groups=excluded.groups,enabled=excluded.enabled,synced_at=now()",(server_id,*record))
            out.execute("UPDATE directory_servers SET last_sync=now(),last_error='' WHERE id=%s",(server_id,))
        return jsonify(ok=True,users=sum(1 for r in records if r[0]=="user"),groups=sum(1 for r in records if r[0]=="group"),message="Directory users and groups synchronized")
    except Exception as exc:
        app.logger.warning("Directory sync failed for %s: %s", server_id, type(exc).__name__)
        with db() as out:
            out.execute("UPDATE directory_servers SET last_error=%s WHERE id=%s",("Directory connection or query failed",server_id))
        return jsonify(error="Sync failed. Check connection and LDAP user/group filters."), 400


@app.delete("/api/admin/directory-servers/<uuid:server_id>/objects/<object_type>/<path:object_id>")
@administrator
def remove_directory_object(server_id, object_type, object_id):
    if object_type not in ("user","group"):
        return jsonify(error="Invalid directory object type"), 400
    with db() as conn:
        conn.execute("DELETE FROM directory_objects WHERE server_id=%s AND object_type=%s AND object_id=%s",(server_id,object_type,object_id))
    return jsonify(ok=True, message="Removed from this inventory cache; the source directory was not changed")


@app.get("/api/data")
@signed_in
def get_data():
    who = session["profile"]
    with db() as conn:
        keys = ("assets", "software", "departments", "maintenance", "manual_users", "settings")
        out = {k: (conn.execute("SELECT value FROM app_state WHERE key=%s", (k,)).fetchone() or ([],))[0] for k in keys}
        if session.get("is_admin"):
            users = conn.execute("SELECT username,display_name,email,department,factory,title,enabled FROM directory_users ORDER BY display_name").fetchall()
            out["users"] = [{"username":r[0],"name":r[1],"email":r[2],"dept":r[3],"site":r[4],"title":r[5],"enabled":r[6],"source":"directory"} for r in users]
            out["users"].extend({k:v for k,v in u.items() if k != "password_hash"} | {"source":"manual"} for u in out.pop("manual_users", []))
            synced = conn.execute("SELECT o.username,o.display_name,o.email,o.department,o.factory,o.title,o.enabled,s.name FROM directory_objects o JOIN directory_servers s ON s.id=o.server_id WHERE o.object_type='user' ORDER BY o.display_name LIMIT 10000").fetchall()
            out["users"].extend({"username":r[0],"name":r[1],"email":r[2],"dept":r[3],"site":r[4],"title":r[5],"enabled":r[6],"active":"Active" if r[6] else "Disabled","role":"Employee","id":r[0],"directory":r[7],"source":"directory"} for r in synced if r[0])
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
                if key == "manual_users":
                    current = (conn.execute("SELECT value FROM app_state WHERE key='manual_users'").fetchone() or ([],))[0]
                    existing = {str(u.get("username", "")).casefold(): u for u in current}
                    clean = []
                    for item in value:
                        user = dict(item)
                        username = str(user.get("username", "")).strip()
                        if not username:
                            continue
                        prior = existing.get(username.casefold(), {})
                        new_password = user.pop("password", "")
                        user.pop("password_confirm", None)
                        if new_password:
                            user["password_hash"] = generate_password_hash(new_password)
                        elif prior.get("password_hash"):
                            user["password_hash"] = prior["password_hash"]
                        if "password_hash" not in user:
                            user["password_hash"] = ""
                        user["username"] = username
                        user["role"] = "Administrator" if user.get("role") == "Administrator" else "User"
                        user["enabled"] = user.get("enabled", True)
                        clean.append(user)
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
        if session.get("is_admin"):
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
    if not session.get("is_admin") and row[0] != session["profile"]["username"]:
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
@administrator
def update_ticket(ticket_id):
    body = request.get_json(force=True)
    allowed = {"assigned":"assigned_to", "status":"status", "eta":"eta", "note":"note"}
    fields = [(allowed[k], v) for k,v in body.items() if k in allowed]
    if not fields:
        return jsonify(error="No supported fields to update"), 400
    if "status" in body and body["status"] not in ("Open", "In progress", "Resolved", "Closed"):
        return jsonify(error="Invalid status"), 400
    assignments = ", ".join(f"{column}=%s" for column,_ in fields)
    with db() as conn:
        cur = conn.execute(f"UPDATE tickets SET {assignments}, updated_at=now() WHERE id=%s RETURNING id", [v for _,v in fields]+[ticket_id])
        if not cur.fetchone():
            abort(404)
        detail = "; ".join(f"{k}: {v}" for k,v in body.items() if k in allowed)[:1000]
        conn.execute("INSERT INTO ticket_events(ticket_id,actor,event_type,detail) VALUES(%s,%s,'updated',%s)", (ticket_id,session["profile"]["username"],detail))
    return jsonify(ok=True)


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
