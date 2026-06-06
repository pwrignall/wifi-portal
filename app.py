"""
WiFi Captive Portal — main Flask application.

Guests connect to the open SSID, get redirected here, and enter
the monthly rotating password to gain internet access.

IoT/smart devices are pre-registered by MAC address in the admin
dashboard and bypass the portal entirely.
"""

import io
import os
import re
import secrets
import random
import sqlite3
import subprocess
from configparser import ConfigParser
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

from flask import (
    Flask, g, redirect, render_template, request,
    Response, session, url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

try:
    import qrcode
    QR_AVAILABLE = True
except ImportError:
    QR_AVAILABLE = False

# ---------------------------------------------------------------------------
# Paths — overridable via environment variables for development
# ---------------------------------------------------------------------------

SETTINGS_FILE = Path(os.environ.get("WIFI_PORTAL_SETTINGS", "/etc/wifi-portal/settings.ini"))
DB_FILE = Path(os.environ.get("WIFI_PORTAL_DB", "/var/lib/wifi-portal/portal.db"))

# ---------------------------------------------------------------------------
# Settings helpers
# ---------------------------------------------------------------------------

def load_settings() -> ConfigParser:
    cfg = ConfigParser()
    cfg.read(SETTINGS_FILE)
    return cfg


def save_settings(cfg: ConfigParser) -> None:
    SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(SETTINGS_FILE, "w") as f:
        cfg.write(f)


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

_settings = load_settings()

app = Flask(__name__)
app.secret_key = _settings.get("app", "secret_key", fallback=secrets.token_hex(32))

# Read once at startup; stable config that doesn't change without a restart.
WLAN_IF = _settings.get("network", "interface", fallback="wlan0")
HOME_SUBNET = _settings.get("network", "home_subnet", fallback="192.168.1.0/24")
SSID = _settings.get("network", "ssid", fallback="HomeGuest")
SESSION_HOURS = _settings.getint("portal", "session_hours", fallback=24)
PORTAL_PORT = _settings.getint("app", "port", fallback=80)

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    mac       TEXT PRIMARY KEY,
    ip        TEXT,
    label     TEXT,
    is_iot    INTEGER NOT NULL DEFAULT 0,
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS failed_logins (
    ip           TEXT NOT NULL,
    attempted_at TEXT NOT NULL
);
"""

def get_db() -> sqlite3.Connection:
    if "db" not in g:
        DB_FILE.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(DB_FILE), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_FILE))
    conn.executescript(_SCHEMA)
    conn.commit()
    conn.close()

# ---------------------------------------------------------------------------
# Password management
# ---------------------------------------------------------------------------

_WORDS_FALLBACK = [
    "amber", "beach", "brave", "cedar", "chess", "cloud", "coral", "crane",
    "delta", "eagle", "ember", "flame", "frost", "globe", "grace", "grove",
    "haven", "honey", "ivory", "jade",  "jewel", "karma", "laser", "lemon",
    "light", "lotus", "maple", "metro", "mist",  "noble", "north", "ocean",
    "olive", "opera", "orbit", "petal", "piano", "pixel", "plaza", "prism",
    "quest", "quinn", "radar", "rapid", "raven", "ridge", "river", "robin",
    "rowan", "ruby",  "rusty", "solar", "solid", "sonic", "spark", "storm",
    "sunny", "swift", "tiger", "titan", "token", "tower", "ultra", "unity",
    "urban", "venus", "vibes", "viola", "vista", "vivid", "water", "waves",
    "windy", "witch", "yacht", "zebra",
]

_WORDS_CSV = Path(__file__).parent / "words.csv"


def _load_words() -> tuple:
    """Return (word_list, from_csv). Reads words.csv if present."""
    if _WORDS_CSV.exists():
        words = []
        with open(_WORDS_CSV) as f:
            for line in f:
                word = line.strip().strip('"').strip("'").lower()
                if word and word.isalpha():
                    words.append(word)
        if len(words) >= 3:
            return words, True
    return _WORDS_FALLBACK, False


def generate_guest_password() -> str:
    words, from_csv = _load_words()
    n = random.randint(10, 99)
    if from_csv:
        w1, w2, w3 = random.sample(words, 3)
        return f"{w1} {w2} {w3} {n}"
    w1, w2 = random.sample(words, 2)
    return f"{w1} {w2} {n}"


def get_current_password() -> str:
    """Re-read from disk so rotation takes effect without an app restart."""
    return load_settings().get("portal", "guest_password", fallback="")


def rotate_password() -> str:
    """Generate a new password, persist it, and expire all guest sessions."""
    new_pw = generate_guest_password()
    cfg = load_settings()
    if not cfg.has_section("portal"):
        cfg.add_section("portal")
    cfg.set("portal", "guest_password", new_pw)
    cfg.set("portal", "password_rotated", datetime.utcnow().isoformat())
    save_settings(cfg)

    # Expire guest sessions and remove their firewall rules.
    conn = sqlite3.connect(str(DB_FILE))
    rows = conn.execute("SELECT mac FROM sessions WHERE is_iot = 0").fetchall()
    conn.execute("DELETE FROM sessions WHERE is_iot = 0")
    conn.commit()
    conn.close()

    from firewall import remove_mac
    for row in rows:
        remove_mac(row[0])

    return new_pw

# ---------------------------------------------------------------------------
# Firewall helpers (thin wrappers imported from firewall.py)
# ---------------------------------------------------------------------------

from firewall import allow_mac, remove_mac, get_client_mac


def restore_firewall_rules() -> None:
    """Re-add iptables rules for all unexpired sessions after a restart."""
    try:
        conn = sqlite3.connect(str(DB_FILE))
        now = datetime.utcnow().isoformat()
        rows = conn.execute(
            "SELECT mac FROM sessions WHERE expires_at > ?", (now,)
        ).fetchall()
        conn.close()
        for row in rows:
            allow_mac(row[0])
        app.logger.info("Restored %d firewall rule(s) from database.", len(rows))
    except Exception as exc:
        app.logger.error("Failed to restore firewall rules: %s", exc)

# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

_MAX_ATTEMPTS = 5
_LOCKOUT_MINUTES = 15


def is_rate_limited(ip: str) -> bool:
    db = get_db()
    cutoff = (datetime.utcnow() - timedelta(minutes=_LOCKOUT_MINUTES)).isoformat()
    count = db.execute(
        "SELECT COUNT(*) FROM failed_logins WHERE ip = ? AND attempted_at > ?",
        (ip, cutoff),
    ).fetchone()[0]
    return count >= _MAX_ATTEMPTS


def record_failed_login(ip: str) -> None:
    db = get_db()
    db.execute(
        "INSERT INTO failed_logins (ip, attempted_at) VALUES (?, ?)",
        (ip, datetime.utcnow().isoformat()),
    )
    db.commit()


def clear_failed_logins(ip: str) -> None:
    db = get_db()
    db.execute("DELETE FROM failed_logins WHERE ip = ?", (ip,))
    db.commit()

# ---------------------------------------------------------------------------
# Session helpers
# ---------------------------------------------------------------------------

def is_authenticated(mac: str) -> bool:
    if not mac:
        return False
    db = get_db()
    now = datetime.utcnow().isoformat()
    row = db.execute(
        "SELECT mac FROM sessions WHERE mac = ? AND expires_at > ?",
        (mac.upper(), now),
    ).fetchone()
    return row is not None


def authenticate_client(mac: str, ip: str, is_iot: bool = False, label: str = "") -> None:
    mac = mac.upper()
    if is_iot:
        expires = (datetime.utcnow() + timedelta(days=3650)).isoformat()  # 10 years
    else:
        expires = (datetime.utcnow() + timedelta(hours=SESSION_HOURS)).isoformat()

    db = get_db()
    db.execute(
        """
        INSERT INTO sessions (mac, ip, label, is_iot, expires_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(mac) DO UPDATE SET
            ip         = excluded.ip,
            label      = excluded.label,
            is_iot     = excluded.is_iot,
            expires_at = excluded.expires_at
        """,
        (mac, ip, label, int(is_iot), expires),
    )
    db.commit()
    allow_mac(mac)


def revoke_client(mac: str) -> None:
    mac = mac.upper()
    db = get_db()
    db.execute("DELETE FROM sessions WHERE mac = ?", (mac,))
    db.commit()
    remove_mac(mac)

# ---------------------------------------------------------------------------
# Admin authentication
# ---------------------------------------------------------------------------

_ADMIN_SESSION_KEY = "admin_ok"

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get(_ADMIN_SESSION_KEY):
            return redirect(url_for("admin_login", next=request.path))
        return f(*args, **kwargs)
    return decorated

# ---------------------------------------------------------------------------
# Routes — captive portal
# ---------------------------------------------------------------------------

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def portal(path):
    """Catch-all: serve the captive portal to unauthenticated clients.

    iptables redirects all HTTP traffic from guest devices here.
    Specific routes (/login, /success, /admin/…) take priority.
    """
    client_ip = request.remote_addr
    mac = get_client_mac(client_ip)
    if mac and is_authenticated(mac):
        return redirect(url_for("success"))

    # Capture the URL the device was actually trying to reach.
    # iptables rewrites the destination to us; the Host header keeps the
    # original hostname.  After login we redirect there so the OS captive-
    # portal detector (e.g. Android's generate_204 check) sees the real
    # server response and dismisses the captive-portal webview cleanly.
    host = request.headers.get("Host", "")
    original_url = ""
    if host and host != request.host:
        original_url = f"http://{host}/{path}"
        if request.query_string:
            original_url += f"?{request.query_string.decode()}"

    return render_template("portal.html", ssid=SSID, original_url=original_url)


@app.route("/login", methods=["POST"])
def login():
    client_ip = request.remote_addr

    if is_rate_limited(client_ip):
        return render_template(
            "portal.html",
            ssid=SSID,
            error="Too many failed attempts — please wait 15 minutes.",
        ), 429

    entered = request.form.get("password", "").strip().upper()
    current = get_current_password().strip().upper()

    if not current or entered != current:
        record_failed_login(client_ip)
        return render_template(
            "portal.html",
            ssid=SSID,
            error="Incorrect password. Check with your host and try again.",
        ), 401

    clear_failed_logins(client_ip)
    mac = get_client_mac(client_ip)
    if not mac:
        # The ARP entry may not exist yet if the client connected moments ago.
        # A single ping from the Pi forces the kernel to resolve the MAC.
        subprocess.run(
            ["ping", "-c", "1", "-W", "1", "-I", WLAN_IF, client_ip],
            capture_output=True, timeout=3,
        )
        mac = get_client_mac(client_ip)

    if not mac:
        app.logger.error("Could not resolve MAC for %s — cannot open firewall", client_ip)
        return render_template(
            "portal.html",
            ssid=SSID,
            error="Could not identify your device. Please disconnect, reconnect to the WiFi, and try again.",
        ), 500

    authenticate_client(mac, client_ip)

    # Redirect to the original URL if it was an external host (not our portal).
    # This lets the OS captive-portal detector receive the real server response
    # (e.g. Google's 204) and close the webview without any flash.
    next_url = request.form.get("next_url", "").strip()
    if (next_url
            and next_url.startswith("http://")
            and not next_url.startswith(f"http://{request.host}")):
        return redirect(next_url)
    return redirect(url_for("success"))


@app.route("/success")
def success():
    return render_template("success.html", ssid=SSID)

# ---------------------------------------------------------------------------
# Routes — admin
# ---------------------------------------------------------------------------

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        password = request.form.get("password", "")
        cfg = load_settings()
        stored_hash = cfg.get("app", "admin_password_hash", fallback="")
        if stored_hash and check_password_hash(stored_hash, password):
            session[_ADMIN_SESSION_KEY] = True
            session.permanent = True
            app.permanent_session_lifetime = timedelta(hours=8)
            next_url = request.args.get("next") or url_for("admin")
            return redirect(next_url)
        return render_template("admin_login.html", error="Incorrect password."), 401
    return render_template("admin_login.html")


@app.route("/admin/logout")
def admin_logout():
    session.pop(_ADMIN_SESSION_KEY, None)
    return redirect(url_for("admin_login"))


@app.route("/admin")
@admin_required
def admin():
    cfg = load_settings()
    password = cfg.get("portal", "guest_password", fallback="(not set — run setup.sh)")
    rotated_raw = cfg.get("portal", "password_rotated", fallback=None)
    if rotated_raw:
        try:
            rotated = datetime.fromisoformat(rotated_raw).strftime("%d %b %Y %H:%M UTC")
        except ValueError:
            rotated = rotated_raw
    else:
        rotated = "Never"

    db = get_db()
    now = datetime.utcnow().isoformat()
    rows = db.execute(
        "SELECT mac, ip, label, is_iot, expires_at FROM sessions WHERE expires_at > ? ORDER BY is_iot DESC, label",
        (now,),
    ).fetchall()

    sessions = []
    for row in rows:
        try:
            exp = datetime.fromisoformat(row["expires_at"]).strftime("%d %b %Y")
        except ValueError:
            exp = row["expires_at"]
        sessions.append({
            "mac": row["mac"],
            "ip": row["ip"] or "—",
            "label": row["label"] or "—",
            "is_iot": bool(row["is_iot"]),
            "expires": exp,
        })

    return render_template(
        "admin.html",
        password=password,
        rotated=rotated,
        sessions=sessions,
        qr_available=QR_AVAILABLE,
        ssid=SSID,
    )


@app.route("/admin/qr.png")
@admin_required
def admin_qr():
    if not QR_AVAILABLE:
        return "Install qrcode[pil] for QR support.", 501
    password = get_current_password()
    img = qrcode.make(password)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return Response(buf, mimetype="image/png")


@app.route("/admin/rotate", methods=["POST"])
@admin_required
def admin_rotate():
    rotate_password()
    return redirect(url_for("admin"))


@app.route("/admin/devices", methods=["POST"])
@admin_required
def admin_devices():
    action = request.form.get("action", "")
    mac = request.form.get("mac", "").strip()
    label = request.form.get("label", "").strip()
    client_ip = request.form.get("ip", "").strip() or ""

    if not _MAC_RE.match(mac):
        return redirect(url_for("admin"))

    mac = mac.upper()
    if action == "add":
        authenticate_client(mac, client_ip, is_iot=True, label=label)
    elif action == "remove":
        revoke_client(mac)

    return redirect(url_for("admin"))


@app.route("/admin/revoke", methods=["POST"])
@admin_required
def admin_revoke():
    mac = request.form.get("mac", "").strip()
    if _MAC_RE.match(mac):
        revoke_client(mac.upper())
    return redirect(url_for("admin"))

# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

def create_app():
    init_db()
    with app.app_context():
        restore_firewall_rules()
    return app


if __name__ == "__main__":
    create_app()
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=PORTAL_PORT, debug=debug)
