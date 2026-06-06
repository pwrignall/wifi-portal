#!/usr/bin/env bash
# rotate-password.sh — generate a new guest password and expire all guest sessions.
#
# Called monthly by the rotate-password.timer systemd unit.
# Can also be run manually: sudo /opt/wifi-portal/scripts/rotate-password.sh

set -euo pipefail

SETTINGS="${WIFI_PORTAL_SETTINGS:-/etc/wifi-portal/settings.ini}"
DB="${WIFI_PORTAL_DB:-/var/lib/wifi-portal/portal.db}"
APP_DIR="${APP_DIR:-/opt/wifi-portal}"

echo "[rotate] Starting monthly password rotation..."

# Mirror the logic in app.py: use words.csv if present, else fall back to
# the built-in list. Same format rules apply.
NEW_PW=$(python3 - "$APP_DIR" <<'PYEOF'
import random, sys
from pathlib import Path

app_dir = Path(sys.argv[1])
words_csv = app_dir / "words.csv"

FALLBACK = [
    "amber","beach","brave","cedar","chess","cloud","coral","crane",
    "delta","eagle","ember","flame","frost","globe","grace","grove",
    "haven","honey","ivory","jade","jewel","karma","laser","lemon",
    "light","lotus","maple","metro","mist","noble","north","ocean",
    "olive","opera","orbit","petal","piano","pixel","plaza","prism",
    "quest","quinn","radar","rapid","raven","ridge","river","robin",
    "rowan","ruby","rusty","solar","solid","sonic","spark","storm",
    "sunny","swift","tiger","titan","token","tower","ultra","unity",
    "urban","venus","vibes","viola","vista","vivid","water","waves",
    "windy","witch","yacht","zebra",
]

if words_csv.exists():
    words = [
        line.strip().strip('"').strip("'").lower()
        for line in words_csv.read_text().splitlines()
        if line.strip().strip('"').strip("'").isalpha()
    ]
    if len(words) >= 3:
        w1, w2, w3 = random.sample(words, 3)
        print(f"{w1} {w2} {w3} {random.randint(10, 99)}")
        sys.exit(0)

w1, w2 = random.sample(FALLBACK, 2)
print(f"{w1} {w2} {random.randint(10, 99)}")
PYEOF
)

echo "[rotate] New password: $NEW_PW"

# Write the new password into settings.ini
python3 - "$SETTINGS" "$NEW_PW" <<'PYEOF'
import configparser, sys
from datetime import datetime, timezone

settings_path, new_pw = sys.argv[1], sys.argv[2]
cfg = configparser.ConfigParser()
cfg.read(settings_path)

if not cfg.has_section("portal"):
    cfg.add_section("portal")

cfg.set("portal", "guest_password", new_pw)
cfg.set("portal", "password_rotated", datetime.now(timezone.utc).isoformat())

with open(settings_path, "w") as f:
    cfg.write(f)

print(f"[rotate] Settings updated: {settings_path}")
PYEOF

# Collect guest MACs before deleting so we can remove their iptables rules
GUEST_MACS=$(sqlite3 "$DB" "SELECT mac FROM sessions WHERE is_iot = 0;" 2>/dev/null || true)

# Expire all guest sessions (IoT devices are unaffected)
sqlite3 "$DB" "DELETE FROM sessions WHERE is_iot = 0;" 2>/dev/null || true
echo "[rotate] Guest sessions cleared."

# Remove iptables rules for each evicted guest MAC
for mac in $GUEST_MACS; do
    iptables -D GUEST_FORWARD -m mac --mac-source "$mac" -j ACCEPT 2>/dev/null || true
    iptables -t nat -D GUEST_PORTAL -m mac --mac-source "$mac" -j RETURN 2>/dev/null || true
    echo "[rotate] Removed firewall rule for $mac"
done

echo "[rotate] Done. New guest password: $NEW_PW"
