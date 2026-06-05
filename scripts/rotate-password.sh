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

# Use the same wordlist and logic as app.py so passwords look identical.
NEW_PW=$(python3 - <<'PYEOF'
import random, sys
WORDS = [
    "AMBER","BEACH","BRAVE","CEDAR","CHESS","CLOUD","CORAL","CRANE",
    "DELTA","EAGLE","EMBER","FLAME","FROST","GLOBE","GRACE","GROVE",
    "HAVEN","HONEY","IVORY","JADE","JEWEL","KARMA","LASER","LEMON",
    "LIGHT","LOTUS","MAPLE","METRO","MIST","NOBLE","NORTH","OCEAN",
    "OLIVE","OPERA","ORBIT","PETAL","PIANO","PIXEL","PLAZA","PRISM",
    "QUEST","QUINN","RADAR","RAPID","RAVEN","RIDGE","RIVER","ROBIN",
    "ROWAN","RUBY","RUSTY","SOLAR","SOLID","SONIC","SPARK","STORM",
    "SUNNY","SWIFT","TIGER","TITAN","TOKEN","TOWER","ULTRA","UNITY",
    "URBAN","VENUS","VIBES","VIOLA","VISTA","VIVID","WATER","WAVES",
    "WINDY","WITCH","YACHT","ZEBRA",
]
w1, w2 = random.sample(WORDS, 2)
print(f"{w1}-{w2}-{random.randint(10, 99)}")
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
