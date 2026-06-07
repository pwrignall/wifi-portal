#!/usr/bin/env bash
# update.sh — sync the git repo to the installed app without a full reinstall.
#
# Copies app code and scripts, syncs Python deps, reloads systemd units if
# they changed, then restarts the portal service.
#
# Does NOT touch /etc/wifi-portal/ (settings, iptables.env) or
# /var/lib/wifi-portal/ (database).
#
# Run as root from the git repo:  sudo bash scripts/update.sh

set -euo pipefail

APP_SRC="$(cd "$(dirname "$0")/.." && pwd)"
APP_DEST="/opt/wifi-portal"

info() { echo -e "\n\033[1;34m[INFO]\033[0m  $*"; }
ok()   { echo -e "\033[1;32m[OK]\033[0m    $*"; }
die()  { echo -e "\033[1;31m[ERROR]\033[0m $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root: sudo bash scripts/update.sh"
[[ -d "$APP_DEST" ]] || die "$APP_DEST does not exist — run setup.sh first."

# ---------------------------------------------------------------------------
# 1. Pull latest changes
# ---------------------------------------------------------------------------
info "Pulling latest changes..."
git -C "$APP_SRC" pull
ok "Git up to date."

# ---------------------------------------------------------------------------
# 2. Sync app files
# ---------------------------------------------------------------------------
info "Syncing app files to $APP_DEST..."
cp -r "$APP_SRC"/app.py "$APP_SRC"/firewall.py "$APP_SRC"/templates \
      "$APP_SRC"/requirements.txt "$APP_SRC"/pyproject.toml "$APP_DEST"/
[[ -f "$APP_SRC/words.csv" ]] && cp "$APP_SRC/words.csv" "$APP_DEST/words.csv"
cp -r "$APP_SRC"/scripts "$APP_DEST"/scripts
chmod +x "$APP_DEST"/scripts/*.sh
ok "App files synced."

# ---------------------------------------------------------------------------
# 3. Sync Python dependencies (no-op if lockfile unchanged)
# ---------------------------------------------------------------------------
info "Syncing Python dependencies..."
cd "$APP_DEST"
uv sync 2>/dev/null || uv pip install --system flask "qrcode[pil]"
ok "Dependencies up to date."

# ---------------------------------------------------------------------------
# 4. Reload systemd units if they changed
# ---------------------------------------------------------------------------
info "Checking systemd units..."
units_changed=0
for f in "$APP_SRC"/systemd/*.service "$APP_SRC"/systemd/*.timer; do
    dest="/etc/systemd/system/$(basename "$f")"
    if [[ ! -f "$dest" ]] || ! diff -q "$f" "$dest" &>/dev/null; then
        cp "$f" "$dest"
        echo "  Updated $(basename "$f")"
        units_changed=1
    fi
done
if [[ $units_changed -eq 1 ]]; then
    systemctl daemon-reload
    ok "Systemd units reloaded."
else
    ok "Systemd units unchanged."
fi

# ---------------------------------------------------------------------------
# 5. Restart the portal service
# ---------------------------------------------------------------------------
info "Restarting wifi-portal..."
systemctl restart wifi-portal
ok "wifi-portal restarted."

echo ""
echo "============================================================"
echo " Update complete."
echo " Check rules: sudo iptables -L GUEST_FORWARD -n -v"
echo "============================================================"
