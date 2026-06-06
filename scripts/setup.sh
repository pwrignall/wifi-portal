#!/usr/bin/env bash
# setup.sh — install and configure the WiFi captive portal on a Raspberry Pi 3.
#
# Run as root:  sudo bash setup.sh
#
# What this script does:
#   1. Installs system packages (hostapd, dnsmasq, iptables, python3, pip)
#   2. Asks for your SSID name, subnets, and admin password
#   3. Configures hostapd, dnsmasq, and a static IP for wlan0
#   4. Installs the Python app to /opt/wifi-portal
#   5. Creates /etc/wifi-portal/settings.ini with the admin password hash
#   6. Installs and enables systemd services
#   7. Starts the portal

set -euo pipefail

APP_SRC="$(cd "$(dirname "$0")/.." && pwd)"
APP_DEST="/opt/wifi-portal"
SETTINGS_DIR="/etc/wifi-portal"
DATA_DIR="/var/lib/wifi-portal"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
info()  { echo -e "\n\033[1;34m[INFO]\033[0m  $*"; }
ok()    { echo -e "\033[1;32m[OK]\033[0m    $*"; }
warn()  { echo -e "\033[1;33m[WARN]\033[0m  $*"; }
die()   { echo -e "\033[1;31m[ERROR]\033[0m $*" >&2; exit 1; }

ask() {
    local prompt="$1" default="${2:-}"
    if [[ -n "$default" ]]; then
        read -rp "$prompt [$default]: " val
        echo "${val:-$default}"
    else
        read -rp "$prompt: " val
        echo "$val"
    fi
}

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------
[[ $EUID -eq 0 ]] || die "This script must be run as root. Try: sudo bash setup.sh"

info "WiFi Captive Portal — Setup"
echo "This will configure your Raspberry Pi 3 as a guest WiFi access point."
echo "Your Pi should be connected to your home router via Ethernet (eth0)."
echo ""

# ---------------------------------------------------------------------------
# Gather configuration
# ---------------------------------------------------------------------------
SSID=$(ask            "Guest SSID name (what guests will see)"    "HomeGuest")
COUNTRY=$(ask         "WiFi regulatory country code (2 letters)"  "GB")
CHANNEL=$(ask         "WiFi channel (1/6/11 recommended for 2.4GHz)" "6")
GUEST_SUBNET=$(ask    "Guest network subnet"                       "192.168.100.0/24")
GUEST_GW=$(ask        "Pi's IP on the guest network (gateway)"    "192.168.100.1")
DHCP_START=$(ask      "DHCP pool start"                           "192.168.100.100")
DHCP_END=$(ask        "DHCP pool end"                             "192.168.100.200")
HOME_SUBNET=$(ask     "Your home LAN subnet (blocked from guests)" "192.168.1.0/24")
WLAN_IF=$(ask         "Guest WiFi interface"                      "wlan0")
ETH_IF=$(ask          "Ethernet interface (internet source)"       "eth0")

echo ""
echo "Choose an admin password for the management dashboard."
echo "This is separate from the rotating guest password."
while true; do
    read -rsp "Admin password: " ADMIN_PW; echo
    read -rsp "Confirm admin password: " ADMIN_PW2; echo
    [[ "$ADMIN_PW" == "$ADMIN_PW2" ]] && break
    echo "Passwords do not match, try again."
done

echo ""
info "Summary"
echo "  SSID:         $SSID"
echo "  Country:      $COUNTRY / Channel: $CHANNEL"
echo "  Guest subnet: $GUEST_SUBNET (gateway: $GUEST_GW)"
echo "  Home subnet:  $HOME_SUBNET (blocked from guests)"
echo "  Interfaces:   $WLAN_IF (WiFi AP) / $ETH_IF (internet)"
read -rp "Continue? [y/N]: " confirm
[[ "${confirm,,}" == "y" ]] || { echo "Aborted."; exit 0; }

# ---------------------------------------------------------------------------
# 1. Install system packages
# ---------------------------------------------------------------------------
info "Installing system packages..."
apt-get update -qq
apt-get install -y --no-install-recommends \
    hostapd dnsmasq iptables python3 sqlite3
ok "System packages installed."

# Install uv (fast Python package manager)
info "Installing uv..."
if ! command -v uv &>/dev/null; then
    # Install into /usr/local/bin so it is on PATH immediately and system-wide
    # (avoids the ~/.local/bin PATH problem when running as root via sudo).
    curl -LsSf https://astral.sh/uv/install.sh | UV_INSTALL_DIR=/usr/local/bin sh
fi
ok "uv installed: $(uv --version)"

# ---------------------------------------------------------------------------
# 2. Stop conflicting services during setup
# ---------------------------------------------------------------------------
info "Stopping services for configuration..."
systemctl stop hostapd dnsmasq wpa_supplicant 2>/dev/null || true
systemctl unmask hostapd 2>/dev/null || true

# ---------------------------------------------------------------------------
# 3. Tell the network manager to leave wlan0 alone
#    (hostapd and iptables.sh handle the interface directly)
# ---------------------------------------------------------------------------
info "Configuring $WLAN_IF static IP..."

if systemctl is-active --quiet NetworkManager 2>/dev/null; then
    # Raspberry Pi OS Bookworm (and most modern systems): use NetworkManager.
    # Mark wlan0 as unmanaged so NM doesn't reassign or reset the address.
    mkdir -p /etc/NetworkManager/conf.d
    cat > /etc/NetworkManager/conf.d/wifi-portal.conf <<EOF
[keyfile]
unmanaged-devices=interface-name:$WLAN_IF
EOF
    systemctl reload NetworkManager
    # Immediately release the interface — reload is async and NM may still
    # hold wlan0 by the time hostapd tries to claim it.
    nmcli device set "$WLAN_IF" managed no 2>/dev/null || true
    ok "NetworkManager told to ignore $WLAN_IF."

elif [ -f /etc/dhcpcd.conf ]; then
    # Raspberry Pi OS Bullseye and earlier: configure via dhcpcd.
    if grep -q "# wifi-portal: begin" /etc/dhcpcd.conf 2>/dev/null; then
        sed -i '/# wifi-portal: begin/,/# wifi-portal: end/d' /etc/dhcpcd.conf
    fi
    cat >> /etc/dhcpcd.conf <<EOF

# wifi-portal: begin
interface $WLAN_IF
    static ip_address=${GUEST_GW}/24
    nohook wpa_supplicant
# wifi-portal: end
EOF
    ok "dhcpcd configured with static IP $GUEST_GW/24 on $WLAN_IF."

else
    warn "Neither NetworkManager nor dhcpcd detected — the static IP for $WLAN_IF"
    warn "will be set at runtime by iptables.sh on each service start."
fi

# Apply the address immediately for the rest of this script.
ip addr flush dev "$WLAN_IF" 2>/dev/null || true
ip addr add "${GUEST_GW}/24" dev "$WLAN_IF" 2>/dev/null || true
ip link set "$WLAN_IF" up

# ---------------------------------------------------------------------------
# 4. Configure hostapd
# ---------------------------------------------------------------------------
info "Configuring hostapd..."
mkdir -p /etc/hostapd

cat > /etc/hostapd/hostapd.conf <<EOF
interface=$WLAN_IF
driver=nl80211
ssid=$SSID
hw_mode=g
ieee80211n=1
channel=$CHANNEL
auth_algs=1
wpa=0
country_code=$COUNTRY
beacon_int=100
dtim_period=2
EOF

# Use a systemd drop-in to pin the config path explicitly.
# This avoids /etc/default/hostapd entirely — on Bookworm that file ships
# with DAEMON_CONF="" already uncommented, so any sed/append approach
# produces duplicate entries and the wrong value may win.
mkdir -p /etc/systemd/system/hostapd.service.d
cat > /etc/systemd/system/hostapd.service.d/wifi-portal.conf <<EOF
[Service]
Type=simple
ExecStart=
ExecStart=/usr/sbin/hostapd /etc/hostapd/hostapd.conf
EOF
systemctl daemon-reload

# Confirm what was actually written
grep "^ssid=" /etc/hostapd/hostapd.conf
ok "hostapd configured (SSID: $SSID)."

# ---------------------------------------------------------------------------
# 5. Configure dnsmasq
# ---------------------------------------------------------------------------
info "Configuring dnsmasq..."
cp /etc/dnsmasq.conf /etc/dnsmasq.conf.backup 2>/dev/null || true

cat > /etc/dnsmasq.conf <<EOF
interface=$WLAN_IF
bind-interfaces
dhcp-range=${DHCP_START},${DHCP_END},255.255.255.0,24h
dhcp-option=3,${GUEST_GW}
dhcp-option=6,${GUEST_GW}
server=8.8.8.8
server=1.1.1.1
no-hosts
no-resolv
log-dhcp
EOF
ok "dnsmasq configured."

# ---------------------------------------------------------------------------
# 6. Enable IP forwarding persistently
# ---------------------------------------------------------------------------
info "Enabling IP forwarding..."
if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi
sysctl -w net.ipv4.ip_forward=1
ok "IP forwarding enabled."

# ---------------------------------------------------------------------------
# 7. Install app
# ---------------------------------------------------------------------------
info "Installing app to $APP_DEST..."
mkdir -p "$APP_DEST"
cp -r "$APP_SRC"/app.py "$APP_SRC"/firewall.py "$APP_SRC"/templates \
       "$APP_SRC"/requirements.txt "$APP_SRC"/pyproject.toml "$APP_DEST"/
[ -f "$APP_SRC/words.csv" ] && cp "$APP_SRC/words.csv" "$APP_DEST/words.csv"
cp -r "$APP_SRC"/scripts "$APP_DEST"/scripts
chmod +x "$APP_DEST"/scripts/*.sh

# Sync dependencies into a uv-managed virtual environment
cd "$APP_DEST"
uv sync 2>/dev/null || uv pip install --system flask "qrcode[pil]"
ok "Python app installed (via uv)."

# ---------------------------------------------------------------------------
# 8. Create settings.ini
# ---------------------------------------------------------------------------
info "Generating settings..."
mkdir -p "$SETTINGS_DIR" "$DATA_DIR"

SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
# Use the uv venv (werkzeug is there); pass password via env var to handle special characters safely.
ADMIN_HASH=$(cd "$APP_DEST" && _PW="$ADMIN_PW" uv run python3 -c "
import os
from werkzeug.security import generate_password_hash
print(generate_password_hash(os.environ['_PW']))
")
# App is already installed — reuse its generate_guest_password() so the
# initial password respects words.csv and matches the rotation format.
INITIAL_PW=$(cd "$APP_DEST" && uv run python3 -c \
    "from app import generate_guest_password; print(generate_guest_password())")

cat > "$SETTINGS_DIR/settings.ini" <<EOF
[app]
secret_key = $SECRET_KEY
admin_password_hash = $ADMIN_HASH
port = 80

[network]
interface = $WLAN_IF
ssid = $SSID
home_subnet = $HOME_SUBNET
guest_subnet = $GUEST_SUBNET
guest_gateway = $GUEST_GW
eth_interface = $ETH_IF

[portal]
guest_password = $INITIAL_PW
password_rotated = $(date -u +"%Y-%m-%dT%H:%M:%S")
session_hours = 24
EOF

chmod 640 "$SETTINGS_DIR/settings.ini"
ok "Settings written to $SETTINGS_DIR/settings.ini"
echo "  Initial guest password: $INITIAL_PW"

# ---------------------------------------------------------------------------
# 9. iptables environment file (read by systemd service)
# ---------------------------------------------------------------------------
cat > /etc/wifi-portal/iptables.env <<EOF
WLAN_IF=$WLAN_IF
ETH_IF=$ETH_IF
GUEST_SUBNET=$GUEST_SUBNET
GUEST_GW=$GUEST_GW
HOME_SUBNET=$HOME_SUBNET
PORTAL_PORT=80
EOF

# ---------------------------------------------------------------------------
# 10. Install systemd services
# ---------------------------------------------------------------------------
info "Installing systemd services..."
cp "$APP_SRC"/systemd/*.service "$APP_SRC"/systemd/*.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable wifi-portal.service
systemctl enable rotate-password.timer
ok "Systemd services installed."

# ---------------------------------------------------------------------------
# 11. Start everything
# ---------------------------------------------------------------------------
info "Starting services..."
# Unblock the WiFi radio in case a soft rfkill was left after teardown.
rfkill unblock wifi 2>/dev/null || true
systemctl start hostapd
systemctl start dnsmasq
systemctl start wifi-portal

systemctl start rotate-password.timer

ok "All services started."

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo "============================================================"
echo " Setup complete!"
echo "============================================================"
echo ""
echo "  Guest SSID:      $SSID  (open — no WiFi password)"
echo "  Guest password:  $INITIAL_PW"
echo "  Admin panel:     http://${GUEST_GW}/admin"
echo "                   (also accessible on your home LAN)"
echo ""
echo "  Guests connect to '$SSID', open a browser, and enter"
echo "  the password above. The password rotates on the 1st of"
echo "  each month — check the admin panel to see the new one."
echo ""
echo "  To add a smart device (IoT bypass), visit the admin"
echo "  panel and register its MAC address."
echo "============================================================"
