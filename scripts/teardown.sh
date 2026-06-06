#!/usr/bin/env bash
# teardown.sh — remove the WiFi captive portal and restore the system.
#
# Reverses setup.sh: stops services, removes config/data, restores originals.
# System packages (hostapd, dnsmasq, iptables) are NOT removed — they may be
# in use by other things. Uninstall them manually if you want them gone.
#
# Run as root:  sudo bash teardown.sh

set -euo pipefail

APP_DEST="/opt/wifi-portal"
SETTINGS_DIR="/etc/wifi-portal"
DATA_DIR="/var/lib/wifi-portal"

info()  { echo -e "\n\033[1;34m[INFO]\033[0m  $*"; }
ok()    { echo -e "\033[1;32m[OK]\033[0m    $*"; }
warn()  { echo -e "\033[1;33m[WARN]\033[0m  $*"; }

[[ $EUID -eq 0 ]] || { echo "Run as root: sudo bash teardown.sh" >&2; exit 1; }

echo ""
echo "This will remove the WiFi captive portal and all associated configuration."
echo "  Removes: /opt/wifi-portal, /etc/wifi-portal, /var/lib/wifi-portal"
echo "  Removes: systemd services, hostapd config, dnsmasq config"
echo "  Resets:  iptables to ACCEPT, NetworkManager/dhcpcd wlan0 management"
echo ""
read -rp "Continue? [y/N]: " confirm
[[ "${confirm,,}" == "y" ]] || { echo "Aborted."; exit 0; }

# Read network config before we delete it (used below for interface names)
WLAN_IF="wlan0"
ETH_IF="eth0"
if [[ -f "$SETTINGS_DIR/iptables.env" ]]; then
    # shellcheck disable=SC1090
    source "$SETTINGS_DIR/iptables.env"
fi

# ---------------------------------------------------------------------------
# 1. Stop and disable services
# ---------------------------------------------------------------------------
info "Stopping services..."
for unit in rotate-password.timer wifi-portal.service hostapd dnsmasq; do
    if systemctl is-active --quiet "$unit" 2>/dev/null; then
        systemctl stop "$unit" && echo "  Stopped $unit"
    fi
done
for unit in wifi-portal.service rotate-password.timer; do
    if systemctl is-enabled --quiet "$unit" 2>/dev/null; then
        systemctl disable "$unit" && echo "  Disabled $unit"
    fi
done
ok "Services stopped."

# ---------------------------------------------------------------------------
# 2. Flush iptables and reset default policies
# ---------------------------------------------------------------------------
info "Resetting iptables..."
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
iptables -P INPUT   ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT  ACCEPT
ok "iptables cleared and policies reset to ACCEPT."

# ---------------------------------------------------------------------------
# 3. Remove wlan0 static IP and restore interface management
# ---------------------------------------------------------------------------
info "Restoring $WLAN_IF management..."

# Remove the static IP the portal assigned
ip addr flush dev "$WLAN_IF" 2>/dev/null || true

# NetworkManager: remove unmanaged-devices override and let NM reclaim wlan0
if [[ -f /etc/NetworkManager/conf.d/wifi-portal.conf ]]; then
    rm /etc/NetworkManager/conf.d/wifi-portal.conf
    systemctl reload NetworkManager 2>/dev/null || true
    # Explicitly re-enable management so the change takes effect immediately
    nmcli device set "$WLAN_IF" managed yes 2>/dev/null || true
    ok "NetworkManager restored to manage $WLAN_IF."

# dhcpcd: remove the wifi-portal stanza
elif [[ -f /etc/dhcpcd.conf ]] && grep -q "# wifi-portal: begin" /etc/dhcpcd.conf 2>/dev/null; then
    sed -i '/# wifi-portal: begin/,/# wifi-portal: end/d' /etc/dhcpcd.conf
    ok "Removed wifi-portal stanza from /etc/dhcpcd.conf."
fi

# Re-enable wpa_supplicant if it exists (setup.sh stopped it)
if systemctl list-unit-files wpa_supplicant.service &>/dev/null; then
    systemctl start wpa_supplicant 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# 4. Remove hostapd config and drop-in
# ---------------------------------------------------------------------------
info "Removing hostapd configuration..."
rm -f /etc/hostapd/hostapd.conf
rm -f /etc/systemd/system/hostapd.service.d/wifi-portal.conf
if [[ -d /etc/systemd/system/hostapd.service.d ]]; then
    rmdir --ignore-fail-on-non-empty /etc/systemd/system/hostapd.service.d
fi
ok "hostapd config removed."

# ---------------------------------------------------------------------------
# 5. Restore dnsmasq config
# ---------------------------------------------------------------------------
info "Restoring dnsmasq configuration..."
if [[ -f /etc/dnsmasq.conf.backup ]]; then
    mv /etc/dnsmasq.conf.backup /etc/dnsmasq.conf
    ok "Restored /etc/dnsmasq.conf from backup."
else
    rm -f /etc/dnsmasq.conf
    warn "No dnsmasq backup found — /etc/dnsmasq.conf removed."
fi

# ---------------------------------------------------------------------------
# 6. Remove systemd service and timer unit files
# ---------------------------------------------------------------------------
info "Removing systemd unit files..."
rm -f /etc/systemd/system/wifi-portal.service
rm -f /etc/systemd/system/rotate-password.service
rm -f /etc/systemd/system/rotate-password.timer
systemctl daemon-reload
ok "Systemd units removed and daemon reloaded."

# ---------------------------------------------------------------------------
# 7. Remove app, settings, and data
# ---------------------------------------------------------------------------
info "Removing app files..."
rm -rf "$APP_DEST"
ok "Removed $APP_DEST"

info "Removing settings..."
rm -rf "$SETTINGS_DIR"
ok "Removed $SETTINGS_DIR"

info "Removing data..."
rm -rf "$DATA_DIR"
ok "Removed $DATA_DIR"

# ---------------------------------------------------------------------------
# 8. Undo IP forwarding
# ---------------------------------------------------------------------------
info "Disabling IP forwarding..."
sed -i '/^net\.ipv4\.ip_forward=1/d' /etc/sysctl.conf
sysctl -w net.ipv4.ip_forward=0
ok "IP forwarding disabled."

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo "============================================================"
echo " Teardown complete."
echo "============================================================"
echo ""
echo "  Packages hostapd, dnsmasq, iptables are still installed."
echo "  Run 'sudo apt-get remove hostapd dnsmasq' to remove them."
echo ""
echo "  You can now run setup.sh again for a fresh install."
echo "============================================================"
