#!/usr/bin/env bash
# iptables.sh — initialise firewall rules for the captive portal.
#
# Called by wifi-portal.service before the Flask app starts.
# Safe to run multiple times (flushes and rebuilds from scratch).
#
# Environment variables (set in wifi-portal.service):
#   WLAN_IF       — guest WiFi interface (default: wlan0)
#   ETH_IF        — internet-facing interface (default: eth0)
#   GUEST_SUBNET  — guest network CIDR (default: 192.168.100.0/24)
#   GUEST_GW      — Pi's IP on the guest network (default: 192.168.100.1)
#   HOME_SUBNET   — your home LAN CIDR to block guests from (default: 192.168.1.0/24)
#   PORTAL_PORT   — port the Flask app listens on (default: 80)
#   PINHOLE_HOST  — IP of a home LAN service guests may reach (e.g. Jellyfin); unset = disabled
#   PINHOLE_PORT  — TCP port for that service (default: 8096)

set -euo pipefail

WLAN_IF="${WLAN_IF:-wlan0}"
ETH_IF="${ETH_IF:-eth0}"
GUEST_SUBNET="${GUEST_SUBNET:-192.168.100.0/24}"
GUEST_GW="${GUEST_GW:-192.168.100.1}"
HOME_SUBNET="${HOME_SUBNET:-192.168.1.0/24}"
PORTAL_PORT="${PORTAL_PORT:-80}"
PINHOLE_HOST="${PINHOLE_HOST:-}"
PINHOLE_PORT="${PINHOLE_PORT:-8096}"

echo "[iptables] Setting up captive portal firewall rules..."
echo "  Guest IF:    $WLAN_IF"
echo "  Internet IF: $ETH_IF"
echo "  Guest net:   $GUEST_SUBNET (gateway: $GUEST_GW)"
echo "  Home net:    $HOME_SUBNET (blocked from guests)"
echo "  Portal port: $PORTAL_PORT"
if [[ -n "$PINHOLE_HOST" ]]; then
  echo "  Pinhole:     $PINHOLE_HOST:$PINHOLE_PORT (accessible from guest network)"
fi

# ---------------------------------------------------------------------------
# Ensure the guest interface has its static IP.
# This is the authoritative assignment — works whether the system uses
# NetworkManager, dhcpcd, or neither, because we set it directly.
# ---------------------------------------------------------------------------
ip addr flush dev "$WLAN_IF" 2>/dev/null || true
ip addr add "${GUEST_GW}/24" dev "$WLAN_IF" 2>/dev/null || true
ip link set "$WLAN_IF" up

# ---------------------------------------------------------------------------
# Flush everything cleanly
# ---------------------------------------------------------------------------
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# ---------------------------------------------------------------------------
# Default policies
# ---------------------------------------------------------------------------
iptables -P INPUT   DROP
iptables -P FORWARD DROP
iptables -P OUTPUT  ACCEPT

# ---------------------------------------------------------------------------
# INPUT — what the Pi itself accepts
# ---------------------------------------------------------------------------

# Always allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow established/related replies
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# SSH — from any interface so you can recover if something goes wrong
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# DHCP requests from guest network (UDP broadcast, no src IP yet)
iptables -A INPUT -i "$WLAN_IF" -p udp --dport 67 -j ACCEPT

# DNS queries from guest network
iptables -A INPUT -i "$WLAN_IF" -p udp --dport 53 -j ACCEPT
iptables -A INPUT -i "$WLAN_IF" -p tcp --dport 53 -j ACCEPT

# Captive portal web server
iptables -A INPUT -i "$WLAN_IF" -p tcp --dport "$PORTAL_PORT" -j ACCEPT

# Full access from home LAN (management / admin dashboard)
iptables -A INPUT -i "$ETH_IF" -j ACCEPT

# ---------------------------------------------------------------------------
# FORWARD — guest clients routing to the internet
#
# Custom chain GUEST_FORWARD keeps per-MAC rules tidy.
#   Rule 0:    ACCEPT dst=PINHOLE_HOST:PINHOLE_PORT  (optional, set via env)
#   Rule 1:    DROP   dst=HOME_SUBNET  (always — even authenticated clients)
#   Rules 2-N: ACCEPT mac=<auth'd>    (injected by app.py via firewall.py)
#   Last:      DROP                   (unauthenticated catch-all)
# ---------------------------------------------------------------------------
iptables -N GUEST_FORWARD

# Pinhole: allow guest access to a single home LAN host:port (e.g. Jellyfin) before the
# blanket HOME_SUBNET drop. Any guest device can reach it without portal authentication,
# which is intentional for IoT devices that won't go through the captive portal flow.
if [[ -n "$PINHOLE_HOST" ]]; then
  iptables -A GUEST_FORWARD -d "$PINHOLE_HOST" -p tcp --dport "$PINHOLE_PORT" -j ACCEPT
fi

# Never let any guest reach the rest of the home LAN
iptables -A GUEST_FORWARD -d "$HOME_SUBNET" -j DROP

# Last rule: drop everyone not explicitly allowed above
iptables -A GUEST_FORWARD -j DROP

# Plug GUEST_FORWARD into the FORWARD chain
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -i "$WLAN_IF" -o "$ETH_IF" -j GUEST_FORWARD

# ---------------------------------------------------------------------------
# NAT — masquerade guest traffic and redirect unauthenticated HTTP
#
# Custom chain GUEST_PORTAL in nat PREROUTING:
#   Rules 1-N: RETURN mac=<auth'd>   (injected by app.py — skips redirect)
#   Last:      REDIRECT port 80 → PORTAL_PORT
# ---------------------------------------------------------------------------

# Masquerade all guest traffic leaving via eth0
iptables -t nat -A POSTROUTING -o "$ETH_IF" -s "$GUEST_SUBNET" -j MASQUERADE

iptables -t nat -N GUEST_PORTAL

# Allow DNS through without redirect (clients need DNS to resolve anything)
iptables -t nat -A PREROUTING -i "$WLAN_IF" -p udp --dport 53 -j ACCEPT
iptables -t nat -A PREROUTING -i "$WLAN_IF" -p tcp --dport 53 -j ACCEPT

# Allow DHCP through
iptables -t nat -A PREROUTING -i "$WLAN_IF" -p udp --dport 67 -j ACCEPT

# Traffic addressed directly to the portal server itself — no redirect needed
iptables -t nat -A PREROUTING -i "$WLAN_IF" -d "$GUEST_GW" -j ACCEPT

# Send all other traffic through the portal chain
iptables -t nat -A PREROUTING -i "$WLAN_IF" -j GUEST_PORTAL

# Last rule of GUEST_PORTAL: redirect HTTP to the captive portal
iptables -t nat -A GUEST_PORTAL -p tcp --dport 80 -j REDIRECT --to-port "$PORTAL_PORT"

# ---------------------------------------------------------------------------
# Enable IP forwarding
# ---------------------------------------------------------------------------
sysctl -w net.ipv4.ip_forward=1

echo "[iptables] Rules installed successfully."
