"""
iptables management for the captive portal.

Two custom chains keep the dynamic per-MAC rules tidy:

  GUEST_FORWARD (in the FORWARD chain):
    Rule 1:    DROP  dst=home_subnet   — always blocks access to home LAN
    Rules 2-N: ACCEPT mac=<auth'd>    — injected/removed dynamically
    Last:      DROP                   — unauthenticated clients go no further

  GUEST_PORTAL (in nat PREROUTING):
    Rules 1-N: RETURN mac=<auth'd>    — skip redirect for auth'd clients
    Last:      REDIRECT port 80 → portal_port

This module is imported by app.py and also used directly by the
rotate-password.sh script (via python3 -c "from firewall import remove_mac; ...").
"""

import os
import re
import subprocess
import logging

log = logging.getLogger(__name__)

WLAN_IF = os.environ.get("WLAN_IF", "wlan0")
PORTAL_PORT = int(os.environ.get("PORTAL_PORT", "80"))

_FWD_CHAIN = "GUEST_FORWARD"
_NAT_CHAIN = "GUEST_PORTAL"

_MAC_RE = re.compile(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")


def _run(*args, check: bool = True) -> bool:
    """Run an iptables command. Returns True on success, False on failure."""
    try:
        subprocess.run(list(args), check=check, capture_output=True)
        return True
    except subprocess.CalledProcessError as exc:
        log.warning("iptables command failed: %s\n%s", " ".join(args), exc.stderr.decode())
        return False
    except FileNotFoundError:
        log.warning("iptables not found — running without firewall enforcement (dev mode).")
        return False


def get_client_mac(ip: str):
    """Look up a client's MAC address from the kernel ARP table.

    Tries three sources in order so we don't depend on net-tools (arp) being
    installed — iproute2 and /proc/net/arp are present on every Pi OS image.
    """
    # 1. /proc/net/arp — direct kernel table read, no subprocess needed.
    try:
        with open("/proc/net/arp") as f:
            for line in f:
                parts = line.split()
                # Columns: IP HWtype Flags HWaddr Mask Device
                if len(parts) >= 4 and parts[0] == ip:
                    mac = parts[3]
                    if _MAC_RE.match(mac) and mac != "00:00:00:00:00:00":
                        return mac.upper()
    except Exception:
        pass

    # 2. ip neigh show — iproute2, installed by default on all Raspberry Pi OS images.
    try:
        result = subprocess.run(
            ["ip", "neigh", "show", ip], capture_output=True, text=True, timeout=2
        )
        m = _MAC_RE.search(result.stdout)
        if m:
            return m.group(0).upper()
    except Exception:
        pass

    # 3. arp -n — net-tools fallback; may not be installed on Bookworm.
    try:
        result = subprocess.run(
            ["arp", "-n", ip], capture_output=True, text=True, timeout=2
        )
        m = _MAC_RE.search(result.stdout)
        if m:
            return m.group(0).upper()
    except Exception:
        pass

    return None


def allow_mac(mac: str) -> None:
    """Grant a client full internet access (bypasses captive portal redirect)."""
    mac = mac.upper()
    # Position 2 places this AFTER the home-subnet DROP rule (rule 1) but before the catch-all DROP.
    _run("iptables", "-I", _FWD_CHAIN, "2", "-m", "mac", "--mac-source", mac, "-j", "ACCEPT")
    _run("iptables", "-t", "nat", "-I", _NAT_CHAIN, "1", "-m", "mac", "--mac-source", mac, "-j", "RETURN")


def remove_mac(mac: str) -> None:
    """Revoke a client's internet access."""
    mac = mac.upper()
    _run("iptables", "-D", _FWD_CHAIN, "-m", "mac", "--mac-source", mac, "-j", "ACCEPT", check=False)
    _run("iptables", "-t", "nat", "-D", _NAT_CHAIN, "-m", "mac", "--mac-source", mac, "-j", "RETURN", check=False)
