# WiFi Captive Portal

A captive portal for a Raspberry Pi 3 that gives guests and smart devices
internet access while keeping them completely separate from your home LAN.

---

## How it works

```
         Home router ─── Ethernet ─── Raspberry Pi ─── WiFi AP "HomeGuest"
         192.168.1.0/24              192.168.100.1      192.168.100.0/24
                                                         │
                                                    ┌────┴────┐
                                                    │  Guests  │  Captive portal login
                                                    │IoT devs  │  (registered by MAC — no portal)
                                                    └─────────┘
```

**Guests** connect to the open `HomeGuest` SSID. Their browser is intercepted
and they are shown a portal page where they enter a password. The password is
human-friendly (e.g. `OCEAN-TIGER-42`) and rotates automatically on the 1st of
every month. You see the current password and a QR code of it in the admin
dashboard.

**Smart/IoT devices** (TV, smart plugs, etc.) are registered once by MAC address
in the admin dashboard. They connect to the same SSID and get internet access
immediately — no captive portal.

**Neither guests nor IoT devices can reach your home LAN** (192.168.1.0/24).
iptables blocks that traffic unconditionally.

---

## Hardware requirements

- Raspberry Pi 3 (built-in WiFi used as the access point)
- Ethernet cable connecting the Pi to your home router
- A micro-SD card with Raspberry Pi OS Lite (64-bit recommended)

The Pi **must** be connected via Ethernet. Its built-in WiFi is used
exclusively for the guest/IoT access point.

---

## Installation

### 1. Prepare the Pi

Flash Raspberry Pi OS Lite onto the SD card, enable SSH, and boot the Pi.
Connect it to your router via Ethernet and SSH in.

### 2. Clone this repository

```bash
git clone <this-repo> wifi-portal
cd wifi-portal
```

### 3. Run setup

```bash
sudo bash scripts/setup.sh
```

The script will ask you for:

| Prompt | Example | Notes |
|--------|---------|-------|
| Guest SSID | `HomeGuest` | What guests see in their WiFi list |
| Country code | `GB` | Your [ISO 3166-1 alpha-2](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2) country code |
| WiFi channel | `6` | Use 1, 6, or 11 to avoid overlap |
| Guest subnet | `192.168.100.0/24` | The new isolated network |
| Gateway IP | `192.168.100.1` | Pi's IP on the guest network |
| DHCP pool | `192.168.100.100` → `192.168.100.200` | |
| Home LAN subnet | `192.168.1.0/24` | Blocked from guests |
| Admin password | *(your choice)* | For the management dashboard |

The script handles both **Raspberry Pi OS Bookworm** (NetworkManager) and
**Bullseye and earlier** (dhcpcd) automatically when configuring the static IP
for `wlan0`.

Setup installs the app to `/opt/wifi-portal`, writes config to
`/etc/wifi-portal/settings.ini`, and starts three systemd units:

| Unit | Purpose |
|------|---------|
| `wifi-portal.service` | Flask portal app (sets up iptables on start) |
| `rotate-password.timer` | Fires on the 1st of each month |
| `rotate-password.service` | Generates new password, expires guest sessions |

---

## Starting fresh / uninstalling

```bash
sudo bash scripts/teardown.sh
```

Reverses `setup.sh` completely: stops and disables all services, flushes
iptables and resets policies to ACCEPT, removes the app and all config/data,
restores NetworkManager or dhcpcd management of `wlan0`, and re-enables
`wpa_supplicant`. System packages (`hostapd`, `dnsmasq`, `iptables`) are left
installed — remove them manually if wanted.

After teardown you can re-run `setup.sh` for a clean install.

---

## Admin dashboard

Visit **`http://192.168.100.1/admin`** from any device on the guest network,
or from your home LAN if you know the Pi's Ethernet IP.

Sign in with the admin password you set during setup. The dashboard shows:

- **Current guest password** — large, readable, with a QR code
- **Rotate now** button — generates a new password immediately (use if a password
  is compromised; disconnects all current guests)
- **Smart devices** — register an IoT device's MAC address here; it will bypass
  the portal permanently
- **Active guest sessions** — see who is connected; revoke individual sessions

### Finding a device's MAC address

- **Smart TV / streaming stick**: Settings → Network → About / Status
- **Your router's DHCP table**: Usually at 192.168.1.1 in your browser
- **The Pi's ARP table**: `arp -n` over SSH after the device connects

---

## Guest experience

1. Guest sees `HomeGuest` in their WiFi list and connects (no WiFi password)
2. Their phone/laptop opens a mini-browser automatically (iOS WebSheet / Android captive portal check)
3. They see: *"Enter the guest password to access the internet"*
4. They type the password you share with them (e.g. from the admin QR code)
5. They see a ✓ "You're connected" page and can browse normally
6. Their session lasts 24 hours; after that they need to re-enter the password

---

## Monthly password rotation

The `rotate-password.timer` fires at 03:00 on the 1st of each month.
It generates a new password, writes it to `settings.ini`, and expires all
active guest sessions. IoT devices are unaffected.

To see the new password: visit `/admin`, or read it directly:

```bash
grep guest_password /etc/wifi-portal/settings.ini
```

To rotate manually (e.g. after a security concern):

```bash
sudo systemctl start rotate-password.service
# or via the admin dashboard "Rotate now" button
```

### Custom word list

Passwords are drawn from a built-in word list by default. To use your own
words, create `/opt/wifi-portal/words.csv` with one word per line:

```
CASTLE
RIVER
FALCON
...
```

The file is read at rotation time. If it is absent or empty the built-in list
is used as a fallback.

---

## Troubleshooting

### Pi's WiFi isn't broadcasting

```bash
sudo systemctl status hostapd
sudo journalctl -u hostapd -n 40
```

Common cause: another process (e.g. `wpa_supplicant`) is holding `wlan0`.
The setup script disables `wpa_supplicant` on `wlan0`, but a reboot may be needed.

### Devices connect but can't reach the portal

```bash
sudo systemctl status wifi-portal
sudo journalctl -u wifi-portal -n 40
sudo iptables -t nat -L -v          # check GUEST_PORTAL chain
sudo iptables -L -v                 # check GUEST_FORWARD chain
```

### Guests can reach the portal but not the internet after login

```bash
sudo iptables -L GUEST_FORWARD -v   # should show ACCEPT rules for active MACs
arp -n                              # check the Pi can see the client's MAC
```

If the Pi can't resolve the MAC via ARP (unusual), the client won't be added
to the allowlist. Try disconnecting and reconnecting to the SSID.

### iptables rules are lost after reboot

They are re-applied by `wifi-portal.service` (`ExecStartPre=iptables.sh`) on
every start. Active sessions are restored from the SQLite database.

### Changing the admin password

```bash
python3 -c "
from werkzeug.security import generate_password_hash
print(generate_password_hash(input('New password: ')))
"
```

Then paste the output into `/etc/wifi-portal/settings.ini` under
`admin_password_hash =` and restart the service:

```bash
sudo systemctl restart wifi-portal
```

---

## File layout

```
/opt/wifi-portal/           Application
  app.py                    Flask routes, session/auth logic
  firewall.py               iptables helpers
  templates/                Jinja2 HTML templates
  scripts/
    iptables.sh             Firewall initialisation (run at service start)
    rotate-password.sh      Monthly password rotation
    setup.sh                First-time installer
    teardown.sh             Removes the portal and restores the system
  words.csv                 (optional) Custom word list for password generation

/etc/wifi-portal/
  settings.ini              Admin password hash, guest password, network config
  iptables.env              Interface/subnet variables read by systemd

/var/lib/wifi-portal/
  portal.db                 SQLite database (sessions, failed login tracking)

/etc/hostapd/hostapd.conf   Access point config
/etc/systemd/system/
  hostapd.service.d/
    wifi-portal.conf        Drop-in that pins hostapd to the correct config path
  wifi-portal.service
  rotate-password.service
  rotate-password.timer

/etc/dnsmasq.conf           DHCP/DNS config
/etc/NetworkManager/conf.d/
  wifi-portal.conf          (Bookworm only) Marks wlan0 as unmanaged by NM
```

---

## Security notes

- **Network isolation**: iptables blocks all traffic from the guest subnet to
  your home LAN subnet (`HOME_SUBNET` in settings). This is enforced before any
  per-MAC ACCEPT rules, so even authenticated clients cannot reach your home devices.
- **Brute force protection**: The portal locks an IP out for 15 minutes after
  5 incorrect password attempts.
- **Admin password**: Stored as a Werkzeug PBKDF2 hash in `settings.ini`.
  The file is readable only by root (mode 640).
- **Guest sessions**: Expire after 24 hours. Rotation or manual revocation
  removes the iptables ACCEPT rule for that MAC immediately.
- **IoT isolation**: IoT devices get internet access but are still blocked from
  your home LAN — the home-subnet DROP rule is unconditional.
- **The app runs as root** (required for iptables management). The Flask
  development server is used and should not be exposed to the internet —
  only to your internal guest and home networks.
