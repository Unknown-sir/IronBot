# Iron Bot

## v19.0.14 — On-demand panel authentication

- IronPanel checks use API Token sessions and do not call `/login` every minute.
- x-ui/3x-ui login happens only when an operation needs it; empty credentials never generate a request.
- Remote cookies are reused for 15 minutes by default to reduce repeated authentication.

Current release: **v19.0.0**

**Iron Bot** is a Telegram sales and management bot for VPN panels. This release keeps existing **x-ui / 3x-ui** delivery support and adds first-class **IronPanel API** delivery, including multiple IronPanel instances in the same bot.

Repository owner: [Unknown-sir](https://github.com/Unknown-sir)  
Repository name: `IronBot`

> Runtime paths are kept compatible with older watcher2 installations, so existing servers can upgrade without losing data.

---

## Main features

- Telegram customer menu and admin panel
- Multi-admin support
- Approval lock for invoices and wallet charge requests
- Wallet payments and admin wallet adjustment
- Normal and special customer groups
- Agency/special-customer request workflow
- Plan groups, per-plan price, per-plan duration, per-plan panel selection, and per-plan IP limit
- `0` duration means unlimited time; `0` IP limit means unlimited IPs
- Temporary suspension when a config exceeds its allowed IP count, with automatic resume after the admin-defined period
- Multi-panel delivery for **IronPanel**, **x-ui**, and **3x-ui**
- Multiple IronPanel API targets can be added from the same panel management section
- Per-plan IronPanel protocol selection, for example `xray`, `openvpn`, `wireguard`, `hysteria2`, `ocserv`, `l2tp`, `pptp`, and `telegram_proxy`
- Per-panel QR-code delivery toggle
- Trial configuration system
- Admin bulk free config creation
- Config name rules and duplicate-safe naming
- Subscription link delivery when the target panel returns or provides a subscription URL
- Fast delivery retry interval set to 1 second
- Default texts for welcome, rules, connection guide, and support
- License verification compatible with the existing LicensePanel Pro license flow

---

## Requirements

- Linux server with systemd
- Python 3
- `curl`, `sqlite3`, `qrencode`, `openssl`
- At least one target panel: IronPanel API, x-ui, or 3x-ui
- Telegram bot token from BotFather
- Admin Telegram Chat ID

The installer installs required packages on Debian/Ubuntu, CentOS, Fedora, AlmaLinux, and Rocky Linux when possible.

---

## Quick install

```bash
sudo apt update
sudo apt install -y git

git clone https://github.com/Unknown-sir/IronBot.git
cd IronBot
sudo bash install.sh
```

Then open the bot in Telegram and send:

```text
/admin
```

---

## Upgrade from a zip release

```bash
cd /tmp
unzip IronBot.zip
cd IronBot
sudo cp watcher2_core.py /opt/watcher2/watcher2_core.py
sudo cp install.sh /opt/watcher2/install.sh
sudo chmod +x /opt/watcher2/watcher2_core.py /opt/watcher2/install.sh
sudo python3 -m py_compile /opt/watcher2/watcher2_core.py
sudo systemctl restart xui-watcher2
sudo journalctl -u xui-watcher2 -n 120 --no-pager
```

---

## Important runtime paths

```text
/opt/watcher2/watcher2_core.py
/etc/watcher2/config.env
/var/lib/watcher2/watcher2.sqlite
/var/lib/watcher2/qrcodes
/var/log/watcher2
```

Systemd service:

```text
xui-watcher2
```

These paths are intentionally preserved for compatibility with previous deployments.

---

## Configuration

The main configuration file is:

```bash
/etc/watcher2/config.env
```

Most settings can be changed from the Telegram admin panel. Sensitive values such as the Telegram bot token can also be edited from the installer menu or directly in `config.env`.

New v19.0.0 keys:

```text
LICENSE_PANEL_HOST=''
LICENSE_ACCEPT_LICENSE_TYPES='pro,admin,trial'
LICENSE_REQUIRE_FEATURE='sales_bot'
IRONPANEL_DEFAULT_PROTOCOLS='xray,openvpn,wireguard,hysteria2,ocserv,l2tp,pptp,telegram_proxy'
```

---

## Multi-panel setup

From the Telegram admin panel:

```text
/admin → Panel management
```

When adding a panel, choose one of these panel types:

1. **IronPanel API**
2. **x-ui / 3x-ui**

### IronPanel API panel

For each IronPanel, enter:

- Panel name
- IronPanel base URL, for example `https://panel.example.com`
- IronPanel API token for `/api/v2`
- Public host used for display and license compatibility

You can add multiple IronPanel servers. When creating a sales plan, select the IronPanel that should deliver that plan and choose the protocols for that plan. The bot creates the user through IronPanel API v2 and stores the returned subscription link.

### x-ui / 3x-ui panel

For each x-ui or 3x-ui panel, enter:

- Panel name
- Panel URL with port, for example `http://1.2.3.4:2053`
- Web base path if the panel uses a hidden path, for example `/secret`
- Username
- Password
- Public host used for config links
- Optional subscription base URL
- QR delivery status for that panel

---

## LicensePanel Pro compatibility

This release changes only the bot-side license client. The LicensePanel server does not need to be changed.

IronBot now checks licenses only from the fixed SkyShield LicensePanel endpoint:

```text
http://license.skyshield.space:8002/api/check
```

The license server address is not requested from the admin and cannot be changed with `/setlicenseserver`. Pro licenses are accepted when the LicensePanel response is valid and either:

- the license type is allowed, for example `pro`, `admin`, or `trial`; or
- the license features include the required feature, by default `sales_bot`.

To make one Pro license work for both one IronPanel and one Iron Bot installation, set the bot license host to the same public host that IronPanel uses:

```text
/setlicensehost panel.example.com
/setlicense YOUR_LICENSE_KEY
```

You can also set it directly in `/etc/watcher2/config.env`:

```text
LICENSE_PANEL_HOST='panel.example.com'
```

---

## Plan IP limits

When creating a sales plan, Iron Bot asks for the maximum allowed IP count.

- `0` means unlimited IPs.
- Any number greater than `0` enables IP monitoring for configs created from that plan.
- If a config is seen from more IPs than allowed, it is temporarily disabled.
- The suspension duration is set by the admin from the IP limit section.

After the suspension period ends, the config is automatically re-enabled unless it was already disabled for another reason such as volume expiration.

---

## Trial configs

From the admin panel, open the trial configuration section. You can configure:

- How many trial configs each user can receive
- Reset trial usage for everyone
- Reset trial usage for one Chat ID
- Trial delivery panel
- Trial inbound for x-ui / 3x-ui panels
- Trial volume
- Trial duration; `0` means unlimited

---

## Security notes

- Do not commit real `config.env`, `.env`, database files, private keys, or license keys.
- Keep Telegram bot tokens, API tokens, passwords, and LicensePanel keys private.
- If Telegram media delivery is slow through a proxy, disable QR delivery for that panel from the admin panel.


### IronPanel/API-only installation note

IronBot can run on a server that does not have x-ui installed. In this mode the local x-ui database `/etc/x-ui/x-ui.db` is optional, the watcher will not spam admins with `DB not found`, and you can add IronPanel/API panels from the Telegram admin menu.


## v19.0.6 Plan target panel edit

Admins can now change the delivery panel of an existing sales plan from the plan edit menu.


### v19.0.7
Fixes exact VLESS xHTTP REALITY link generation and adds test config domain override.

### v19.0.8

- IronPanel plans now accept Cisco/OpenConnect as `ocserv`, `cisco`, `openconnect`, or `anyconnect`.
- Xray links generated directly by the bot no longer keep an old visible `ironpanel-` prefix in the config remark.



## v19.0.10 - Mandatory Channel Join / ادد اجباری

Admin panel now includes `📢 ادد اجباری`. When enabled, users must be members of the configured Telegram channel before using the bot. The bot checks that it is an administrator in the channel before saving/enabling the channel.


## v19.0.11

When an order or trial config is created through an **IronPanel API** target, IronBot now delivers only the IronPanel subscription link plus a short user guide. It no longer sends a direct config link or a separate QR for IronPanel API deliveries.

## v19.0.12

IronPanel API trial and paid-plan deliveries now include an inline **Open subscription link** URL button. The delivery guide was shortened by removing the two extra IronPanel/Subscription sentences, while keeping subscription-only delivery and a plain-text fallback.



## v19.0.13 — Special customer request auto approval

Administrators can enable delayed automatic approval for **agency / special-customer enrollment requests** and set the waiting time in minutes. Only `agency_requests` rows still in `pending` after the delay are approved. Purchase orders and payment receipts remain subject to their existing approval flow.
