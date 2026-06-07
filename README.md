# Iron Bot

Current release: **v18.12.1**

**Iron Bot** is a Telegram sales and management bot for **x-ui / 3x-ui** panels. It can sell VPN configurations, manage wallets and orders, create trial configs, work with multiple panels, apply per-plan IP limits, and deliver configs to users through Telegram.

Repository owner: [Unknown-sir](https://github.com/Unknown-sir)  
Repository name: `IronBot`

> Internal runtime paths are kept compatible with older watcher2 installations, so existing servers can upgrade without losing data.

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
- Multi x-ui / 3x-ui panel delivery
- Per-panel QR-code delivery toggle
- Trial configuration system
- Admin bulk free config creation
- Config name rules and duplicate-safe naming
- Subscription link delivery only when a subscription URL is configured for the selected panel
- Fast delivery retry interval set to 1 second
- Default texts for welcome, rules, connection guide, and support
- Optional license verification support

---

## Requirements

- Linux server with systemd
- Python 3
- `curl`, `sqlite3`, `qrencode`, `openssl`
- Local or remote x-ui / 3x-ui panel
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

A template is available in this repository:

```text
.env.example
```

Most settings can be changed from the Telegram admin panel. Sensitive values such as the Telegram bot token can also be edited from the installer menu or directly in `config.env`.

---

## Multi-panel setup

From the admin panel:

```text
/admin → 🖥 مدیریت پنل‌ها
```

For each remote panel, enter:

- Panel name
- Panel URL with port, for example `http://1.2.3.4:2053`
- Web base path if the panel uses a hidden path, for example `/secret`
- Username
- Password
- Public host used for config links
- Optional subscription base URL
- QR delivery status for that panel

When creating a sales plan, choose the panel that should deliver configs for that plan.

---

## Plan IP limits

When creating a sales plan, Iron Bot asks for the maximum allowed IP count.

- `0` means unlimited IPs.
- Any number greater than `0` enables IP monitoring for configs created from that plan.
- If a config is seen from more IPs than allowed, it is temporarily disabled.
- The suspension duration is set by the admin from:

```text
/admin → 🛡 محدودیت IP
```

After the suspension period ends, the config is automatically re-enabled unless it was already disabled for another reason such as volume expiration.

---

## Trial configs

From the admin panel:

```text
/admin → 🧪 کانفیگ تست
```

You can configure:

- How many trial configs each user can receive
- Reset trial usage for everyone
- Reset trial usage for one Chat ID
- Trial delivery panel
- Trial inbound
- Trial volume
- Trial duration; `0` means unlimited

Users receive trials from:

```text
🧪 دریافت تست
```

---

## Publishing to GitHub

After extracting this package:

```bash
cd IronBot
git init
git add .
git commit -m "Initial Iron Bot release"
git branch -M main
git remote add origin https://github.com/Unknown-sir/IronBot.git
git push -u origin main
```

Or use the helper script:

```bash
bash scripts/publish_to_github.sh
```

---

## Security notes

- Do not commit real `config.env`, `.env`, database files, private keys, or license keys.
- The repository includes `.gitignore` to keep runtime secrets out of Git.
- If Telegram media delivery is slow through a proxy, disable QR delivery for that panel from the admin panel.
